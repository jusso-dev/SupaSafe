//! WHERE clause analysis.
//!
//! The difference between `DELETE FROM users WHERE id = $1` and
//! `DELETE FROM users WHERE 1=1` is not lexical: both have a WHERE clause and
//! both look equally harmless to a rule that only checks for the keyword. The
//! second one deletes everything.
//!
//! This module walks the predicate expression and answers three questions:
//!
//! 1. Is the predicate a tautology (evaluates to TRUE regardless of the row)?
//! 2. Does it pin the statement to a single row via a key equality?
//! 3. Roughly how much of the table does it let through?

use serde::{Deserialize, Serialize};
use sqlparser::ast::{BinaryOperator, Expr, UnaryOperator, Value};

/// How much of the table a predicate is expected to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Selectivity {
    /// A key equality. At most one row.
    SingleRow,
    /// Bounded by an IN list, a small key set, or an explicit LIMIT.
    Narrow,
    /// Filters something, but could match an arbitrary fraction of the table.
    Broad,
    /// Matches every row: no WHERE clause, or a tautological one.
    Unbounded,
}

impl Selectivity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Selectivity::SingleRow => "single_row",
            Selectivity::Narrow => "narrow",
            Selectivity::Broad => "broad",
            Selectivity::Unbounded => "unbounded",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Selectivity::SingleRow => "targets at most one row via a key equality",
            Selectivity::Narrow => "targets a bounded set of rows",
            Selectivity::Broad => "could match an unbounded fraction of the table",
            Selectivity::Unbounded => "matches every row in the table",
        }
    }
}

/// The result of analysing a statement's row filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateAnalysis {
    /// A WHERE clause was present in the statement.
    pub present: bool,
    /// The predicate is a tautology: it constant-folds to TRUE.
    pub always_true: bool,
    /// The predicate constant-folds to FALSE, so the statement is a no-op.
    pub always_false: bool,
    /// The predicate pins the row set through equality on a likely key column.
    pub key_lookup: bool,
    /// Columns referenced by the predicate.
    pub columns: Vec<String>,
    /// The predicate reaches into a subquery, so its selectivity cannot be
    /// judged from the statement alone.
    pub has_subquery: bool,
    /// Number of bind parameters in the predicate. A parameterised predicate
    /// is not evaluable at analysis time, which is itself worth knowing.
    pub bind_params: usize,
    /// Estimated share of the table the predicate lets through.
    pub selectivity: Selectivity,
}

impl PredicateAnalysis {
    /// No WHERE clause at all.
    pub fn absent() -> Self {
        Self {
            present: false,
            always_true: false,
            always_false: false,
            key_lookup: false,
            columns: Vec::new(),
            has_subquery: false,
            bind_params: 0,
            selectivity: Selectivity::Unbounded,
        }
    }

    /// A statement whose filter cannot be inspected (an unparsed statement).
    /// Assume the worst.
    pub fn unknown() -> Self {
        Self {
            present: false,
            always_true: false,
            always_false: false,
            key_lookup: false,
            columns: Vec::new(),
            has_subquery: false,
            bind_params: 0,
            selectivity: Selectivity::Unbounded,
        }
    }

    /// True when the statement is effectively unfiltered: either there is no
    /// WHERE clause, or the one that exists lets every row through.
    pub fn is_unfiltered(&self) -> bool {
        !self.present || self.always_true
    }

    pub fn analyze(expr: &Expr) -> Self {
        let mut ctx = Walk::default();
        ctx.walk(expr);
        let folded = fold(expr);
        let always_true = folded == Some(true);
        let always_false = folded == Some(false);

        let key_lookup = !always_true && is_key_lookup(expr);
        let selectivity = if always_true {
            Selectivity::Unbounded
        } else if key_lookup {
            Selectivity::SingleRow
        } else if ctx.bounded_set {
            Selectivity::Narrow
        } else {
            Selectivity::Broad
        };

        Self {
            present: true,
            always_true,
            always_false,
            key_lookup,
            columns: ctx.columns,
            has_subquery: ctx.has_subquery,
            bind_params: ctx.bind_params,
            selectivity,
        }
    }

    /// Apply a `LIMIT n` to the selectivity estimate. `DELETE ... LIMIT 1` is
    /// not unbounded even without a WHERE clause.
    pub fn with_limit(mut self, limit: Option<u64>) -> Self {
        if let Some(n) = limit {
            let bound = if n <= 1 {
                Selectivity::SingleRow
            } else {
                Selectivity::Narrow
            };
            if bound < self.selectivity {
                self.selectivity = bound;
            }
        }
        self
    }
}

/// Column names that are treated as key-like when no live catalog is
/// available. When SupaSafe is attached to a database it replaces this
/// heuristic with the real primary key from `pg_index`.
fn looks_like_key_column(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "id"
        || n == "uuid"
        || n == "pk"
        || n == "ctid"
        || n.ends_with("_id")
        || n.ends_with("_uuid")
        || n.ends_with("_key")
}

/// Constant-fold a predicate to a boolean where possible.
///
/// Returns `None` whenever the value depends on row data, a bind parameter, or
/// anything else not knowable at analysis time. Only literal-versus-literal
/// comparisons fold; `id = 1` stays `None` because it depends on the row.
fn fold(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::Nested(inner) => fold(inner),
        Expr::Value(v) => match &v.value {
            Value::Boolean(b) => Some(*b),
            Value::Null => Some(false),
            Value::Number(n, _) => Some(n != "0"),
            _ => None,
        },
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => fold(expr).map(|b| !b),
        Expr::IsTrue(e) => fold(e),
        Expr::IsNotTrue(e) => fold(e).map(|b| !b),
        Expr::IsFalse(e) => fold(e).map(|b| !b),
        Expr::IsNotFalse(e) => fold(e),
        Expr::IsNull(e) => literal(e).map(|_| false),
        Expr::IsNotNull(e) => literal(e).map(|_| true),
        Expr::BinaryOp { left, op, right } => match op {
            BinaryOperator::And => match (fold(left), fold(right)) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            },
            BinaryOperator::Or => match (fold(left), fold(right)) {
                // `... OR TRUE` is the classic model-generated tautology.
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Gt
            | BinaryOperator::Lt
            | BinaryOperator::GtEq
            | BinaryOperator::LtEq => compare(left, op, right),
            _ => None,
        },
        _ => None,
    }
}

/// A literal value reduced to a comparable form.
#[derive(PartialEq, PartialOrd)]
enum Lit {
    Num(f64),
    Str(String),
    Bool(bool),
}

fn literal(expr: &Expr) -> Option<Lit> {
    match expr {
        Expr::Nested(inner) => literal(inner),
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => match literal(expr) {
            Some(Lit::Num(n)) => Some(Lit::Num(-n)),
            _ => None,
        },
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse::<f64>().ok().map(Lit::Num),
            Value::SingleQuotedString(s)
            | Value::EscapedStringLiteral(s)
            | Value::NationalStringLiteral(s)
            | Value::DollarQuotedString(sqlparser::ast::DollarQuotedString { value: s, .. }) => {
                Some(Lit::Str(s.clone()))
            }
            Value::Boolean(b) => Some(Lit::Bool(*b)),
            _ => None,
        },
        // A cast of a literal is still a literal for tautology purposes:
        // `WHERE 1::int = 1` is just as unbounded as `WHERE 1 = 1`.
        Expr::Cast { expr, .. } => literal(expr),
        _ => None,
    }
}

fn compare(left: &Expr, op: &BinaryOperator, right: &Expr) -> Option<bool> {
    let (l, r) = (literal(left)?, literal(right)?);
    // Comparisons across types are left to the database.
    let ord = match (&l, &r) {
        (Lit::Num(_), Lit::Num(_)) | (Lit::Str(_), Lit::Str(_)) | (Lit::Bool(_), Lit::Bool(_)) => {
            l.partial_cmp(&r)?
        }
        _ => return None,
    };
    use std::cmp::Ordering::*;
    Some(match op {
        BinaryOperator::Eq => ord == Equal,
        BinaryOperator::NotEq => ord != Equal,
        BinaryOperator::Gt => ord == Greater,
        BinaryOperator::Lt => ord == Less,
        BinaryOperator::GtEq => ord != Less,
        BinaryOperator::LtEq => ord != Greater,
        _ => return None,
    })
}

/// True when the predicate is a conjunction that includes at least one
/// equality between a key-like column and a constant or bind parameter, and
/// contains no top-level disjunction that could widen it.
fn is_key_lookup(expr: &Expr) -> bool {
    match expr {
        Expr::Nested(inner) => is_key_lookup(inner),
        Expr::BinaryOp { left, op, right } => match op {
            // A disjunction widens the row set; only treat it as a key lookup
            // when both sides independently are.
            BinaryOperator::Or => is_key_lookup(left) && is_key_lookup(right),
            BinaryOperator::And => is_key_lookup(left) || is_key_lookup(right),
            BinaryOperator::Eq => {
                (is_key_column(left) && is_value(right)) || (is_key_column(right) && is_value(left))
            }
            _ => false,
        },
        _ => false,
    }
}

fn is_key_column(expr: &Expr) -> bool {
    match expr {
        Expr::Identifier(ident) => looks_like_key_column(&ident.value),
        Expr::CompoundIdentifier(parts) => parts
            .last()
            .map(|i| looks_like_key_column(&i.value))
            .unwrap_or(false),
        Expr::Nested(inner) => is_key_column(inner),
        _ => false,
    }
}

/// A constant or bind parameter: something that resolves to one value.
fn is_value(expr: &Expr) -> bool {
    match expr {
        Expr::Nested(inner) => is_value(inner),
        Expr::Cast { expr, .. } => is_value(expr),
        Expr::Value(v) => !matches!(v.value, Value::Null),
        Expr::TypedString(_) => true,
        _ => false,
    }
}

#[derive(Default)]
struct Walk {
    columns: Vec<String>,
    has_subquery: bool,
    bind_params: usize,
    bounded_set: bool,
}

impl Walk {
    fn note_column(&mut self, name: &str) {
        if !self.columns.iter().any(|c| c == name) {
            self.columns.push(name.to_string());
        }
    }

    fn walk(&mut self, expr: &Expr) {
        match expr {
            Expr::Identifier(ident) => self.note_column(&ident.value),
            Expr::CompoundIdentifier(parts) => {
                if let Some(last) = parts.last() {
                    self.note_column(&last.value);
                }
            }
            Expr::Value(v) => {
                if matches!(v.value, Value::Placeholder(_)) {
                    self.bind_params += 1;
                }
            }
            Expr::Nested(inner)
            | Expr::Cast { expr: inner, .. }
            | Expr::Collate { expr: inner, .. } => self.walk(inner),
            Expr::UnaryOp { expr, .. } => self.walk(expr),
            Expr::BinaryOp { left, right, .. } => {
                self.walk(left);
                self.walk(right);
            }
            Expr::IsNull(e)
            | Expr::IsNotNull(e)
            | Expr::IsTrue(e)
            | Expr::IsNotTrue(e)
            | Expr::IsFalse(e)
            | Expr::IsNotFalse(e)
            | Expr::IsUnknown(e)
            | Expr::IsNotUnknown(e) => self.walk(e),
            Expr::InList { expr, list, .. } => {
                self.walk(expr);
                for e in list {
                    self.walk(e);
                }
                // An IN list against a key column bounds the row set.
                if is_key_column(expr) {
                    self.bounded_set = true;
                }
            }
            Expr::InSubquery { expr, .. } => {
                self.walk(expr);
                self.has_subquery = true;
            }
            Expr::Subquery(_) | Expr::Exists { .. } => self.has_subquery = true,
            Expr::Between {
                expr, low, high, ..
            } => {
                self.walk(expr);
                self.walk(low);
                self.walk(high);
            }
            Expr::Like { expr, pattern, .. }
            | Expr::ILike { expr, pattern, .. }
            | Expr::SimilarTo { expr, pattern, .. } => {
                self.walk(expr);
                self.walk(pattern);
            }
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                if let Some(op) = operand {
                    self.walk(op);
                }
                for c in conditions {
                    self.walk(&c.condition);
                    self.walk(&c.result);
                }
                if let Some(e) = else_result {
                    self.walk(e);
                }
            }
            Expr::Function(_) => {}
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn where_of(sql: &str) -> PredicateAnalysis {
        let stmts = Parser::parse_sql(&PostgreSqlDialect {}, sql).expect("parses");
        match &stmts[0] {
            sqlparser::ast::Statement::Delete(d) => d
                .selection
                .as_ref()
                .map(PredicateAnalysis::analyze)
                .unwrap_or_else(PredicateAnalysis::absent),
            sqlparser::ast::Statement::Update(u) => u
                .selection
                .as_ref()
                .map(PredicateAnalysis::analyze)
                .unwrap_or_else(PredicateAnalysis::absent),
            other => panic!("unexpected statement {other:?}"),
        }
    }

    #[test]
    fn missing_where_is_unbounded() {
        let p = where_of("DELETE FROM users");
        assert!(!p.present);
        assert!(p.is_unfiltered());
        assert_eq!(p.selectivity, Selectivity::Unbounded);
    }

    #[test]
    fn tautologies_are_detected() {
        for sql in [
            "DELETE FROM users WHERE 1=1",
            "DELETE FROM users WHERE true",
            "DELETE FROM users WHERE TRUE AND 1 = 1",
            "DELETE FROM users WHERE email = 'x' OR 1=1",
            "DELETE FROM users WHERE NOT false",
            "DELETE FROM users WHERE 2 > 1",
            "DELETE FROM users WHERE (1=1)",
            "DELETE FROM users WHERE 'a' = 'a'",
        ] {
            let p = where_of(sql);
            assert!(p.always_true, "expected tautology for: {sql}");
            assert!(p.is_unfiltered(), "expected unfiltered for: {sql}");
            assert_eq!(p.selectivity, Selectivity::Unbounded);
        }
    }

    #[test]
    fn real_predicates_are_not_tautologies() {
        for sql in [
            "DELETE FROM users WHERE id = 1",
            "DELETE FROM users WHERE created_at < now()",
            "DELETE FROM users WHERE email = $1",
            "DELETE FROM users WHERE 1 = 2",
        ] {
            let p = where_of(sql);
            assert!(!p.always_true, "false tautology for: {sql}");
        }
    }

    #[test]
    fn contradictions_are_flagged_not_treated_as_open() {
        let p = where_of("DELETE FROM users WHERE 1 = 2");
        assert!(p.always_false);
        assert!(!p.is_unfiltered());
    }

    #[test]
    fn key_lookups_are_single_row() {
        for sql in [
            "DELETE FROM users WHERE id = 1",
            "DELETE FROM users WHERE id = $1",
            "UPDATE users SET name = 'x' WHERE users.id = 42",
            "DELETE FROM orders WHERE user_id = 7 AND status = 'draft'",
        ] {
            let p = where_of(sql);
            assert!(p.key_lookup, "expected key lookup for: {sql}");
            assert_eq!(p.selectivity, Selectivity::SingleRow);
        }
    }

    #[test]
    fn non_key_predicates_are_broad() {
        let p = where_of("DELETE FROM users WHERE status = 'inactive'");
        assert!(!p.key_lookup);
        assert_eq!(p.selectivity, Selectivity::Broad);
        assert_eq!(p.columns, vec!["status".to_string()]);
    }

    #[test]
    fn or_widens_a_key_lookup() {
        let p = where_of("DELETE FROM users WHERE id = 1 OR status = 'inactive'");
        assert!(!p.key_lookup);
    }

    #[test]
    fn in_list_on_key_is_narrow() {
        let p = where_of("DELETE FROM users WHERE id IN (1, 2, 3)");
        assert_eq!(p.selectivity, Selectivity::Narrow);
    }

    #[test]
    fn subqueries_are_noted() {
        let p = where_of("DELETE FROM users WHERE id IN (SELECT user_id FROM banned)");
        assert!(p.has_subquery);
    }

    #[test]
    fn bind_params_are_counted() {
        let p = where_of("DELETE FROM users WHERE email = $1 AND tenant = $2");
        assert_eq!(p.bind_params, 2);
    }

    #[test]
    fn limit_narrows_selectivity() {
        let p = PredicateAnalysis::absent().with_limit(Some(1));
        assert_eq!(p.selectivity, Selectivity::SingleRow);
    }
}
