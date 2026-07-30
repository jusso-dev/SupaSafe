//! Lexical classification for statements the grammar cannot represent.
//!
//! No SQL parser covers every PostgreSQL statement, and the ones it misses are
//! not harmless: `DO $$ ... $$` runs arbitrary PL/pgSQL, `REINDEX` takes heavy
//! locks, `CLUSTER` rewrites a table. Falling back to "allow, we could not
//! parse it" would make the parser itself the bypass.
//!
//! So when the AST parser rejects a statement, SupaSafe classifies it from the
//! token stream instead and marks the result `unparsed`, which the risk engine
//! treats as an aggravating factor rather than an excuse. This is still
//! lexical analysis over a tokeniser that understands quoting and comments,
//! not pattern matching against raw text.

use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

use crate::kind::StatementKind;
use crate::normalize;
use crate::objects::{Access, ObjectKind, ObjectRef};
use crate::predicate::PredicateAnalysis;
use crate::statement::{Flags, StatementAnalysis};

/// A token reduced to what the classifier needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Lex {
    /// An unquoted word. Held twice: upper-cased for keyword comparison, and
    /// lower-cased because that is how PostgreSQL folds unquoted identifiers.
    Word(String, String),
    /// A quoted identifier, case preserved.
    Quoted(String),
    /// The body of a dollar quoted string.
    Body(String),
    /// A literal or operator we only need to know the shape of.
    Other,
    Dot,
    Comma,
    LParen,
    RParen,
}

impl Lex {
    /// The upper-cased form, for comparing against keywords.
    fn word(&self) -> Option<&str> {
        match self {
            Lex::Word(upper, _) => Some(upper),
            _ => None,
        }
    }

    /// The identifier as PostgreSQL would resolve it: unquoted words fold to
    /// lower case, quoted ones keep their case exactly.
    fn ident(&self) -> Option<&str> {
        match self {
            Lex::Word(_, lower) => Some(lower),
            Lex::Quoted(q) => Some(q),
            _ => None,
        }
    }
}

fn lex(sql: &str) -> Vec<Lex> {
    let dialect = PostgreSqlDialect {};
    let tokens = match Tokenizer::new(&dialect, sql).tokenize() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    tokens
        .into_iter()
        .filter_map(|t| match t {
            Token::EOF | Token::Whitespace(Whitespace::Space) => None,
            Token::Whitespace(_) => None,
            Token::Word(w) => Some(match w.quote_style {
                Some(_) => Lex::Quoted(w.value),
                None => Lex::Word(w.value.to_ascii_uppercase(), w.value.to_ascii_lowercase()),
            }),
            Token::DollarQuotedString(d) => Some(Lex::Body(d.value)),
            Token::Period => Some(Lex::Dot),
            Token::Comma => Some(Lex::Comma),
            Token::LParen => Some(Lex::LParen),
            Token::RParen => Some(Lex::RParen),
            _ => Some(Lex::Other),
        })
        .collect()
}

/// Keywords whose presence anywhere in an opaque body means the body can
/// destroy data or schema.
const DESTRUCTIVE: &[&str] = &[
    "DROP", "TRUNCATE", "DELETE", "ALTER", "GRANT", "REVOKE", "UPDATE", "REASSIGN",
];

/// Scan a body of SQL (a DO block, a function body) for destructive keywords.
///
/// Returns the distinct keywords found, in the order listed above, so the
/// message SupaSafe shows a human is deterministic.
pub fn destructive_keywords(body: &str) -> Vec<String> {
    let tokens = lex(body);
    let mut found = Vec::new();
    for keyword in DESTRUCTIVE {
        if tokens.iter().any(|t| t.word() == Some(*keyword))
            && !found.contains(&keyword.to_string())
        {
            found.push(keyword.to_string());
        }
    }
    found
}

/// True when the token stream contains the given keyword sequence anywhere.
fn contains_seq(tokens: &[Lex], seq: &[&str]) -> bool {
    if seq.is_empty() || tokens.len() < seq.len() {
        return false;
    }
    tokens
        .windows(seq.len())
        .any(|w| w.iter().zip(seq.iter()).all(|(t, k)| t.word() == Some(*k)))
}

fn has_word(tokens: &[Lex], word: &str) -> bool {
    tokens.iter().any(|t| t.word() == Some(word))
}

/// Read a possibly qualified object name starting at `i`, e.g. `auth . users`.
/// Returns the reference and the index just past it.
fn read_name(tokens: &[Lex], mut i: usize) -> Option<(Option<String>, String, usize)> {
    // Skip qualifiers that sit between the keyword and the name.
    const SKIP: &[&str] = &[
        "IF",
        "NOT",
        "EXISTS",
        "ONLY",
        "CONCURRENTLY",
        "TABLE",
        "INDEX",
        "UNIQUE",
        "VERBOSE",
    ];
    while i < tokens.len() && tokens[i].word().map(|w| SKIP.contains(&w)).unwrap_or(false) {
        i += 1;
    }
    let first = tokens.get(i)?.ident()?.to_string();
    i += 1;
    if tokens.get(i) == Some(&Lex::Dot) {
        if let Some(second) = tokens.get(i + 1).and_then(|t| t.ident()) {
            return Some((Some(first), second.to_string(), i + 2));
        }
    }
    Some((None, first, i))
}

struct Guess {
    kind: StatementKind,
    objects: Vec<ObjectRef>,
    flags: Flags,
    notes: Vec<String>,
}

impl Guess {
    fn new(kind: StatementKind) -> Self {
        Self {
            kind,
            objects: Vec::new(),
            flags: Flags::default(),
            notes: Vec::new(),
        }
    }

    fn with_name(mut self, tokens: &[Lex], at: usize, kind: ObjectKind, access: Access) -> Self {
        if let Some((schema, name, _)) = read_name(tokens, at) {
            // For a schema-level object the name itself is the schema.
            let obj = if kind == ObjectKind::Schema {
                ObjectRef::new(Some(name.clone()), name, kind, access)
            } else {
                ObjectRef::new(schema, name, kind, access)
            };
            self.objects.push(obj);
        }
        self
    }

    fn note(mut self, s: impl Into<String>) -> Self {
        self.notes.push(s.into());
        self
    }
}

/// Classify a statement that could not be parsed into an AST.
pub fn classify(sql: &str, index: usize, parse_error: Option<String>) -> StatementAnalysis {
    let tokens = lex(sql);
    let mut guess = guess_kind(&tokens);

    guess.flags.unparsed = true;
    guess.flags.cascade |= has_word(&tokens, "CASCADE");
    guess.flags.if_exists |= contains_seq(&tokens, &["IF", "EXISTS"]);
    guess.flags.concurrently |= has_word(&tokens, "CONCURRENTLY");

    // Anything with an opaque body gets its body scanned.
    for token in &tokens {
        if let Lex::Body(body) = token {
            guess.flags.opaque_body = true;
            let found = destructive_keywords(body);
            if !found.is_empty() {
                guess.flags.opaque_body_is_destructive = true;
                guess.notes.push(format!(
                    "the block body contains destructive statements ({})",
                    found.join(", ")
                ));
            }
        }
    }

    if guess.kind == StatementKind::Unknown {
        guess.notes.push(
            "SupaSafe could not determine what this statement does; under an allow-list policy \
             it is denied rather than guessed at"
                .to_string(),
        );
    } else {
        guess.notes.push(format!(
            "classified as {} from the token stream because the grammar could not parse it",
            guess.kind.label()
        ));
    }

    StatementAnalysis {
        index,
        kind: guess.kind,
        sql: sql.to_string(),
        normalized: normalize::normalize(sql),
        objects: guess.objects,
        // An unparsed statement gets no credit for a WHERE clause we cannot
        // verify.
        predicate: PredicateAnalysis::unknown(),
        limit: None,
        flags: guess.flags,
        parsed: false,
        parse_error,
        notes: guess.notes,
    }
}

fn guess_kind(tokens: &[Lex]) -> Guess {
    let w = |i: usize| tokens.get(i).and_then(|t| t.word()).unwrap_or("");

    match w(0) {
        "DO" => Guess::new(StatementKind::DoBlock).note(
            "a DO block executes procedural code that is opaque to static analysis; it can run \
             any statement the current role is allowed to run",
        ),
        "REINDEX" => Guess::new(StatementKind::Reindex)
            .with_name(tokens, 1, ObjectKind::Index, Access::Maintain)
            .note("REINDEX without CONCURRENTLY blocks writes to the table"),
        "CLUSTER" => Guess::new(StatementKind::Cluster)
            .with_name(tokens, 1, ObjectKind::Table, Access::Maintain)
            .note("CLUSTER rewrites the table under an ACCESS EXCLUSIVE lock"),
        "CHECKPOINT" => Guess::new(StatementKind::Checkpoint),
        "VACUUM" => Guess::new(StatementKind::Vacuum),
        "ANALYZE" | "ANALYSE" => Guess::new(StatementKind::Analyze),
        "TRUNCATE" => {
            let at = if w(1) == "TABLE" { 2 } else { 1 };
            Guess::new(StatementKind::Truncate).with_name(
                tokens,
                at,
                ObjectKind::Table,
                Access::Truncate,
            )
        }
        "DELETE" => {
            let at = if w(1) == "FROM" { 2 } else { 1 };
            Guess::new(StatementKind::Delete).with_name(
                tokens,
                at,
                ObjectKind::Table,
                Access::Delete,
            )
        }
        "UPDATE" => Guess::new(StatementKind::Update).with_name(
            tokens,
            1,
            ObjectKind::Table,
            Access::Update,
        ),
        "INSERT" => {
            let at = if w(1) == "INTO" { 2 } else { 1 };
            Guess::new(StatementKind::Insert).with_name(
                tokens,
                at,
                ObjectKind::Table,
                Access::Insert,
            )
        }
        "SELECT" | "WITH" | "TABLE" | "VALUES" => Guess::new(StatementKind::Select),
        "COPY" => {
            let mut g = Guess::new(if has_word(tokens, "TO") {
                StatementKind::CopyTo
            } else {
                StatementKind::CopyFrom
            })
            .with_name(tokens, 1, ObjectKind::Table, Access::Insert);
            if has_word(tokens, "PROGRAM") {
                g.flags.copy_program = true;
                g = g.note("COPY ... PROGRAM executes a shell command on the database host");
            }
            g
        }
        "GRANT" => {
            let mut g = Guess::new(StatementKind::Grant);
            g.flags.grants_all = has_word(tokens, "ALL");
            g.flags.grants_to_public = has_word(tokens, "PUBLIC")
                || has_word(tokens, "ANON")
                || has_word(tokens, "AUTHENTICATED");
            g.flags.grants_elevated_role =
                has_word(tokens, "SUPERUSER") || has_word(tokens, "POSTGRES");
            g
        }
        "REVOKE" => Guess::new(StatementKind::Revoke),
        "REASSIGN" => Guess::new(StatementKind::AlterRole)
            .note("REASSIGN OWNED transfers ownership of every object a role owns"),
        "SECURITY" => Guess::new(StatementKind::Unknown),
        "LOCK" => Guess::new(StatementKind::Lock),
        "BEGIN" | "START" => Guess::new(StatementKind::Begin),
        "COMMIT" | "END" => Guess::new(StatementKind::Commit),
        "ROLLBACK" | "ABORT" => Guess::new(StatementKind::Rollback),
        "SAVEPOINT" => Guess::new(StatementKind::Savepoint),
        "SET" => Guess::new(StatementKind::Set),
        "RESET" => Guess::new(StatementKind::Reset),
        "SHOW" => Guess::new(StatementKind::Show),
        "DISCARD" => Guess::new(StatementKind::Discard),
        "LISTEN" => Guess::new(StatementKind::Listen),
        "NOTIFY" => Guess::new(StatementKind::Notify),
        "UNLISTEN" => Guess::new(StatementKind::Unlisten),
        "EXPLAIN" => Guess::new(StatementKind::Explain),
        "CALL" => Guess::new(StatementKind::Call).with_name(
            tokens,
            1,
            ObjectKind::Procedure,
            Access::Execute,
        ),
        "DROP" => drop_guess(tokens),
        "CREATE" => create_guess(tokens),
        "ALTER" => alter_guess(tokens),
        "COMMENT" => Guess::new(StatementKind::Comment),
        "PREPARE" => Guess::new(StatementKind::Prepare),
        "EXECUTE" => Guess::new(StatementKind::Execute),
        "DEALLOCATE" => Guess::new(StatementKind::Deallocate),
        "DECLARE" => Guess::new(StatementKind::Declare),
        "FETCH" => Guess::new(StatementKind::Fetch),
        "CLOSE" => Guess::new(StatementKind::Close),
        "MERGE" => Guess::new(StatementKind::Merge),
        _ => Guess::new(StatementKind::Unknown),
    }
}

/// Position of the object name after a `CREATE`/`DROP`/`ALTER` keyword,
/// skipping modifiers such as `OR REPLACE`, `MATERIALIZED`, `UNIQUE`.
fn name_start(tokens: &[Lex], from: usize) -> usize {
    const MODIFIERS: &[&str] = &[
        "OR",
        "REPLACE",
        "MATERIALIZED",
        "UNIQUE",
        "TEMP",
        "TEMPORARY",
        "GLOBAL",
        "LOCAL",
        "UNLOGGED",
        "RECURSIVE",
        "FOREIGN",
        "DEFAULT",
    ];
    let mut i = from;
    while i < tokens.len()
        && tokens[i]
            .word()
            .map(|w| MODIFIERS.contains(&w))
            .unwrap_or(false)
    {
        i += 1;
    }
    i
}

fn object_keyword(tokens: &[Lex], from: usize) -> (StatementKind, ObjectKind, usize, &'static str) {
    let i = name_start(tokens, from);
    let word = tokens.get(i).and_then(|t| t.word()).unwrap_or("");
    let verb = tokens.first().and_then(|t| t.word()).unwrap_or("");
    let next = i + 1;
    use StatementKind as K;
    let (kind, obj) = match (verb, word) {
        ("DROP", "TABLE") => (K::DropTable, ObjectKind::Table),
        ("DROP", "SCHEMA") => (K::DropSchema, ObjectKind::Schema),
        ("DROP", "DATABASE") => (K::DropDatabase, ObjectKind::Database),
        ("DROP", "INDEX") => (K::DropIndex, ObjectKind::Index),
        ("DROP", "VIEW") => (K::DropView, ObjectKind::View),
        ("DROP", "SEQUENCE") => (K::DropSequence, ObjectKind::Sequence),
        ("DROP", "FUNCTION") => (K::DropFunction, ObjectKind::Function),
        ("DROP", "PROCEDURE") => (K::DropProcedure, ObjectKind::Procedure),
        ("DROP", "TRIGGER") => (K::DropTrigger, ObjectKind::Trigger),
        ("DROP", "POLICY") => (K::DropPolicy, ObjectKind::Policy),
        ("DROP", "EXTENSION") => (K::DropExtension, ObjectKind::Extension),
        ("DROP", "TYPE") => (K::DropType, ObjectKind::Type),
        ("DROP", "ROLE") | ("DROP", "USER") => (K::DropRole, ObjectKind::Role),
        ("DROP", _) => (K::DropOther, ObjectKind::Unknown),

        ("CREATE", "TABLE") => (K::CreateTable, ObjectKind::Table),
        ("CREATE", "SCHEMA") => (K::CreateSchema, ObjectKind::Schema),
        ("CREATE", "DATABASE") => (K::CreateDatabase, ObjectKind::Database),
        ("CREATE", "INDEX") => (K::CreateIndex, ObjectKind::Index),
        ("CREATE", "VIEW") => (K::CreateView, ObjectKind::View),
        ("CREATE", "SEQUENCE") => (K::CreateSequence, ObjectKind::Sequence),
        ("CREATE", "FUNCTION") => (K::CreateFunction, ObjectKind::Function),
        ("CREATE", "PROCEDURE") => (K::CreateProcedure, ObjectKind::Procedure),
        ("CREATE", "TRIGGER") => (K::CreateTrigger, ObjectKind::Trigger),
        ("CREATE", "POLICY") => (K::CreatePolicy, ObjectKind::Policy),
        ("CREATE", "EXTENSION") => (K::CreateExtension, ObjectKind::Extension),
        ("CREATE", "TYPE") => (K::CreateType, ObjectKind::Type),
        ("CREATE", "ROLE") | ("CREATE", "USER") => (K::CreateRole, ObjectKind::Role),
        ("CREATE", _) => (K::CreateOther, ObjectKind::Unknown),

        ("ALTER", "TABLE") => (K::AlterTable, ObjectKind::Table),
        ("ALTER", "SCHEMA") => (K::AlterSchema, ObjectKind::Schema),
        ("ALTER", "INDEX") => (K::AlterIndex, ObjectKind::Index),
        ("ALTER", "VIEW") => (K::AlterView, ObjectKind::View),
        ("ALTER", "FUNCTION") => (K::AlterFunction, ObjectKind::Function),
        ("ALTER", "TYPE") => (K::AlterType, ObjectKind::Type),
        ("ALTER", "POLICY") => (K::AlterPolicy, ObjectKind::Policy),
        ("ALTER", "ROLE") | ("ALTER", "USER") => (K::AlterRole, ObjectKind::Role),
        ("ALTER", _) => (K::AlterOther, ObjectKind::Unknown),

        _ => (K::Unknown, ObjectKind::Unknown),
    };
    let access = match verb {
        "DROP" => "drop",
        "CREATE" => "create",
        _ => "alter",
    };
    (kind, obj, next, access)
}

fn drop_guess(tokens: &[Lex]) -> Guess {
    let (kind, obj, at, _) = object_keyword(tokens, 1);
    Guess::new(kind).with_name(tokens, at, obj, Access::Drop)
}

fn create_guess(tokens: &[Lex]) -> Guess {
    let (kind, obj, at, _) = object_keyword(tokens, 1);
    let mut g = Guess::new(kind).with_name(tokens, at, obj, Access::Create);
    g.flags.or_replace = contains_seq(tokens, &["OR", "REPLACE"]);
    g.flags.security_definer = contains_seq(tokens, &["SECURITY", "DEFINER"]);
    if g.flags.security_definer {
        g = g.note("SECURITY DEFINER code runs with the privileges of its owner");
    }
    g
}

fn alter_guess(tokens: &[Lex]) -> Guess {
    let (kind, obj, at, _) = object_keyword(tokens, 1);
    let mut g = Guess::new(kind).with_name(tokens, at, obj, Access::Alter);
    g.flags.drops_column = contains_seq(tokens, &["DROP", "COLUMN"]);
    g.flags.drops_constraint = contains_seq(tokens, &["DROP", "CONSTRAINT"]);
    g.flags.changes_owner = contains_seq(tokens, &["OWNER", "TO"]);
    g.flags.renames = has_word(tokens, "RENAME");
    g.flags.weakens_rls = contains_seq(tokens, &["DISABLE", "ROW"]);
    g.flags.strengthens_rls = contains_seq(tokens, &["ENABLE", "ROW"]);
    g.flags.disables_trigger = contains_seq(tokens, &["DISABLE", "TRIGGER"]);
    g.flags.grants_elevated_role = has_word(tokens, "SUPERUSER")
        || has_word(tokens, "BYPASSRLS")
        || has_word(tokens, "REPLICATION");
    if g.flags.grants_elevated_role {
        g = g.note("this statement grants an elevated role attribute");
    }
    if g.flags.weakens_rls {
        g = g.note("disabling row level security exposes every row of the table");
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_do_blocks() {
        let a = classify("DO $$ BEGIN DROP TABLE users; END $$", 0, None);
        assert_eq!(a.kind, StatementKind::DoBlock);
        assert!(a.flags.opaque_body);
        assert!(a.flags.opaque_body_is_destructive);
        assert!(!a.parsed);
    }

    #[test]
    fn a_harmless_do_block_is_not_flagged_destructive() {
        let a = classify("DO $$ BEGIN RAISE NOTICE 'hi'; END $$", 0, None);
        assert!(a.flags.opaque_body);
        assert!(!a.flags.opaque_body_is_destructive);
    }

    #[test]
    fn classifies_drop_variants() {
        let a = classify("DROP TABLE IF EXISTS auth.users CASCADE", 0, None);
        assert_eq!(a.kind, StatementKind::DropTable);
        assert!(a.flags.cascade);
        assert!(a.flags.if_exists);
        assert_eq!(a.objects[0].qualified(), "auth.users");

        let a = classify("DROP SCHEMA public CASCADE", 0, None);
        assert_eq!(a.kind, StatementKind::DropSchema);
        assert_eq!(a.objects[0].qualified(), "public.public");
    }

    #[test]
    fn classifies_maintenance() {
        assert_eq!(
            classify("REINDEX TABLE orders", 0, None).kind,
            StatementKind::Reindex
        );
        assert_eq!(
            classify("CLUSTER orders USING orders_pkey", 0, None).kind,
            StatementKind::Cluster
        );
        assert_eq!(
            classify("CHECKPOINT", 0, None).kind,
            StatementKind::Checkpoint
        );
    }

    #[test]
    fn unparsed_statements_never_claim_a_where_clause() {
        let a = classify(
            "DELETE FROM users WHERE id = 1 RETURNING weird_syntax(",
            0,
            None,
        );
        assert!(a.predicate.is_unfiltered());
    }

    #[test]
    fn unknown_statements_are_unknown_not_harmless() {
        let a = classify("FLARGLE BARGLE", 0, None);
        assert_eq!(a.kind, StatementKind::Unknown);
    }

    #[test]
    fn alter_flags_are_detected() {
        let a = classify(
            "ALTER TABLE public.users DISABLE ROW LEVEL SECURITY",
            0,
            None,
        );
        assert_eq!(a.kind, StatementKind::AlterTable);
        assert!(a.flags.weakens_rls);

        let a = classify("ALTER TABLE t DROP COLUMN email", 0, None);
        assert!(a.flags.drops_column);

        let a = classify("ALTER ROLE app WITH SUPERUSER", 0, None);
        assert!(a.flags.grants_elevated_role);
    }
}
