//! Statement normalisation.
//!
//! Two jobs, both lexical:
//!
//! * produce a stable shape for a statement so that the same query with
//!   different literals groups together in the audit log and the dashboard;
//! * strip literal values so SupaSafe can record what an agent ran without
//!   copying passwords, tokens, PII or API keys into its own logs.
//!
//! Normalisation runs on the token stream, so it is correct for dollar quoted
//! bodies, escaped strings and comments.

use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

/// Replace every literal with `?` and collapse whitespace.
///
/// `SELECT * FROM users WHERE email = 'ada@example.com'` becomes
/// `SELECT * FROM users WHERE email = ?`.
pub fn normalize(sql: &str) -> String {
    let dialect = PostgreSqlDialect {};
    let tokens = match Tokenizer::new(&dialect, sql).tokenize() {
        Ok(t) => t,
        // If the statement does not even tokenise we cannot safely emit any of
        // it, because we cannot tell where a string literal begins or ends.
        Err(_) => return "<untokenizable statement>".to_string(),
    };

    let mut out = String::with_capacity(sql.len());
    let mut needs_space = false;

    for token in tokens {
        let piece = match token {
            Token::EOF => continue,
            // Comments can carry anything a model was told; drop them.
            Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_)) => {
                needs_space = true;
                continue;
            }
            Token::Whitespace(_) => {
                needs_space = true;
                continue;
            }
            Token::Number(_, _)
            | Token::SingleQuotedString(_)
            | Token::DollarQuotedString(_)
            | Token::TripleSingleQuotedString(_)
            | Token::TripleDoubleQuotedString(_)
            | Token::EscapedStringLiteral(_)
            | Token::UnicodeStringLiteral(_)
            | Token::NationalStringLiteral(_)
            | Token::HexStringLiteral(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_)
            | Token::SingleQuotedRawStringLiteral(_)
            | Token::DoubleQuotedRawStringLiteral(_) => "?".to_string(),
            Token::Word(ref w) => match w.quote_style {
                // A quoted identifier is structure, not data. Keep it.
                Some(q) => format!("{q}{}{q}", w.value),
                None => w.value.to_ascii_uppercase(),
            },
            ref other => other.to_string(),
        };

        if needs_space && !out.is_empty() && !piece.is_empty() {
            let last = out.chars().last().unwrap_or(' ');
            let first = piece.chars().next().unwrap_or(' ');
            // Do not insert a space where SQL never needs one; it keeps the
            // fingerprint stable across formatting differences.
            let tight = matches!(last, '(' | '.') || matches!(first, ')' | ',' | '.' | ';');
            if !tight {
                out.push(' ');
            }
        }
        out.push_str(&piece);
        needs_space = false;
    }

    out.trim().to_string()
}

/// A short, human-readable summary for lists and notifications.
pub fn summarize(sql: &str, max_chars: usize) -> String {
    let flat = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars {
        return flat;
    }
    let truncated: String = flat.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{truncated}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_string_literals() {
        assert_eq!(
            normalize("SELECT * FROM users WHERE email = 'ada@example.com'"),
            "SELECT * FROM USERS WHERE EMAIL = ?"
        );
    }

    #[test]
    fn masks_numbers() {
        assert_eq!(
            normalize("DELETE FROM t WHERE id = 42"),
            "DELETE FROM T WHERE ID = ?"
        );
    }

    #[test]
    fn same_shape_different_literals_match() {
        assert_eq!(
            normalize("UPDATE users SET name='a' WHERE id=1"),
            normalize("UPDATE users SET name='zzz' WHERE id=99999")
        );
    }

    #[test]
    fn keeps_quoted_identifiers() {
        assert_eq!(
            normalize(r#"SELECT "userId" FROM t"#),
            r#"SELECT "userId" FROM T"#
        );
    }

    #[test]
    fn drops_comments() {
        let n = normalize("SELECT 1 -- secret note about tokens\n");
        assert!(
            !n.contains("secret"),
            "comment leaked into normalized form: {n}"
        );
    }

    #[test]
    fn masks_dollar_quoted_bodies() {
        let n = normalize("DO $$ BEGIN PERFORM set_config('x', 'sk-live-abcdef', false); END $$");
        assert!(!n.contains("sk-live"), "secret leaked: {n}");
    }

    #[test]
    fn summarize_truncates() {
        assert_eq!(summarize("select   1", 40), "select 1");
        assert_eq!(summarize("aaaaaaaaaa", 5).chars().count(), 5);
    }
}
