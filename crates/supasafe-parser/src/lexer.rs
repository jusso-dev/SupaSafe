//! A minimal PostgreSQL lexical scanner used to split a multi-statement batch
//! into individual statements.
//!
//! This is a character-level state machine, not a regular expression. It
//! understands the four PostgreSQL constructs in which a `;` does *not*
//! terminate a statement:
//!
//! * single quoted strings, including the `''` escape and `E'\'` escapes
//! * double quoted (delimited) identifiers, including the `""` escape
//! * dollar quoted strings (`$$ ... $$`, `$tag$ ... $tag$`)
//! * comments (`-- line`, `/* nested block */`)
//!
//! Splitting has to happen before parsing because a single unparseable
//! statement in a batch must not blind SupaSafe to the statements around it.
//! An attacker (or a confused model) that appends `DROP SCHEMA public CASCADE`
//! after a statement our AST parser rejects would otherwise sail straight
//! through.

/// A statement sliced out of a batch, with its byte offset in the original
/// input so callers can report positions against the text the client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawStatement {
    pub text: String,
    pub offset: usize,
}

/// Split a SQL batch into individual statements.
///
/// Empty statements (stray semicolons, trailing whitespace, comment-only
/// fragments) are dropped. The returned text does not include the trailing
/// semicolon.
pub fn split_statements(sql: &str) -> Vec<RawStatement> {
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' => i = skip_single_quoted(bytes, i),
            b'"' => i = skip_double_quoted(bytes, i),
            b'$' => match dollar_tag(bytes, i) {
                Some(tag_end) => i = skip_dollar_quoted(bytes, i, tag_end),
                None => i += 1,
            },
            b'-' if bytes.get(i + 1) == Some(&b'-') => i = skip_line_comment(bytes, i),
            b'/' if bytes.get(i + 1) == Some(&b'*') => i = skip_block_comment(bytes, i),
            b';' => {
                push(&mut out, sql, start, i);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    push(&mut out, sql, start, bytes.len());
    out
}

fn push(out: &mut Vec<RawStatement>, sql: &str, start: usize, end: usize) {
    if start >= end || end > sql.len() {
        return;
    }
    let slice = &sql[start..end];
    let trimmed = slice.trim();
    if trimmed.is_empty() || is_only_comments(trimmed) {
        return;
    }
    // Preserve the offset of the first non-whitespace byte.
    let lead = slice.len() - slice.trim_start().len();
    out.push(RawStatement {
        text: trimmed.to_string(),
        offset: start + lead,
    });
}

/// True when the fragment contains nothing but comments and whitespace.
fn is_only_comments(fragment: &str) -> bool {
    let bytes = fragment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'-' if bytes.get(i + 1) == Some(&b'-') => i = skip_line_comment(bytes, i),
            b'/' if bytes.get(i + 1) == Some(&b'*') => i = skip_block_comment(bytes, i),
            c if c.is_ascii_whitespace() => i += 1,
            _ => return false,
        }
    }
    true
}

fn skip_single_quoted(bytes: &[u8], mut i: usize) -> usize {
    // Detect an E'' string, whose backslash escapes are honoured by Postgres.
    let escaped = i > 0 && matches!(bytes[i - 1], b'e' | b'E');
    i += 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if escaped => i += 2,
            b'\'' if bytes.get(i + 1) == Some(&b'\'') => i += 2,
            b'\'' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn skip_double_quoted(bytes: &[u8], mut i: usize) -> usize {
    i += 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' if bytes.get(i + 1) == Some(&b'"') => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// If a dollar quote tag opens at `i`, return the index just past the opening
/// tag (i.e. past the closing `$`). Returns `None` for `$1` placeholders and
/// bare `$` characters.
fn dollar_tag(bytes: &[u8], i: usize) -> Option<usize> {
    // A tag body must be a valid identifier (or empty for `$$`).
    let mut j = i + 1;
    while j < bytes.len() && (bytes[j] == b'_' || bytes[j].is_ascii_alphanumeric()) {
        // A leading digit means this is a positional parameter such as `$1`.
        if j == i + 1 && bytes[j].is_ascii_digit() {
            return None;
        }
        j += 1;
    }
    if bytes.get(j) == Some(&b'$') {
        Some(j + 1)
    } else {
        None
    }
}

fn skip_dollar_quoted(bytes: &[u8], open: usize, body_start: usize) -> usize {
    let tag = &bytes[open..body_start];
    let mut i = body_start;
    while i + tag.len() <= bytes.len() {
        if bytes[i] == b'$' && &bytes[i..i + tag.len()] == tag {
            return i + tag.len();
        }
        i += 1;
    }
    bytes.len()
}

fn skip_line_comment(bytes: &[u8], mut i: usize) -> usize {
    i += 2;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_block_comment(bytes: &[u8], mut i: usize) -> usize {
    // PostgreSQL block comments nest.
    let mut depth = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            depth += 1;
            i += 2;
        } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(sql: &str) -> Vec<String> {
        split_statements(sql).into_iter().map(|s| s.text).collect()
    }

    #[test]
    fn splits_plain_statements() {
        assert_eq!(
            texts("SELECT 1; SELECT 2"),
            vec!["SELECT 1".to_string(), "SELECT 2".to_string()]
        );
    }

    #[test]
    fn semicolon_inside_string_is_not_a_split() {
        assert_eq!(texts("SELECT 'a;b'").len(), 1);
        assert_eq!(texts("SELECT 'it''s; fine'").len(), 1);
        assert_eq!(texts(r"SELECT E'a\';b'").len(), 1);
    }

    #[test]
    fn semicolon_inside_dollar_quote_is_not_a_split() {
        let sql = "DO $$ BEGIN DELETE FROM users; END $$; SELECT 1";
        assert_eq!(texts(sql).len(), 2);
        let sql = "CREATE FUNCTION f() RETURNS void AS $body$ SELECT 1; $body$ LANGUAGE sql";
        assert_eq!(texts(sql).len(), 1);
    }

    #[test]
    fn positional_parameters_are_not_dollar_quotes() {
        assert_eq!(texts("SELECT $1; SELECT $2").len(), 2);
    }

    #[test]
    fn semicolon_inside_comment_is_not_a_split() {
        assert_eq!(texts("SELECT 1 -- ; not a split\n").len(), 1);
        assert_eq!(texts("SELECT /* ; /* nested ; */ */ 1").len(), 1);
    }

    #[test]
    fn quoted_identifiers_are_respected() {
        assert_eq!(texts(r#"SELECT * FROM "we;ird""#).len(), 1);
    }

    #[test]
    fn comment_only_fragments_are_dropped() {
        assert!(texts("-- nothing here\n").is_empty());
        assert!(texts(";;;").is_empty());
    }

    #[test]
    fn offsets_point_at_the_statement() {
        let sql = "  SELECT 1;  DROP TABLE t";
        let parts = split_statements(sql);
        assert_eq!(&sql[parts[0].offset..parts[0].offset + 8], "SELECT 1");
        assert_eq!(&sql[parts[1].offset..], "DROP TABLE t");
    }
}
