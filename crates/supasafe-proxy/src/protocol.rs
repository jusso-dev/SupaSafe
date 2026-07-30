//! PostgreSQL frontend/backend protocol, version 3.
//!
//! Enough of the wire format to read what a client is asking for, forward it
//! unchanged, and synthesise a refusal that every PostgreSQL client already
//! knows how to handle. Speaking the protocol rather than sitting beside it is
//! what makes SupaSafe work with `psql`, with an ORM, and with an agent that
//! has never heard of it.
//!
//! Reference: <https://www.postgresql.org/docs/current/protocol-message-formats.html>

use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// PostgreSQL refuses to allocate more than 1GB for a message, and so do we.
/// Without this, a hostile length prefix is an out-of-memory attack.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 1024;

pub const SSL_REQUEST_CODE: i32 = 80_877_103;
pub const GSSENC_REQUEST_CODE: i32 = 80_877_104;
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;
pub const PROTOCOL_VERSION_3: i32 = 196_608; // 3.0

// Frontend message tags.
pub const FE_QUERY: u8 = b'Q';
pub const FE_PARSE: u8 = b'P';
pub const FE_BIND: u8 = b'B';
pub const FE_EXECUTE: u8 = b'E';
pub const FE_DESCRIBE: u8 = b'D';
pub const FE_CLOSE: u8 = b'C';
pub const FE_SYNC: u8 = b'S';
pub const FE_FLUSH: u8 = b'H';
pub const FE_TERMINATE: u8 = b'X';
pub const FE_FUNCTION_CALL: u8 = b'F';
pub const FE_COPY_DATA: u8 = b'd';
pub const FE_COPY_DONE: u8 = b'c';
pub const FE_COPY_FAIL: u8 = b'f';
pub const FE_PASSWORD: u8 = b'p';

// Backend message tags.
pub const BE_ERROR: u8 = b'E';
pub const BE_NOTICE: u8 = b'N';
pub const BE_READY_FOR_QUERY: u8 = b'Z';
pub const BE_COMMAND_COMPLETE: u8 = b'C';
pub const BE_AUTHENTICATION: u8 = b'R';
pub const BE_PARAMETER_STATUS: u8 = b'S';
pub const BE_BACKEND_KEY_DATA: u8 = b'K';
pub const BE_ROW_DESCRIPTION: u8 = b'T';
pub const BE_DATA_ROW: u8 = b'D';
pub const BE_EMPTY_QUERY: u8 = b'I';

/// The transaction status PostgreSQL reports in `ReadyForQuery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Not in a transaction block.
    Idle,
    /// In a transaction block.
    InTransaction,
    /// In a failed transaction block; everything until COMMIT or ROLLBACK is
    /// rejected.
    Failed,
}

impl TransactionStatus {
    pub fn from_byte(b: u8) -> TransactionStatus {
        match b {
            b'T' => TransactionStatus::InTransaction,
            b'E' => TransactionStatus::Failed,
            _ => TransactionStatus::Idle,
        }
    }

    pub fn as_byte(&self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }

    pub fn in_transaction(&self) -> bool {
        matches!(
            self,
            TransactionStatus::InTransaction | TransactionStatus::Failed
        )
    }
}

/// A protocol message: one tag byte and a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub tag: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(tag: u8, payload: Vec<u8>) -> Frame {
        Frame { tag, payload }
    }

    /// The message as it goes on the wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 5);
        out.push(self.tag);
        out.extend_from_slice(&((self.payload.len() + 4) as i32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// The SQL carried by a simple Query message.
    pub fn query_sql(&self) -> Option<String> {
        if self.tag != FE_QUERY {
            return None;
        }
        read_cstring(&self.payload, 0).map(|(s, _)| s)
    }

    /// The prepared statement name and SQL carried by a Parse message.
    pub fn parse_sql(&self) -> Option<(String, String)> {
        if self.tag != FE_PARSE {
            return None;
        }
        let (name, next) = read_cstring(&self.payload, 0)?;
        let (sql, _) = read_cstring(&self.payload, next)?;
        Some((name, sql))
    }

    /// Rewrite the SQL inside a Query or Parse message, keeping everything
    /// else about it intact. Used when an approver edits the statement.
    pub fn with_sql(&self, sql: &str) -> Option<Frame> {
        match self.tag {
            FE_QUERY => Some(Frame::query(sql)),
            FE_PARSE => {
                let (name, next) = read_cstring(&self.payload, 0)?;
                let (_, after_sql) = read_cstring(&self.payload, next)?;
                let mut payload = Vec::new();
                write_cstring(&mut payload, &name);
                write_cstring(&mut payload, sql);
                // Parameter type OIDs follow the statement text.
                payload.extend_from_slice(&self.payload[after_sql..]);
                Some(Frame::new(FE_PARSE, payload))
            }
            _ => None,
        }
    }

    /// A simple Query message.
    pub fn query(sql: &str) -> Frame {
        let mut payload = Vec::with_capacity(sql.len() + 1);
        write_cstring(&mut payload, sql);
        Frame::new(FE_QUERY, payload)
    }

    /// The transaction status carried by a ReadyForQuery message.
    pub fn ready_status(&self) -> Option<TransactionStatus> {
        if self.tag != BE_READY_FOR_QUERY {
            return None;
        }
        self.payload
            .first()
            .map(|b| TransactionStatus::from_byte(*b))
    }
}

/// How a client opened the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// "Do you speak TLS?"
    SslRequest,
    /// "Do you speak GSSAPI encryption?"
    GssEncRequest,
    /// A request to cancel a running query on another connection.
    Cancel { process_id: i32, secret_key: i32 },
    /// A real connection request.
    Connect {
        version: i32,
        parameters: HashMap<String, String>,
    },
}

impl Startup {
    /// The parameters as they go on the wire.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Startup::SslRequest => {
                let mut out = Vec::with_capacity(8);
                out.extend_from_slice(&8i32.to_be_bytes());
                out.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
                out
            }
            Startup::GssEncRequest => {
                let mut out = Vec::with_capacity(8);
                out.extend_from_slice(&8i32.to_be_bytes());
                out.extend_from_slice(&GSSENC_REQUEST_CODE.to_be_bytes());
                out
            }
            Startup::Cancel {
                process_id,
                secret_key,
            } => {
                let mut out = Vec::with_capacity(16);
                out.extend_from_slice(&16i32.to_be_bytes());
                out.extend_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
                out.extend_from_slice(&process_id.to_be_bytes());
                out.extend_from_slice(&secret_key.to_be_bytes());
                out
            }
            Startup::Connect {
                version,
                parameters,
            } => {
                let mut body = Vec::new();
                body.extend_from_slice(&version.to_be_bytes());
                // Sorted so the encoding is deterministic, which makes the
                // round-trip test meaningful.
                let mut keys: Vec<&String> = parameters.keys().collect();
                keys.sort();
                for key in keys {
                    write_cstring(&mut body, key);
                    write_cstring(&mut body, &parameters[key]);
                }
                body.push(0);
                let mut out = Vec::with_capacity(body.len() + 4);
                out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
                out.extend_from_slice(&body);
                out
            }
        }
    }

    /// The database name the client asked for.
    pub fn database(&self) -> Option<&str> {
        match self {
            Startup::Connect { parameters, .. } => parameters.get("database").map(|s| s.as_str()),
            _ => None,
        }
    }

    pub fn user(&self) -> Option<&str> {
        match self {
            Startup::Connect { parameters, .. } => parameters.get("user").map(|s| s.as_str()),
            _ => None,
        }
    }

    /// The `application_name`, which is how SupaSafe knows which agent is on
    /// the other end of the socket.
    pub fn application_name(&self) -> Option<&str> {
        match self {
            Startup::Connect { parameters, .. } => {
                parameters.get("application_name").map(|s| s.as_str())
            }
            _ => None,
        }
    }
}

/// Read a startup packet.
pub async fn read_startup<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Startup> {
    let length = reader.read_i32().await?;
    if !(8..=10_000).contains(&length) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("startup packet length {length} is out of range"),
        ));
    }
    let mut body = vec![0u8; length as usize - 4];
    reader.read_exact(&mut body).await?;

    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    match code {
        SSL_REQUEST_CODE => Ok(Startup::SslRequest),
        GSSENC_REQUEST_CODE => Ok(Startup::GssEncRequest),
        CANCEL_REQUEST_CODE => {
            if body.len() < 12 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated cancel request",
                ));
            }
            Ok(Startup::Cancel {
                process_id: i32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                secret_key: i32::from_be_bytes([body[8], body[9], body[10], body[11]]),
            })
        }
        version => {
            let mut parameters = HashMap::new();
            let mut pos = 4;
            while pos < body.len() {
                if body[pos] == 0 {
                    break;
                }
                let Some((key, next)) = read_cstring(&body, pos) else {
                    break;
                };
                let Some((value, next)) = read_cstring(&body, next) else {
                    break;
                };
                parameters.insert(key, value);
                pos = next;
            }
            Ok(Startup::Connect {
                version,
                parameters,
            })
        }
    }
}

/// Read one tagged message. Returns `None` at a clean end of stream.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Frame>> {
    let mut tag = [0u8; 1];
    match reader.read_exact(&mut tag).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = reader.read_i32().await?;
    if length < 4 || length as usize > MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message length {length} is out of range"),
        ));
    }
    let mut payload = vec![0u8; length as usize - 4];
    reader.read_exact(&mut payload).await?;
    Ok(Some(Frame::new(tag[0], payload)))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> std::io::Result<()> {
    writer.write_all(&frame.encode()).await?;
    writer.flush().await
}

/// Build an ErrorResponse.
///
/// SQLSTATE `42501` is `insufficient_privilege`, which is both true and
/// already handled sensibly by every client library: they surface the message
/// and do not retry.
pub fn error_response(message: &str, detail: Option<&str>, hint: Option<&str>) -> Frame {
    error_with_code("42501", "ERROR", message, detail, hint)
}

/// Build an ErrorResponse with an explicit SQLSTATE and severity.
pub fn error_with_code(
    sqlstate: &str,
    severity: &str,
    message: &str,
    detail: Option<&str>,
    hint: Option<&str>,
) -> Frame {
    let mut payload = Vec::new();
    payload.push(b'S');
    write_cstring(&mut payload, severity);
    payload.push(b'V');
    write_cstring(&mut payload, severity);
    payload.push(b'C');
    write_cstring(&mut payload, sqlstate);
    payload.push(b'M');
    write_cstring(&mut payload, message);
    if let Some(detail) = detail {
        payload.push(b'D');
        write_cstring(&mut payload, detail);
    }
    if let Some(hint) = hint {
        payload.push(b'H');
        write_cstring(&mut payload, hint);
    }
    payload.push(0);
    Frame::new(BE_ERROR, payload)
}

/// Build a NoticeResponse: the client sees it, the statement still runs.
pub fn notice_response(message: &str, detail: Option<&str>) -> Frame {
    let mut payload = Vec::new();
    payload.push(b'S');
    write_cstring(&mut payload, "WARNING");
    payload.push(b'V');
    write_cstring(&mut payload, "WARNING");
    payload.push(b'C');
    write_cstring(&mut payload, "01000");
    payload.push(b'M');
    write_cstring(&mut payload, message);
    if let Some(detail) = detail {
        payload.push(b'D');
        write_cstring(&mut payload, detail);
    }
    payload.push(0);
    Frame::new(BE_NOTICE, payload)
}

pub fn ready_for_query(status: TransactionStatus) -> Frame {
    Frame::new(BE_READY_FOR_QUERY, vec![status.as_byte()])
}

pub fn command_complete(tag: &str) -> Frame {
    let mut payload = Vec::new();
    write_cstring(&mut payload, tag);
    Frame::new(BE_COMMAND_COMPLETE, payload)
}

/// Read a null-terminated string starting at `start`, returning it and the
/// index just past the terminator.
pub fn read_cstring(buf: &[u8], start: usize) -> Option<(String, usize)> {
    if start >= buf.len() {
        return None;
    }
    let end = buf[start..].iter().position(|b| *b == 0)? + start;
    let s = String::from_utf8_lossy(&buf[start..end]).into_owned();
    Some((s, end + 1))
}

pub fn write_cstring(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

/// Pull the human-readable message out of a backend ErrorResponse, for
/// logging what the database said.
pub fn error_message(frame: &Frame) -> Option<String> {
    if frame.tag != BE_ERROR && frame.tag != BE_NOTICE {
        return None;
    }
    let mut pos = 0;
    while pos < frame.payload.len() && frame.payload[pos] != 0 {
        let field = frame.payload[pos];
        let (value, next) = read_cstring(&frame.payload, pos + 1)?;
        if field == b'M' {
            return Some(value);
        }
        pos = next;
    }
    None
}

/// Rows reported by a CommandComplete tag such as `DELETE 42`.
pub fn rows_from_command_tag(frame: &Frame) -> Option<u64> {
    if frame.tag != BE_COMMAND_COMPLETE {
        return None;
    }
    let (tag, _) = read_cstring(&frame.payload, 0)?;
    let mut parts = tag.split_whitespace();
    let verb = parts.next()?;
    match verb {
        // INSERT reports an OID before the row count.
        "INSERT" => parts.nth(1)?.parse().ok(),
        "UPDATE" | "DELETE" | "SELECT" | "MERGE" | "COPY" | "FETCH" | "MOVE" => {
            parts.next()?.parse().ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_round_trip() {
        let frame = Frame::query("SELECT 1");
        let encoded = frame.encode();
        assert_eq!(encoded[0], FE_QUERY);
        assert_eq!(
            i32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]) as usize,
            encoded.len() - 1
        );
        assert_eq!(frame.query_sql().as_deref(), Some("SELECT 1"));
    }

    #[tokio::test]
    async fn frames_read_back() {
        let frame = Frame::query("SELECT 1");
        let mut cursor = Cursor::new(frame.encode());
        let read = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(read, frame);
        // A second read hits a clean end of stream.
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_absurd_length_is_rejected_not_allocated() {
        // Tag 'Q' with a length of 2GB.
        let mut bytes = vec![FE_QUERY];
        bytes.extend_from_slice(&2_000_000_000i32.to_be_bytes());
        let mut cursor = Cursor::new(bytes);
        assert!(read_frame(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn ssl_requests_are_recognised() {
        let mut cursor = Cursor::new(Startup::SslRequest.encode());
        assert_eq!(
            read_startup(&mut cursor).await.unwrap(),
            Startup::SslRequest
        );
    }

    #[tokio::test]
    async fn cancel_requests_are_recognised() {
        let original = Startup::Cancel {
            process_id: 4242,
            secret_key: 9999,
        };
        let mut cursor = Cursor::new(original.encode());
        assert_eq!(read_startup(&mut cursor).await.unwrap(), original);
    }

    #[tokio::test]
    async fn startup_parameters_round_trip() {
        let mut parameters = HashMap::new();
        parameters.insert("user".to_string(), "postgres".to_string());
        parameters.insert("database".to_string(), "app".to_string());
        parameters.insert("application_name".to_string(), "claude-code".to_string());
        let original = Startup::Connect {
            version: PROTOCOL_VERSION_3,
            parameters,
        };
        let mut cursor = Cursor::new(original.encode());
        let read = read_startup(&mut cursor).await.unwrap();
        assert_eq!(read, original);
        assert_eq!(read.database(), Some("app"));
        assert_eq!(read.user(), Some("postgres"));
        assert_eq!(read.application_name(), Some("claude-code"));
    }

    #[test]
    fn parse_messages_expose_their_sql() {
        let mut payload = Vec::new();
        write_cstring(&mut payload, "stmt1");
        write_cstring(&mut payload, "DELETE FROM users WHERE id = $1");
        payload.extend_from_slice(&1i16.to_be_bytes());
        payload.extend_from_slice(&23i32.to_be_bytes());
        let frame = Frame::new(FE_PARSE, payload);
        let (name, sql) = frame.parse_sql().unwrap();
        assert_eq!(name, "stmt1");
        assert_eq!(sql, "DELETE FROM users WHERE id = $1");
    }

    #[test]
    fn parse_messages_can_be_rewritten_keeping_their_parameters() {
        let mut payload = Vec::new();
        write_cstring(&mut payload, "stmt1");
        write_cstring(&mut payload, "DELETE FROM users");
        payload.extend_from_slice(&1i16.to_be_bytes());
        payload.extend_from_slice(&23i32.to_be_bytes());
        let frame = Frame::new(FE_PARSE, payload);

        let edited = frame.with_sql("DELETE FROM users WHERE id = $1").unwrap();
        let (name, sql) = edited.parse_sql().unwrap();
        assert_eq!(name, "stmt1");
        assert_eq!(sql, "DELETE FROM users WHERE id = $1");
        // The parameter type OIDs survived the rewrite.
        assert_eq!(
            &edited.payload[edited.payload.len() - 4..],
            &23i32.to_be_bytes()
        );
    }

    #[test]
    fn error_responses_carry_a_readable_message() {
        let frame = error_response(
            "SupaSafe blocked this statement",
            Some("it would drop the table users"),
            Some("ask a human"),
        );
        assert_eq!(frame.tag, BE_ERROR);
        assert_eq!(
            error_message(&frame).as_deref(),
            Some("SupaSafe blocked this statement")
        );
    }

    #[test]
    fn transaction_status_round_trips() {
        for status in [
            TransactionStatus::Idle,
            TransactionStatus::InTransaction,
            TransactionStatus::Failed,
        ] {
            let frame = ready_for_query(status);
            assert_eq!(frame.ready_status(), Some(status));
        }
        assert!(TransactionStatus::Failed.in_transaction());
        assert!(!TransactionStatus::Idle.in_transaction());
    }

    #[test]
    fn command_tags_report_row_counts() {
        assert_eq!(
            rows_from_command_tag(&command_complete("DELETE 42")),
            Some(42)
        );
        assert_eq!(
            rows_from_command_tag(&command_complete("UPDATE 7")),
            Some(7)
        );
        assert_eq!(
            rows_from_command_tag(&command_complete("INSERT 0 3")),
            Some(3)
        );
        assert_eq!(
            rows_from_command_tag(&command_complete("CREATE TABLE")),
            None
        );
    }

    #[test]
    fn cstrings_handle_empty_and_missing_terminators() {
        let buf = b"abc\0\0def";
        assert_eq!(read_cstring(buf, 0), Some(("abc".to_string(), 4)));
        assert_eq!(read_cstring(buf, 4), Some((String::new(), 5)));
        assert_eq!(read_cstring(b"no terminator", 0), None);
        assert_eq!(read_cstring(b"", 0), None);
    }
}
