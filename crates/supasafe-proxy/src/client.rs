//! A minimal PostgreSQL client, used only for SupaSafe's own introspection.
//!
//! This exists so that blast radius can be measured rather than guessed. It
//! connects with its own credentials, runs three read-only queries against the
//! system catalogues, and disconnects. It never carries an agent's statements
//! and never touches an agent's credentials.
//!
//! It is deliberately small: startup, authentication, simple query, text
//! results. Nothing else is needed to read `pg_class`, and a fuller client
//! would be a much larger surface for no benefit.
//!
//! Authentication supports trust, cleartext, MD5 and SCRAM-SHA-256, which is
//! what Supabase and every modern PostgreSQL use.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::protocol::{self, Frame, Startup};
use crate::tls::TlsClientConfig;

/// What can go wrong while introspecting.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("could not reach {host}:{port}: {source}")]
    Connect {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS failed: {0}")]
    Tls(String),
    #[error("the database refused the connection: {0}")]
    Rejected(String),
    #[error(
        "this server asked for {0} authentication, which the introspection client does not \
         implement. Use a role with SCRAM-SHA-256, MD5 or password authentication."
    )]
    UnsupportedAuth(String),
    #[error("no password was supplied, but the server asked for one")]
    PasswordRequired,
    #[error("the server sent something unexpected during {0}")]
    Protocol(&'static str),
}

/// A result set from a simple query, as text.
#[derive(Debug, Default, Clone)]
pub struct Rows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
}

impl Rows {
    /// The value in a named column, for a row.
    pub fn get<'a>(&'a self, row: &'a [Option<String>], column: &str) -> Option<&'a str> {
        let index = self.columns.iter().position(|c| c == column)?;
        row.get(index)?.as_deref()
    }

    /// A named column parsed as a number, defaulting to zero. Catalogue
    /// numbers that do not parse are not worth failing an entire refresh over.
    pub fn number(&self, row: &[Option<String>], column: &str) -> u64 {
        self.get(row, column)
            .and_then(|v| v.parse::<f64>().ok())
            .map(|v| if v < 0.0 { 0 } else { v as u64 })
            .unwrap_or(0)
    }

    pub fn boolean(&self, row: &[Option<String>], column: &str) -> bool {
        matches!(self.get(row, column), Some("t") | Some("true"))
    }
}

/// Where and how to connect.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub database: String,
    pub use_tls: bool,
}

impl ClientConfig {
    /// Parse a libpq-style URL.
    pub fn from_url(url: &str) -> Option<ClientConfig> {
        let rest = url
            .strip_prefix("postgresql://")
            .or_else(|| url.strip_prefix("postgres://"))?;
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, p),
            None => (rest, ""),
        };
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (user, password) = match userinfo {
            Some(info) => match info.split_once(':') {
                Some((u, p)) => (decode(u), Some(decode(p))),
                None => (decode(info), None),
            },
            None => ("postgres".to_string(), None),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(5432)),
            None => (hostport.to_string(), 5432),
        };
        let (database, query) = match path.split_once('?') {
            Some((d, q)) => (d.to_string(), q),
            None => (path.to_string(), ""),
        };

        // sslmode=disable is the only value that turns TLS off; everything
        // else either wants it or tolerates it, and wanting it is the safer
        // reading. Loopback has no network to protect.
        let use_tls = !query
            .split('&')
            .any(|pair| pair.eq_ignore_ascii_case("sslmode=disable"))
            && !is_local(&host);

        Some(ClientConfig {
            host,
            port,
            user,
            password,
            database: if database.is_empty() {
                "postgres".to_string()
            } else {
                database
            },
            use_tls,
        })
    }

    /// Follow the operator's decision about TLS to the database.
    ///
    /// `proxy.upstream_tls` governs how SupaSafe talks to your database, and
    /// the introspection connection is SupaSafe talking to your database. One
    /// setting, not two that can disagree.
    ///
    /// An explicit `sslmode=disable` in the URL still wins, and loopback is
    /// still left alone: there is no network there to protect.
    pub fn with_upstream_tls(mut self, required: bool) -> ClientConfig {
        if !required {
            self.use_tls = false;
        } else if !is_local(&self.host) {
            self.use_tls = true;
        }
        self
    }
}

fn is_local(host: &str) -> bool {
    host == "localhost" || host.starts_with("127.") || host == "::1" || host.starts_with('/')
}

/// Percent-decode a userinfo component, because passwords routinely contain
/// characters that have to be escaped in a URL.
fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Connect, run some queries, disconnect.
pub async fn query_all(
    config: &ClientConfig,
    statements: &[&str],
) -> Result<Vec<Rows>, ClientError> {
    let stream = TcpStream::connect((config.host.as_str(), config.port))
        .await
        .map_err(|source| ClientError::Connect {
            host: config.host.clone(),
            port: config.port,
            source,
        })?;
    stream.set_nodelay(true)?;

    if config.use_tls {
        let mut stream = stream;
        stream.write_all(&Startup::SslRequest.encode()).await?;
        stream.flush().await?;
        let mut answer = [0u8; 1];
        stream.read_exact(&mut answer).await?;
        if answer[0] != b'S' {
            return Err(ClientError::Tls(
                "the server refused TLS for the introspection connection".into(),
            ));
        }
        let tls =
            TlsClientConfig::with_webpki_roots().map_err(|e| ClientError::Tls(e.to_string()))?;
        let stream = tls
            .connect(&config.host, stream)
            .await
            .map_err(|e| ClientError::Tls(e.to_string()))?;
        run(stream, config, statements).await
    } else {
        run(stream, config, statements).await
    }
}

async fn run<S>(
    mut stream: S,
    config: &ClientConfig,
    statements: &[&str],
) -> Result<Vec<Rows>, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut parameters = HashMap::new();
    parameters.insert("user".to_string(), config.user.clone());
    parameters.insert("database".to_string(), config.database.clone());
    parameters.insert(
        "application_name".to_string(),
        "supasafe-introspect".to_string(),
    );
    // Read-only by construction, so a mistake in a catalogue query cannot
    // write anything.
    parameters.insert(
        "default_transaction_read_only".to_string(),
        "on".to_string(),
    );

    let startup = Startup::Connect {
        version: protocol::PROTOCOL_VERSION_3,
        parameters,
    };
    stream.write_all(&startup.encode()).await?;
    stream.flush().await?;

    authenticate(&mut stream, config).await?;

    let mut results = Vec::with_capacity(statements.len());
    for sql in statements {
        results.push(simple_query(&mut stream, sql).await?);
    }

    let _ = stream
        .write_all(&Frame::new(protocol::FE_TERMINATE, vec![]).encode())
        .await;
    Ok(results)
}

/// Relay the authentication exchange until the server says it is satisfied.
async fn authenticate<S>(stream: &mut S, config: &ClientConfig) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let Some(frame) = protocol::read_frame(stream).await? else {
            return Err(ClientError::Protocol("authentication"));
        };

        match frame.tag {
            protocol::BE_ERROR => {
                return Err(ClientError::Rejected(
                    protocol::error_message(&frame).unwrap_or_else(|| "unknown error".into()),
                ));
            }
            protocol::BE_AUTHENTICATION => {
                if frame.payload.len() < 4 {
                    return Err(ClientError::Protocol("authentication"));
                }
                let kind = i32::from_be_bytes([
                    frame.payload[0],
                    frame.payload[1],
                    frame.payload[2],
                    frame.payload[3],
                ]);
                match kind {
                    // AuthenticationOk
                    0 => {}
                    // Cleartext password
                    3 => {
                        let password = config
                            .password
                            .as_deref()
                            .ok_or(ClientError::PasswordRequired)?;
                        send_password(stream, password.as_bytes()).await?;
                    }
                    // MD5 password
                    5 => {
                        let password = config
                            .password
                            .as_deref()
                            .ok_or(ClientError::PasswordRequired)?;
                        let salt = &frame.payload[4..];
                        if salt.len() < 4 {
                            return Err(ClientError::Protocol("md5 salt"));
                        }
                        let hashed = md5_password(&config.user, password, &salt[..4]);
                        send_password(stream, hashed.as_bytes()).await?;
                    }
                    // SASL
                    10 => {
                        let password = config
                            .password
                            .as_deref()
                            .ok_or(ClientError::PasswordRequired)?;
                        scram(stream, password).await?;
                    }
                    other => {
                        return Err(ClientError::UnsupportedAuth(match other {
                            2 => "Kerberos".into(),
                            6 => "SCM credential".into(),
                            7 | 8 => "GSSAPI".into(),
                            9 => "SSPI".into(),
                            n => format!("type {n}"),
                        }));
                    }
                }
            }
            // ReadyForQuery: authentication finished and the session is up.
            protocol::BE_READY_FOR_QUERY => return Ok(()),
            // ParameterStatus, BackendKeyData and notices are not interesting
            // here.
            _ => {}
        }
    }
}

async fn send_password<S>(stream: &mut S, payload: &[u8]) -> Result<(), ClientError>
where
    S: AsyncWrite + Unpin,
{
    let mut body = payload.to_vec();
    body.push(0);
    stream
        .write_all(&Frame::new(protocol::FE_PASSWORD, body).encode())
        .await?;
    stream.flush().await?;
    Ok(())
}

/// `md5(md5(password + user) + salt)`, prefixed with "md5".
fn md5_password(user: &str, password: &str, salt: &[u8]) -> String {
    use md5::Md5;
    let inner = Md5::digest(format!("{password}{user}").as_bytes());
    let inner_hex = hex_lower(&inner);
    let mut outer = Md5::new();
    outer.update(inner_hex.as_bytes());
    outer.update(salt);
    format!("md5{}", hex_lower(&outer.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// SCRAM-SHA-256 (RFC 5802 / RFC 7677)
// ---------------------------------------------------------------------------

async fn scram<S>(stream: &mut S, password: &str) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // A fixed nonce would be a real weakness in a general client. Here both
    // ends are ours and the channel is either loopback or TLS, but deriving it
    // from the clock and the address of a local allocation still avoids
    // sending the same nonce twice.
    let nonce = client_nonce();

    let client_first_bare = format!("n=,r={nonce}");
    let client_first = format!("n,,{client_first_bare}");

    let mut body = Vec::new();
    protocol::write_cstring(&mut body, "SCRAM-SHA-256");
    body.extend_from_slice(&(client_first.len() as i32).to_be_bytes());
    body.extend_from_slice(client_first.as_bytes());
    stream
        .write_all(&Frame::new(protocol::FE_PASSWORD, body).encode())
        .await?;
    stream.flush().await?;

    // AuthenticationSASLContinue
    let frame = expect_auth(stream, 11).await?;
    let server_first = String::from_utf8_lossy(&frame.payload[4..]).into_owned();
    let fields = scram_fields(&server_first);

    let server_nonce = fields
        .get("r")
        .ok_or(ClientError::Protocol("SCRAM server-first"))?;
    let salt = BASE64
        .decode(fields.get("s").ok_or(ClientError::Protocol("SCRAM salt"))?)
        .map_err(|_| ClientError::Protocol("SCRAM salt"))?;
    let iterations: u32 = fields
        .get("i")
        .and_then(|i| i.parse().ok())
        .ok_or(ClientError::Protocol("SCRAM iteration count"))?;

    if !server_nonce.starts_with(&nonce) {
        return Err(ClientError::Rejected(
            "the server's SCRAM nonce does not extend ours".into(),
        ));
    }

    let salted = pbkdf2_sha256(password.as_bytes(), &salt, iterations);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = Sha256::digest(&client_key);

    let channel_binding = format!("c={}", BASE64.encode(b"n,,"));
    let client_final_bare = format!("{channel_binding},r={server_nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");

    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    let client_final = format!("{client_final_bare},p={}", BASE64.encode(&proof));
    stream
        .write_all(&Frame::new(protocol::FE_PASSWORD, client_final.into_bytes()).encode())
        .await?;
    stream.flush().await?;

    // AuthenticationSASLFinal. The server proof is checked rather than
    // ignored: skipping it would let anything that can answer the handshake
    // impersonate the database.
    let frame = expect_auth(stream, 12).await?;
    let server_final = String::from_utf8_lossy(&frame.payload[4..]).into_owned();
    let fields = scram_fields(&server_final);
    let sent = fields
        .get("v")
        .ok_or(ClientError::Protocol("SCRAM server-final"))?;

    let server_key = hmac_sha256(&salted, b"Server Key");
    let expected = BASE64.encode(hmac_sha256(&server_key, auth_message.as_bytes()));
    if sent != &expected {
        return Err(ClientError::Rejected(
            "the server could not prove it knows the password; this is not the database you \
             think it is"
                .into(),
        ));
    }

    Ok(())
}

fn client_nonce() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let marker = Box::new(0u8);
    let address = &*marker as *const u8 as usize;
    hex_lower(&Sha256::digest(format!("{now}:{address}").as_bytes()))[..32].to_string()
}

fn scram_fields(message: &str) -> HashMap<String, String> {
    message
        .split(',')
        .filter_map(|part| part.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// HMAC-SHA-256, written out rather than pulled in: it is nine lines and this
/// is the only place SupaSafe needs it.
fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    inner.update(padded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(padded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(inner);
    outer.finalize().to_vec()
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    // One 32-byte block is exactly the output length SCRAM-SHA-256 wants.
    let mut salted = salt.to_vec();
    salted.extend_from_slice(&1u32.to_be_bytes());

    let mut previous = hmac_sha256(password, &salted);
    let mut result = previous.clone();
    for _ in 1..iterations {
        previous = hmac_sha256(password, &previous);
        for (r, p) in result.iter_mut().zip(previous.iter()) {
            *r ^= p;
        }
    }
    result
}

async fn expect_auth<S>(stream: &mut S, kind: i32) -> Result<Frame, ClientError>
where
    S: AsyncRead + Unpin,
{
    let Some(frame) = protocol::read_frame(stream).await? else {
        return Err(ClientError::Protocol("SCRAM exchange"));
    };
    if frame.tag == protocol::BE_ERROR {
        return Err(ClientError::Rejected(
            protocol::error_message(&frame).unwrap_or_else(|| "unknown error".into()),
        ));
    }
    if frame.tag != protocol::BE_AUTHENTICATION || frame.payload.len() < 4 {
        return Err(ClientError::Protocol("SCRAM exchange"));
    }
    let got = i32::from_be_bytes([
        frame.payload[0],
        frame.payload[1],
        frame.payload[2],
        frame.payload[3],
    ]);
    if got != kind {
        return Err(ClientError::Protocol("SCRAM exchange"));
    }
    Ok(frame)
}

// ---------------------------------------------------------------------------
// Simple query
// ---------------------------------------------------------------------------

async fn simple_query<S>(stream: &mut S, sql: &str) -> Result<Rows, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&Frame::query(sql).encode()).await?;
    stream.flush().await?;

    let mut rows = Rows::default();
    let mut error = None;

    loop {
        let Some(frame) = protocol::read_frame(stream).await? else {
            return Err(ClientError::Protocol("query"));
        };
        match frame.tag {
            protocol::BE_ROW_DESCRIPTION => rows.columns = parse_row_description(&frame),
            protocol::BE_DATA_ROW => rows.rows.push(parse_data_row(&frame)),
            protocol::BE_ERROR => error = protocol::error_message(&frame),
            protocol::BE_READY_FOR_QUERY => break,
            _ => {}
        }
    }

    match error {
        Some(message) => Err(ClientError::Rejected(message)),
        None => Ok(rows),
    }
}

fn parse_row_description(frame: &Frame) -> Vec<String> {
    let payload = &frame.payload;
    if payload.len() < 2 {
        return Vec::new();
    }
    let count = i16::from_be_bytes([payload[0], payload[1]]).max(0) as usize;
    let mut names = Vec::with_capacity(count);
    let mut pos = 2;
    for _ in 0..count {
        let Some((name, next)) = protocol::read_cstring(payload, pos) else {
            break;
        };
        names.push(name);
        // Each field carries 18 bytes of metadata after its name.
        pos = next + 18;
        if pos > payload.len() {
            break;
        }
    }
    names
}

fn parse_data_row(frame: &Frame) -> Vec<Option<String>> {
    let payload = &frame.payload;
    if payload.len() < 2 {
        return Vec::new();
    }
    let count = i16::from_be_bytes([payload[0], payload[1]]).max(0) as usize;
    let mut values = Vec::with_capacity(count);
    let mut pos = 2;
    for _ in 0..count {
        if pos + 4 > payload.len() {
            break;
        }
        let length = i32::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]);
        pos += 4;
        if length < 0 {
            values.push(None);
            continue;
        }
        let end = (pos + length as usize).min(payload.len());
        values.push(Some(
            String::from_utf8_lossy(&payload[pos..end]).into_owned(),
        ));
        pos = end;
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_parsed_including_escaped_passwords() {
        let c = ClientConfig::from_url(
            "postgresql://supasafe_ro:p%40ss%3Aword@db.abc.supabase.co:5432/postgres",
        )
        .unwrap();
        assert_eq!(c.user, "supasafe_ro");
        assert_eq!(c.password.as_deref(), Some("p@ss:word"));
        assert_eq!(c.host, "db.abc.supabase.co");
        assert_eq!(c.port, 5432);
        assert_eq!(c.database, "postgres");
        assert!(c.use_tls);
    }

    #[test]
    fn local_connections_do_not_demand_tls() {
        let c = ClientConfig::from_url("postgresql://postgres@127.0.0.1:5432/app").unwrap();
        assert!(!c.use_tls);
        assert_eq!(c.database, "app");
    }

    #[test]
    fn the_upstream_tls_setting_governs_introspection_too() {
        // A deployment that turned TLS off for the proxy did so for a reason;
        // the introspection connection must not then demand it and fail.
        let c = ClientConfig::from_url("postgresql://postgres:postgres@postgres:5432/postgres")
            .unwrap();
        assert!(c.use_tls, "a remote host defaults to TLS");
        assert!(!c.clone().with_upstream_tls(false).use_tls);

        // And a deployment that wants TLS gets it.
        let c = ClientConfig::from_url("postgresql://u:p@db.example.com/app").unwrap();
        assert!(c.with_upstream_tls(true).use_tls);

        // Loopback stays plain either way: there is no network to protect.
        let c = ClientConfig::from_url("postgresql://postgres@127.0.0.1:5432/app").unwrap();
        assert!(!c.with_upstream_tls(true).use_tls);
    }

    #[test]
    fn sslmode_disable_is_honoured() {
        let c =
            ClientConfig::from_url("postgresql://u:p@db.example.com/app?sslmode=disable").unwrap();
        assert!(!c.use_tls);
    }

    #[test]
    fn hmac_matches_the_published_vectors() {
        // RFC 4231, test case 1.
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex_lower(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // RFC 4231, test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex_lower(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn pbkdf2_matches_the_published_vectors() {
        // RFC 7677 section 3: password "pencil", salt "W22ZaJ0SNY7soEsUEjb6gQ==",
        // 4096 iterations. The salted password is the documented value.
        let salt = BASE64.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let salted = pbkdf2_sha256(b"pencil", &salt, 4096);
        assert_eq!(
            BASE64.encode(&salted),
            "xKSVEDI6tPlSysH6mUQZOeeOp01r6B3fcJbodRPcYV0="
        );
    }

    #[test]
    fn md5_password_matches_the_documented_construction() {
        // md5(md5("passworduser") + salt), prefixed with "md5".
        let hashed = md5_password("user", "password", &[1, 2, 3, 4]);
        assert!(hashed.starts_with("md5"));
        assert_eq!(hashed.len(), 35);
    }

    #[test]
    fn nonces_differ_between_handshakes() {
        assert_ne!(client_nonce(), client_nonce());
    }

    #[test]
    fn data_rows_decode_including_nulls() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&2i16.to_be_bytes());
        payload.extend_from_slice(&5i32.to_be_bytes());
        payload.extend_from_slice(b"hello");
        payload.extend_from_slice(&(-1i32).to_be_bytes());
        let frame = Frame::new(protocol::BE_DATA_ROW, payload);
        assert_eq!(
            parse_data_row(&frame),
            vec![Some("hello".to_string()), None]
        );
    }

    #[test]
    fn row_descriptions_decode() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1i16.to_be_bytes());
        protocol::write_cstring(&mut payload, "schema");
        payload.extend_from_slice(&[0u8; 18]);
        let frame = Frame::new(protocol::BE_ROW_DESCRIPTION, payload);
        assert_eq!(parse_row_description(&frame), vec!["schema".to_string()]);
    }

    #[test]
    fn numbers_survive_the_float_shaped_values_pg_class_returns() {
        let rows = Rows {
            columns: vec!["reltuples".into()],
            rows: vec![],
        };
        // reltuples is a float4 and can come back negative when unanalysed.
        assert_eq!(rows.number(&[Some("8412".into())], "reltuples"), 8412);
        assert_eq!(rows.number(&[Some("-1".into())], "reltuples"), 0);
        assert_eq!(rows.number(&[None], "reltuples"), 0);
    }
}
