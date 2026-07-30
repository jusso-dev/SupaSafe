//! # supasafe-proxy
//!
//! A PostgreSQL wire protocol proxy that enforces SupaSafe policy.
//!
//! Point an agent at this instead of at your database and nothing about its
//! setup changes: it is a PostgreSQL server, it speaks the protocol, and every
//! client already knows how to talk to it. What changes is that a statement
//! now has to get past the policy engine before it reaches your data.
//!
//! ## What it does not do
//!
//! It does not read your credentials. The authentication exchange is relayed
//! between client and server byte for byte, whether that is SCRAM, MD5 or
//! anything else, so no password or proof is ever held in this process.
//!
//! It does not rewrite your queries. An allowed statement is forwarded exactly
//! as it arrived. The only statement SupaSafe ever changes is one an approver
//! deliberately edited, and that edit is re-analysed before it runs.

#![forbid(unsafe_code)]

pub mod client;
pub mod introspect;
pub mod protocol;
pub mod session;
pub mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use supasafe_core::environment::ConnectionTarget;
use supasafe_core::guard::Guard;
use supasafe_core::snapshot::SnapshotManager;

use crate::protocol::{read_startup, Startup};
use crate::session::SessionContext;
use crate::tls::{TlsClientConfig, TlsServerConfig};

/// How the proxy is set up.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Where agents connect.
    pub listen: SocketAddr,
    /// The real database, as `host:port`.
    pub upstream_host: String,
    pub upstream_port: u16,
    /// Offer TLS to connecting clients.
    pub server_tls: Option<TlsServerConfig>,
    /// Require TLS on the connection to the database.
    pub client_tls: Option<TlsClientConfig>,
}

/// Something went wrong setting the proxy up.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("could not listen on {addr}: {source}")]
    Listen {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("could not reach the database at {host}:{port}: {source}")]
    Upstream {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("TLS setup failed: {0}")]
    Tls(String),
}

/// The proxy.
pub struct Proxy {
    config: ProxyConfig,
    context: Arc<SessionContext>,
}

impl Proxy {
    pub fn new(config: ProxyConfig, guard: Arc<Guard>, snapshots: Arc<SnapshotManager>) -> Proxy {
        Proxy {
            config,
            context: Arc::new(SessionContext { guard, snapshots }),
        }
    }

    /// Bind the listening socket. Doing this before serving means a port
    /// clash is reported at startup rather than swallowed by a background
    /// task.
    pub async fn bind(&self) -> Result<TcpListener, ProxyError> {
        TcpListener::bind(self.config.listen)
            .await
            .map_err(|source| ProxyError::Listen {
                addr: self.config.listen,
                source,
            })
    }

    /// Accept connections until the process ends.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (socket, peer) = listener.accept().await?;
            let proxy = self.clone();
            tokio::spawn(async move {
                if let Err(e) = proxy.handle(socket).await {
                    // A client hanging up mid-connection is ordinary, not an
                    // incident.
                    if e.kind() != std::io::ErrorKind::UnexpectedEof
                        && e.kind() != std::io::ErrorKind::ConnectionReset
                    {
                        tracing::warn!(%peer, error = %e, "connection ended with an error");
                    }
                }
            });
        }
    }

    async fn handle(&self, mut client: TcpStream) -> std::io::Result<()> {
        client.set_nodelay(true)?;

        // --- TLS with the client -------------------------------------------
        // The client asks first. If SupaSafe has a certificate it says yes and
        // the rest of the session is encrypted; otherwise it says no, which is
        // what a PostgreSQL server without TLS does, and the client decides
        // whether that is acceptable.
        let startup = read_startup(&mut client).await?;

        match startup {
            Startup::SslRequest | Startup::GssEncRequest => {
                let accept_tls =
                    matches!(startup, Startup::SslRequest) && self.config.server_tls.is_some();
                client
                    .write_all(&[if accept_tls { b'S' } else { b'N' }])
                    .await?;
                client.flush().await?;

                if accept_tls {
                    let acceptor = self
                        .config
                        .server_tls
                        .as_ref()
                        .expect("checked above")
                        .acceptor();
                    let stream = acceptor.accept(client).await.map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
                    return self.after_negotiation(stream).await;
                }
                // The client will now send a real startup packet.
                self.after_negotiation(client).await
            }
            other => self.connect_and_run(client, other).await,
        }
    }

    /// Read the startup packet that follows a TLS or GSSAPI negotiation.
    async fn after_negotiation<C>(&self, mut client: C) -> std::io::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let startup = read_startup(&mut client).await?;
        match startup {
            // A client that asks twice is not one we need to accommodate.
            Startup::SslRequest | Startup::GssEncRequest => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "client repeated its encryption request",
            )),
            other => self.connect_and_run(client, other).await,
        }
    }

    async fn connect_and_run<C>(&self, client: C, startup: Startup) -> std::io::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut server = TcpStream::connect((
            self.config.upstream_host.as_str(),
            self.config.upstream_port,
        ))
        .await?;
        server.set_nodelay(true)?;

        let target = ConnectionTarget {
            host: self.config.upstream_host.clone(),
            port: self.config.upstream_port,
            database: startup.database().unwrap_or_default().to_string(),
            user: startup.user().unwrap_or_default().to_string(),
            application_name: startup.application_name().map(|s| s.to_string()),
        };

        // --- TLS with the database ------------------------------------------
        if let Some(tls) = &self.config.client_tls {
            server.write_all(&Startup::SslRequest.encode()).await?;
            server.flush().await?;
            let mut answer = [0u8; 1];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut answer).await?;
            match answer[0] {
                b'S' => {
                    let stream = tls
                        .connect(&self.config.upstream_host, server)
                        .await
                        .map_err(|e| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                        })?;
                    return self.start_session(client, stream, startup, target).await;
                }
                _ => {
                    // Refusing to continue in the clear is the point of asking.
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "the database refused TLS and SupaSafe is configured to require it",
                    ));
                }
            }
        }

        self.start_session(client, server, startup, target).await
    }

    async fn start_session<C, S>(
        &self,
        client: C,
        mut server: S,
        startup: Startup,
        target: ConnectionTarget,
    ) -> std::io::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Cancel requests carry no SQL: forward and close.
        if let Startup::Cancel { .. } = startup {
            server.write_all(&startup.encode()).await?;
            server.flush().await?;
            return Ok(());
        }

        // Forward the startup packet as it arrived. From here until the
        // session begins, authentication messages pass through untouched.
        server.write_all(&startup.encode()).await?;
        server.flush().await?;

        tracing::info!(
            database = %target.database,
            user = %target.user,
            agent = target.application_name.as_deref().unwrap_or("unknown"),
            "client connected"
        );

        session::run(client, server, &startup, target, self.context.clone()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use supasafe_core::approval::{ApprovalSettings, ApprovalStore};
    use supasafe_core::audit::AuditLog;
    use supasafe_core::config::Config;
    use supasafe_core::snapshot::SnapshotSettings;

    fn guard() -> Arc<Guard> {
        Arc::new(Guard::new(
            Config::default().compile().unwrap(),
            Arc::new(AuditLog::in_memory()),
            ApprovalStore::new(ApprovalSettings::default()),
        ))
    }

    #[tokio::test]
    async fn binding_reports_a_port_clash_at_startup() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = taken.local_addr().unwrap();

        let proxy = Proxy::new(
            ProxyConfig {
                listen: addr,
                upstream_host: "127.0.0.1".into(),
                upstream_port: 5432,
                server_tls: None,
                client_tls: None,
            },
            guard(),
            Arc::new(SnapshotManager::new(SnapshotSettings::default(), None)),
        );
        assert!(proxy.bind().await.is_err());
    }
}
