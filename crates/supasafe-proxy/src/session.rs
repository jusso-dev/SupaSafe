//! One client connection.
//!
//! The proxy is transparent in both directions except at one point: a frontend
//! message that carries SQL is analysed before it is forwarded, and may never
//! be forwarded at all.
//!
//! Two things make this safe rather than merely clever:
//!
//! * **Authentication is passed through untouched.** SupaSafe relays the
//!   authentication exchange between client and server without interpreting
//!   it, so it never holds a password, a SCRAM proof or a token. There is no
//!   credential in this process to leak.
//! * **A refusal is expressed in the protocol.** The client gets an
//!   `ErrorResponse` with SQLSTATE 42501 and a `ReadyForQuery`, exactly as if
//!   the database itself had refused. Nothing hangs, nothing desynchronises,
//!   and every existing client handles it correctly.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;

use supasafe_core::approval::ApprovalState;
use supasafe_core::audit::Outcome;
use supasafe_core::environment::ConnectionTarget;
use supasafe_core::guard::{Guard, Request, Verdict};
use supasafe_core::policy::Decision;
use supasafe_core::snapshot::{tables_to_capture, SnapshotManager};

use crate::protocol::{self, Frame, Startup, TransactionStatus};

/// Everything a session needs that outlives it.
pub struct SessionContext {
    pub guard: Arc<Guard>,
    pub snapshots: Arc<SnapshotManager>,
}

/// A statement that has been forwarded and is waiting for the database to say
/// what happened, so the audit record can be completed.
struct PendingAudit {
    verdict: Verdict,
    request: Request,
    started: Instant,
    recovery_point: Option<String>,
}

/// State shared between the two directions of one connection.
struct Shared {
    /// Last transaction status the server reported.
    status: AtomicU8,
    pending: Mutex<VecDeque<PendingAudit>>,
    context: Arc<SessionContext>,
}

impl Shared {
    fn status(&self) -> TransactionStatus {
        TransactionStatus::from_byte(self.status.load(Ordering::Relaxed))
    }

    fn set_status(&self, status: TransactionStatus) {
        self.status.store(status.as_byte(), Ordering::Relaxed);
    }
}

/// Run a session to completion.
///
/// `client` and `server` are already past TLS negotiation and past the startup
/// packet; `startup` is what the client asked for and has already been
/// forwarded to the server.
pub async fn run<C, S>(
    client: C,
    server: S,
    startup: &Startup,
    target: ConnectionTarget,
    context: Arc<SessionContext>,
) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let agent = startup
        .application_name()
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string();

    let (client_read, client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);

    let shared = Arc::new(Shared {
        status: AtomicU8::new(TransactionStatus::Idle.as_byte()),
        pending: Mutex::new(VecDeque::new()),
        context,
    });

    // Everything written to the client goes through this channel, so the two
    // directions never interleave halfway through a message.
    let (to_client, client_rx) = mpsc::channel::<Frame>(64);

    let writer = tokio::spawn(client_writer(client_write, client_rx));
    let backend = tokio::spawn(backend_to_client(
        server_read,
        to_client.clone(),
        shared.clone(),
    ));
    let frontend = frontend_to_backend(
        client_read,
        server_write,
        to_client,
        shared.clone(),
        agent,
        target,
    )
    .await;

    backend.abort();
    let _ = writer.await;
    frontend
}

/// Owns the client's write half. Serialising through one task is what keeps a
/// synthesised error from being spliced into the middle of a result set.
async fn client_writer<C>(mut write: WriteHalf<C>, mut rx: mpsc::Receiver<Frame>)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(frame) = rx.recv().await {
        if write.write_all(&frame.encode()).await.is_err() {
            break;
        }
        if write.flush().await.is_err() {
            break;
        }
    }
}

/// Server to client. Forwarded verbatim; watched for transaction status and
/// for the results that complete an audit record.
async fn backend_to_client<S>(
    mut read: ReadHalf<S>,
    to_client: mpsc::Sender<Frame>,
    shared: Arc<Shared>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut last_error: Option<String> = None;
    let mut rows: Option<u64> = None;

    loop {
        let frame = match protocol::read_frame(&mut read).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };

        match frame.tag {
            protocol::BE_ERROR => {
                last_error = protocol::error_message(&frame);
            }
            protocol::BE_COMMAND_COMPLETE => {
                if let Some(n) = protocol::rows_from_command_tag(&frame) {
                    rows = Some(n);
                }
            }
            protocol::BE_READY_FOR_QUERY => {
                if let Some(status) = frame.ready_status() {
                    shared.set_status(status);
                }
                // A ReadyForQuery closes out everything that was in flight.
                // For the simple query protocol that is exactly one statement;
                // for a pipelined extended-protocol batch it is everything
                // since the last Sync, which all shared a fate anyway.
                let pending: Vec<PendingAudit> = {
                    let mut queue = shared.pending.lock().unwrap_or_else(|p| p.into_inner());
                    queue.drain(..).collect()
                };
                for entry in pending {
                    let outcome = match &last_error {
                        Some(error) => Outcome::Failed {
                            error: error.clone(),
                        },
                        None => Outcome::Executed,
                    };
                    shared.context.guard.record(
                        &entry.verdict,
                        &entry.request,
                        outcome,
                        rows,
                        Some(entry.started.elapsed().as_millis() as u64),
                        entry.recovery_point.clone(),
                    );
                }
                last_error = None;
                rows = None;
            }
            _ => {}
        }

        if to_client.send(frame).await.is_err() {
            break;
        }
    }
}

/// Client to server. This is where statements are judged.
async fn frontend_to_backend<C, S>(
    mut read: ReadHalf<C>,
    mut server: WriteHalf<S>,
    to_client: mpsc::Sender<Frame>,
    shared: Arc<Shared>,
    agent: String,
    target: ConnectionTarget,
) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Set when SupaSafe refused a statement inside an open transaction. From
    // then on the client is told the transaction is aborted, exactly as
    // PostgreSQL would, until it ends the block. Without this the client would
    // believe its transaction failed while the server happily carried on
    // executing inside it.
    let mut aborted_by_us = false;
    // Set when a refusal happened mid extended-protocol batch: everything up
    // to the next Sync is discarded, which is what the server itself does
    // after an error.
    let mut sink_until_sync = false;

    loop {
        let frame = match protocol::read_frame(&mut read).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(e) => return Err(e),
        };

        match frame.tag {
            protocol::FE_TERMINATE => {
                let _ = server.write_all(&frame.encode()).await;
                let _ = server.flush().await;
                break;
            }

            protocol::FE_SYNC if sink_until_sync => {
                sink_until_sync = false;
                let _ = to_client
                    .send(protocol::ready_for_query(client_status(
                        &shared,
                        aborted_by_us,
                    )))
                    .await;
            }

            _ if sink_until_sync => {
                // Discard. The statement that would have used these was never
                // sent.
            }

            protocol::FE_QUERY | protocol::FE_PARSE => {
                let sql = match frame.tag {
                    protocol::FE_QUERY => frame.query_sql().unwrap_or_default(),
                    _ => frame.parse_sql().map(|(_, sql)| sql).unwrap_or_default(),
                };
                let extended = frame.tag == protocol::FE_PARSE;

                // While the client believes its transaction is aborted, only
                // ending the block is allowed.
                if aborted_by_us {
                    if ends_transaction(&sql) {
                        aborted_by_us = false;
                        // COMMIT in an aborted transaction rolls back, so send
                        // the server the statement that means what the client
                        // is about to be told happened.
                        let rewritten = frame.with_sql("ROLLBACK").unwrap_or_else(|| frame.clone());
                        forward(&mut server, &rewritten).await?;
                        continue;
                    }
                    reject_aborted(&to_client, extended, &mut sink_until_sync).await;
                    continue;
                }

                let request = Request {
                    sql: sql.clone(),
                    agent: agent.clone(),
                    prompt: None,
                    reason: None,
                    in_transaction: shared.status().in_transaction(),
                };

                let verdict = shared.context.guard.evaluate(&request, &target);

                match verdict.decision.clone() {
                    Decision::Allow => {
                        queue_audit(&shared, &verdict, &request, None);
                        forward(&mut server, &frame).await?;
                    }

                    Decision::Warn => {
                        if let Some(statement) = verdict.dominant() {
                            let _ = to_client
                                .send(protocol::notice_response(
                                    &format!(
                                        "SupaSafe: this statement would {} (risk {})",
                                        statement.statement.describe(),
                                        statement.risk.score
                                    ),
                                    statement.reasons.first().map(|s| s.as_str()),
                                ))
                                .await;
                        }
                        queue_audit(&shared, &verdict, &request, None);
                        forward(&mut server, &frame).await?;
                    }

                    Decision::Deny => {
                        shared.context.guard.record(
                            &verdict,
                            &request,
                            Outcome::Blocked,
                            None,
                            None,
                            None,
                        );
                        refuse(
                            &to_client,
                            &verdict,
                            &shared,
                            extended,
                            &mut sink_until_sync,
                            &mut aborted_by_us,
                        )
                        .await;
                    }

                    Decision::RequireApproval { .. } => {
                        let recovery_point = maybe_snapshot(&shared, &verdict).await;
                        let approval = shared.context.guard.request_approval(
                            &verdict,
                            &request,
                            recovery_point.clone(),
                        );

                        tracing::info!(
                            id = %approval.id,
                            agent = %agent,
                            risk = verdict.risk,
                            "holding a statement for approval"
                        );

                        let decided = shared.context.guard.approvals().wait(approval.id).await;

                        match &decided.state {
                            ApprovalState::Approved { by } => {
                                shared.context.guard.record(
                                    &verdict,
                                    &request,
                                    Outcome::Approved { by: by.clone() },
                                    None,
                                    None,
                                    recovery_point.clone(),
                                );
                                queue_audit(&shared, &verdict, &request, recovery_point);
                                forward(&mut server, &frame).await?;
                            }
                            ApprovalState::Edited { by, sql: edited } => {
                                // The approver rewrote the statement. It is
                                // re-analysed rather than trusted: an edit is
                                // a new statement, and a human under time
                                // pressure is not a policy engine.
                                let edited_request = Request {
                                    sql: edited.clone(),
                                    ..request.clone()
                                };
                                let re_verdict =
                                    shared.context.guard.evaluate(&edited_request, &target);
                                if re_verdict.decision == Decision::Deny {
                                    shared.context.guard.record(
                                        &re_verdict,
                                        &edited_request,
                                        Outcome::Blocked,
                                        None,
                                        None,
                                        None,
                                    );
                                    refuse(
                                        &to_client,
                                        &re_verdict,
                                        &shared,
                                        extended,
                                        &mut sink_until_sync,
                                        &mut aborted_by_us,
                                    )
                                    .await;
                                } else {
                                    shared.context.guard.record(
                                        &re_verdict,
                                        &edited_request,
                                        Outcome::Approved {
                                            by: vec![by.clone()],
                                        },
                                        None,
                                        None,
                                        recovery_point.clone(),
                                    );
                                    queue_audit(
                                        &shared,
                                        &re_verdict,
                                        &edited_request,
                                        recovery_point,
                                    );
                                    let rewritten =
                                        frame.with_sql(edited).unwrap_or_else(|| frame.clone());
                                    forward(&mut server, &rewritten).await?;
                                }
                            }
                            ApprovalState::Rejected { by, reason } => {
                                shared.context.guard.record(
                                    &verdict,
                                    &request,
                                    Outcome::Rejected { by: by.clone() },
                                    None,
                                    None,
                                    recovery_point,
                                );
                                refuse_with(
                                    &to_client,
                                    &format!(
                                        "SupaSafe: {by} rejected this statement{}",
                                        reason
                                            .as_ref()
                                            .map(|r| format!(": {r}"))
                                            .unwrap_or_default()
                                    ),
                                    None,
                                    &shared,
                                    extended,
                                    &mut sink_until_sync,
                                    &mut aborted_by_us,
                                )
                                .await;
                            }
                            _ => {
                                shared.context.guard.record(
                                    &verdict,
                                    &request,
                                    Outcome::Expired,
                                    None,
                                    None,
                                    recovery_point,
                                );
                                refuse_with(
                                    &to_client,
                                    "SupaSafe: this statement needed approval and nobody \
                                     approved it in time",
                                    Some(
                                        "Silence is a refusal. Ask a human to approve it in the \
                                         SupaSafe dashboard, then run it again.",
                                    ),
                                    &shared,
                                    extended,
                                    &mut sink_until_sync,
                                    &mut aborted_by_us,
                                )
                                .await;
                            }
                        }
                    }
                }
            }

            protocol::FE_FUNCTION_CALL => {
                // The fast-path protocol calls a function by OID with binary
                // arguments. There is no SQL to parse, so there is nothing to
                // judge, and a function can do anything its owner can. Modern
                // clients only use it for large objects.
                let _ = to_client
                    .send(protocol::error_response(
                        "SupaSafe: fast-path function calls are not allowed",
                        Some(
                            "The fast-path protocol invokes a function by OID, which carries no \
                             SQL for SupaSafe to analyse.",
                        ),
                        Some("Call the function with SELECT or CALL instead."),
                    ))
                    .await;
                let _ = to_client
                    .send(protocol::ready_for_query(client_status(
                        &shared,
                        aborted_by_us,
                    )))
                    .await;
            }

            // Bind, Execute, Describe, Close, Flush, Sync, CopyData and the
            // rest carry no SQL and are forwarded as they are.
            _ => {
                forward(&mut server, &frame).await?;
            }
        }
    }

    Ok(())
}

async fn forward<S>(server: &mut WriteHalf<S>, frame: &Frame) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    server.write_all(&frame.encode()).await?;
    server.flush().await
}

fn queue_audit(
    shared: &Arc<Shared>,
    verdict: &Verdict,
    request: &Request,
    recovery_point: Option<String>,
) {
    let mut queue = shared.pending.lock().unwrap_or_else(|p| p.into_inner());
    queue.push_back(PendingAudit {
        verdict: verdict.clone(),
        request: request.clone(),
        started: Instant::now(),
        recovery_point,
    });
}

/// The status to report to the client, which differs from the server's view
/// while SupaSafe is holding a transaction open that the client believes has
/// failed.
fn client_status(shared: &Arc<Shared>, aborted_by_us: bool) -> TransactionStatus {
    if aborted_by_us {
        TransactionStatus::Failed
    } else {
        shared.status()
    }
}

async fn refuse(
    to_client: &mpsc::Sender<Frame>,
    verdict: &Verdict,
    shared: &Arc<Shared>,
    extended: bool,
    sink_until_sync: &mut bool,
    aborted_by_us: &mut bool,
) {
    let statement = verdict.dominant();
    let message = match statement {
        Some(s) => format!(
            "SupaSafe blocked this statement: it would {}",
            s.statement.describe()
        ),
        None => "SupaSafe blocked this statement".to_string(),
    };
    let detail = statement.map(|s| s.reasons.join(" "));
    refuse_with(
        to_client,
        &message,
        detail.as_deref(),
        shared,
        extended,
        sink_until_sync,
        aborted_by_us,
    )
    .await;
}

async fn refuse_with(
    to_client: &mpsc::Sender<Frame>,
    message: &str,
    detail: Option<&str>,
    shared: &Arc<Shared>,
    extended: bool,
    sink_until_sync: &mut bool,
    aborted_by_us: &mut bool,
) {
    if shared.status().in_transaction() {
        *aborted_by_us = true;
    }

    let _ = to_client
        .send(protocol::error_response(
            message,
            detail,
            Some(
                "Do not retry this in another form. Approve it in the SupaSafe dashboard, or \
                 write it as a reviewed migration.",
            ),
        ))
        .await;

    if extended {
        // In the extended protocol the client will keep sending Bind, Execute
        // and Describe for a statement that was never parsed. Discard them
        // until Sync, then answer the Sync, which is what the server does
        // after an error.
        *sink_until_sync = true;
    } else {
        let _ = to_client
            .send(protocol::ready_for_query(client_status(
                shared,
                *aborted_by_us,
            )))
            .await;
    }
}

async fn reject_aborted(
    to_client: &mpsc::Sender<Frame>,
    extended: bool,
    sink_until_sync: &mut bool,
) {
    let _ = to_client
        .send(protocol::error_with_code(
            "25P02",
            "ERROR",
            "current transaction is aborted, commands ignored until end of transaction block",
            Some("SupaSafe refused an earlier statement in this transaction."),
            Some("Send ROLLBACK to end the transaction."),
        ))
        .await;
    if extended {
        *sink_until_sync = true;
    } else {
        let _ = to_client
            .send(protocol::ready_for_query(TransactionStatus::Failed))
            .await;
    }
}

/// True when the statement ends a transaction block, judged from the parsed
/// statement rather than the text.
fn ends_transaction(sql: &str) -> bool {
    use supasafe_parser::StatementKind;
    supasafe_parser::analyze(sql)
        .statements
        .iter()
        .any(|s| matches!(s.kind, StatementKind::Commit | StatementKind::Rollback))
}

/// Take a recovery point if the policy asked for one.
async fn maybe_snapshot(shared: &Arc<Shared>, verdict: &Verdict) -> Option<String> {
    let statement = verdict.statements.iter().find(|s| s.wants_snapshot)?;
    let tables = tables_to_capture(&statement.statement);
    let database = verdict.environment.target.database.clone();

    match shared
        .context
        .snapshots
        .capture(&database, &statement.statement.sql, &tables)
        .await
    {
        Ok(snapshot) => {
            tracing::info!(label = %snapshot.label, "recovery point taken");
            Some(snapshot.label)
        }
        Err(e) => {
            // A failed snapshot is reported, not hidden. The approver sees
            // that there is nothing to restore from and can decide
            // accordingly.
            tracing::warn!(error = %e, "could not take a recovery point");
            Some(
                SnapshotManager::unavailable(&database, &statement.statement.sql, e.to_string())
                    .describe(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_enders_are_detected_semantically() {
        assert!(ends_transaction("COMMIT"));
        assert!(ends_transaction("ROLLBACK"));
        assert!(ends_transaction("commit;"));
        assert!(!ends_transaction("SELECT 1"));
        // A string that merely mentions COMMIT is not a COMMIT.
        assert!(!ends_transaction("INSERT INTO log VALUES ('COMMIT')"));
    }
}
