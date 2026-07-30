//! The approval workflow.
//!
//! When a policy says a statement needs a human, execution stops here. The
//! request goes into a store the dashboard, the CLI and the MCP server all
//! read, and the connection waiting on it blocks until somebody answers or the
//! request times out.
//!
//! Timing out means *refused*. A request that nobody looked at is not a
//! request that was approved.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::blast::BlastRadius;
use crate::environment::Environment;
use crate::risk::RiskScore;
use crate::rollback::RollbackPlan;

/// Where an approval request has got to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ApprovalState {
    /// Waiting for a human.
    Pending,
    /// Approved, and by whom.
    Approved { by: Vec<String> },
    /// Refused, by whom, and why.
    Rejected { by: String, reason: Option<String> },
    /// Approved with different SQL to what the agent asked for.
    Edited { by: String, sql: String },
    /// Nobody answered in time.
    Expired,
}

impl ApprovalState {
    pub fn is_final(&self) -> bool {
        !matches!(self, ApprovalState::Pending)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalState::Pending => "pending",
            ApprovalState::Approved { .. } => "approved",
            ApprovalState::Rejected { .. } => "rejected",
            ApprovalState::Edited { .. } => "edited",
            ApprovalState::Expired => "expired",
        }
    }
}

/// Everything a human needs to decide, in one object.
///
/// The fields are ordered the way the approval card reads: what was asked for,
/// what it will do, how bad it is, and how to get back if it goes wrong.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,

    /// Which agent asked.
    pub agent: String,
    /// The statement, as written.
    pub sql: String,
    /// One sentence describing what it does.
    pub description: String,
    /// Why the agent said it needed this, when the client passed a reason
    /// through.
    pub reason: Option<String>,

    pub database: String,
    pub environment: Environment,
    pub policy: String,

    /// Tables and other objects affected.
    pub affected_objects: Vec<String>,
    pub risk: RiskScore,
    pub blast: BlastRadius,
    /// What the policy said, in words.
    pub policy_reasons: Vec<String>,
    /// How many distinct people have to say yes.
    pub approvals_required: u8,
    /// How to undo it, if it can be undone.
    pub rollback: RollbackPlan,
    /// A snapshot taken before the statement, when one was.
    pub recovery_point: Option<String>,

    pub state: ApprovalState,
    /// Who has approved so far.
    pub approvers: Vec<String>,
}

impl ApprovalRequest {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    pub fn seconds_remaining(&self, now: DateTime<Utc>) -> i64 {
        (self.expires_at - now).num_seconds().max(0)
    }

    /// The SQL that should actually run, which is the edited version when an
    /// approver rewrote it.
    pub fn effective_sql(&self) -> &str {
        match &self.state {
            ApprovalState::Edited { sql, .. } => sql,
            _ => &self.sql,
        }
    }

    /// True when the request has been answered in a way that lets it run.
    pub fn is_granted(&self) -> bool {
        matches!(
            self.state,
            ApprovalState::Approved { .. } | ApprovalState::Edited { .. }
        )
    }
}

/// What went wrong when answering a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "error")]
pub enum ApprovalError {
    #[error("no approval request with id {0}")]
    NotFound(Uuid),
    #[error("this request has already been {0}")]
    AlreadyDecided(String),
    #[error("this request has expired")]
    Expired,
    #[error(
        "{who} requested this statement, and this policy does not let the requester approve \
         their own request"
    )]
    SelfApproval { who: String },
    #[error("{who} has already approved this request; it needs a different person")]
    DuplicateApprover { who: String },
    #[error("this policy does not allow approvers to edit the statement")]
    EditNotAllowed,
}

/// A change to a request, broadcast so the dashboard updates live and the
/// blocked connection wakes up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalEvent {
    pub request: ApprovalRequest,
}

/// Settings that govern the workflow.
#[derive(Debug, Clone)]
pub struct ApprovalSettings {
    pub timeout_seconds: u64,
    pub allow_edit: bool,
    pub require_distinct_approver: bool,
}

impl Default for ApprovalSettings {
    fn default() -> Self {
        Self {
            timeout_seconds: 300,
            allow_edit: true,
            require_distinct_approver: true,
        }
    }
}

/// The shared store of pending and completed requests.
#[derive(Debug, Clone)]
pub struct ApprovalStore {
    inner: Arc<Mutex<Inner>>,
    events: broadcast::Sender<ApprovalEvent>,
    settings: Arc<ApprovalSettings>,
}

#[derive(Debug, Default)]
struct Inner {
    requests: HashMap<Uuid, ApprovalRequest>,
    /// Newest last.
    order: Vec<Uuid>,
}

impl ApprovalStore {
    pub fn new(settings: ApprovalSettings) -> ApprovalStore {
        let (events, _) = broadcast::channel(256);
        ApprovalStore {
            inner: Arc::new(Mutex::new(Inner::default())),
            events,
            settings: Arc::new(settings),
        }
    }

    pub fn settings(&self) -> &ApprovalSettings {
        &self.settings
    }

    /// Subscribe to state changes.
    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalEvent> {
        self.events.subscribe()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// File a new request.
    pub fn submit(&self, mut request: ApprovalRequest) -> ApprovalRequest {
        request.state = ApprovalState::Pending;
        let mut inner = self.lock();
        inner.order.push(request.id);
        inner.requests.insert(request.id, request.clone());
        drop(inner);
        let _ = self.events.send(ApprovalEvent {
            request: request.clone(),
        });
        request
    }

    pub fn get(&self, id: Uuid) -> Option<ApprovalRequest> {
        self.lock().requests.get(&id).cloned()
    }

    /// Every request, newest first.
    pub fn list(&self) -> Vec<ApprovalRequest> {
        let inner = self.lock();
        inner
            .order
            .iter()
            .rev()
            .filter_map(|id| inner.requests.get(id).cloned())
            .collect()
    }

    /// Requests still waiting on a human.
    pub fn pending(&self) -> Vec<ApprovalRequest> {
        self.list()
            .into_iter()
            .filter(|r| r.state == ApprovalState::Pending)
            .collect()
    }

    /// Approve a request. Returns the updated request once it has enough
    /// approvals, or the still-pending request when it needs more.
    pub fn approve(&self, id: Uuid, by: &str) -> Result<ApprovalRequest, ApprovalError> {
        self.update(id, |request, settings| {
            if settings.require_distinct_approver && request.agent.eq_ignore_ascii_case(by) {
                return Err(ApprovalError::SelfApproval {
                    who: by.to_string(),
                });
            }
            if request.approvers.iter().any(|a| a.eq_ignore_ascii_case(by)) {
                return Err(ApprovalError::DuplicateApprover {
                    who: by.to_string(),
                });
            }
            request.approvers.push(by.to_string());
            if request.approvers.len() as u8 >= request.approvals_required.max(1) {
                request.state = ApprovalState::Approved {
                    by: request.approvers.clone(),
                };
            }
            Ok(())
        })
    }

    /// Refuse a request.
    pub fn reject(
        &self,
        id: Uuid,
        by: &str,
        reason: Option<String>,
    ) -> Result<ApprovalRequest, ApprovalError> {
        self.update(id, |request, _| {
            request.state = ApprovalState::Rejected {
                by: by.to_string(),
                reason: reason.clone(),
            };
            Ok(())
        })
    }

    /// Approve, but run different SQL to what was asked for.
    pub fn edit(&self, id: Uuid, by: &str, sql: &str) -> Result<ApprovalRequest, ApprovalError> {
        self.update(id, |request, settings| {
            if !settings.allow_edit {
                return Err(ApprovalError::EditNotAllowed);
            }
            if settings.require_distinct_approver && request.agent.eq_ignore_ascii_case(by) {
                return Err(ApprovalError::SelfApproval {
                    who: by.to_string(),
                });
            }
            request.approvers.push(by.to_string());
            request.state = ApprovalState::Edited {
                by: by.to_string(),
                sql: sql.to_string(),
            };
            Ok(())
        })
    }

    /// Mark everything past its deadline as expired. Returns what changed.
    pub fn expire_due(&self, now: DateTime<Utc>) -> Vec<ApprovalRequest> {
        let due: Vec<Uuid> = {
            let inner = self.lock();
            inner
                .requests
                .values()
                .filter(|r| r.state == ApprovalState::Pending && r.is_expired(now))
                .map(|r| r.id)
                .collect()
        };
        due.into_iter()
            .filter_map(|id| {
                self.update(id, |request, _| {
                    request.state = ApprovalState::Expired;
                    Ok(())
                })
                .ok()
            })
            .collect()
    }

    /// Expire one request. Does nothing if it has already been decided.
    pub fn expire(&self, id: Uuid) -> Result<ApprovalRequest, ApprovalError> {
        self.update(id, |request, _| {
            request.state = ApprovalState::Expired;
            Ok(())
        })
    }

    fn update<F>(&self, id: Uuid, f: F) -> Result<ApprovalRequest, ApprovalError>
    where
        F: FnOnce(&mut ApprovalRequest, &ApprovalSettings) -> Result<(), ApprovalError>,
    {
        let updated = {
            let mut inner = self.lock();
            let request = inner
                .requests
                .get_mut(&id)
                .ok_or(ApprovalError::NotFound(id))?;
            if request.state.is_final() {
                return Err(ApprovalError::AlreadyDecided(
                    request.state.as_str().to_string(),
                ));
            }
            f(request, &self.settings)?;
            request.clone()
        };
        let _ = self.events.send(ApprovalEvent {
            request: updated.clone(),
        });
        Ok(updated)
    }

    /// Wait for a decision, or for the deadline.
    ///
    /// The caller is a connection holding a statement that has not run. When
    /// this returns anything other than a granted state, the statement is
    /// refused.
    pub async fn wait(&self, id: Uuid) -> ApprovalRequest {
        let mut events = self.subscribe();

        // Check first: the decision may already have been made between
        // submitting and waiting.
        if let Some(request) = self.get(id) {
            if request.state.is_final() {
                return request;
            }
            // Milliseconds, not seconds: a deadline under a second still has
            // to be waited out rather than rounded down to zero.
            let remaining = (request.expires_at - Utc::now()).num_milliseconds().max(0) as u64;
            let deadline = tokio::time::Duration::from_millis(remaining);
            let wait = async {
                loop {
                    match events.recv().await {
                        Ok(event) if event.request.id == id && event.request.state.is_final() => {
                            return event.request;
                        }
                        Ok(_) => continue,
                        // Lagging only means the dashboard was busy; fall back
                        // to reading the current state.
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            if let Some(r) = self.get(id) {
                                if r.state.is_final() {
                                    return r;
                                }
                            }
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            return self.get(id).unwrap_or_else(|| request.clone());
                        }
                    }
                }
            };
            match tokio::time::timeout(deadline, wait).await {
                Ok(decided) => decided,
                Err(_) => {
                    // Nobody answered. Silence is a refusal, and it is
                    // recorded as one here rather than left to a clock
                    // comparison that may be a millisecond the wrong side of
                    // the deadline.
                    let _ = self.expire(id);
                    self.get(id).unwrap_or(request)
                }
            }
        } else {
            // A request that vanished cannot be granted.
            ApprovalRequest {
                id,
                created_at: Utc::now(),
                expires_at: Utc::now(),
                agent: String::new(),
                sql: String::new(),
                description: String::new(),
                reason: None,
                database: String::new(),
                environment: Environment::Production,
                policy: String::new(),
                affected_objects: Vec::new(),
                risk: RiskScore {
                    score: 100,
                    level: crate::risk::RiskLevel::Catastrophic,
                    base: 100,
                    factors: Vec::new(),
                },
                blast: crate::blast::analyze(&supasafe_parser::analyze_statement("SELECT 1"), None),
                policy_reasons: Vec::new(),
                approvals_required: 1,
                rollback: RollbackPlan::none(),
                recovery_point: None,
                state: ApprovalState::Expired,
                approvers: Vec::new(),
            }
        }
    }
}

/// Build the deadline for a new request.
pub fn deadline(timeout_seconds: u64) -> DateTime<Utc> {
    Utc::now() + Duration::seconds(timeout_seconds as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::RiskLevel;

    fn request(agent: &str, approvals: u8) -> ApprovalRequest {
        ApprovalRequest {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            expires_at: deadline(300),
            agent: agent.into(),
            sql: "DROP TABLE users".into(),
            description: "permanently remove the table users".into(),
            reason: None,
            database: "postgres".into(),
            environment: Environment::Production,
            policy: "production".into(),
            affected_objects: vec!["public.users".into()],
            risk: RiskScore {
                score: 100,
                level: RiskLevel::Catastrophic,
                base: 100,
                factors: vec![],
            },
            blast: crate::blast::analyze(
                &supasafe_parser::analyze_statement("DROP TABLE users"),
                None,
            ),
            policy_reasons: vec![],
            approvals_required: approvals,
            rollback: RollbackPlan::none(),
            recovery_point: None,
            state: ApprovalState::Pending,
            approvers: vec![],
        }
    }

    fn store() -> ApprovalStore {
        ApprovalStore::new(ApprovalSettings::default())
    }

    #[test]
    fn a_single_approval_grants() {
        let s = store();
        let r = s.submit(request("claude-code", 1));
        let out = s.approve(r.id, "alice").unwrap();
        assert!(out.is_granted());
    }

    #[test]
    fn two_person_approval_needs_two_people() {
        let s = store();
        let r = s.submit(request("claude-code", 2));
        let out = s.approve(r.id, "alice").unwrap();
        assert_eq!(out.state, ApprovalState::Pending);
        let out = s.approve(r.id, "bob").unwrap();
        assert!(out.is_granted());
    }

    #[test]
    fn the_same_person_cannot_approve_twice() {
        let s = store();
        let r = s.submit(request("claude-code", 2));
        s.approve(r.id, "alice").unwrap();
        assert!(matches!(
            s.approve(r.id, "alice"),
            Err(ApprovalError::DuplicateApprover { .. })
        ));
    }

    #[test]
    fn the_requester_cannot_approve_their_own_request() {
        let s = store();
        let r = s.submit(request("claude-code", 1));
        assert!(matches!(
            s.approve(r.id, "claude-code"),
            Err(ApprovalError::SelfApproval { .. })
        ));
    }

    #[test]
    fn rejection_is_final() {
        let s = store();
        let r = s.submit(request("claude-code", 1));
        let out = s.reject(r.id, "alice", Some("wrong table".into())).unwrap();
        assert!(!out.is_granted());
        assert!(matches!(
            s.approve(r.id, "bob"),
            Err(ApprovalError::AlreadyDecided(_))
        ));
    }

    #[test]
    fn editing_replaces_the_statement() {
        let s = store();
        let r = s.submit(request("claude-code", 1));
        let out = s
            .edit(r.id, "alice", "DELETE FROM users WHERE id = 42")
            .unwrap();
        assert!(out.is_granted());
        assert_eq!(out.effective_sql(), "DELETE FROM users WHERE id = 42");
    }

    #[test]
    fn editing_can_be_turned_off() {
        let s = ApprovalStore::new(ApprovalSettings {
            allow_edit: false,
            ..Default::default()
        });
        let r = s.submit(request("claude-code", 1));
        assert!(matches!(
            s.edit(r.id, "alice", "SELECT 1"),
            Err(ApprovalError::EditNotAllowed)
        ));
    }

    #[test]
    fn expiry_is_a_refusal() {
        let s = store();
        let mut req = request("claude-code", 1);
        req.expires_at = Utc::now() - Duration::seconds(1);
        let r = s.submit(req);
        let expired = s.expire_due(Utc::now());
        assert_eq!(expired.len(), 1);
        let after = s.get(r.id).unwrap();
        assert_eq!(after.state, ApprovalState::Expired);
        assert!(!after.is_granted());
    }

    #[tokio::test]
    async fn waiting_returns_as_soon_as_someone_answers() {
        let s = store();
        let r = s.submit(request("claude-code", 1));
        let store2 = s.clone();
        let id = r.id;
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
            store2.approve(id, "alice").unwrap();
        });
        let decided = s.wait(id).await;
        assert!(decided.is_granted());
    }

    #[tokio::test]
    async fn waiting_past_the_deadline_refuses() {
        let s = store();
        let mut req = request("claude-code", 1);
        req.expires_at = Utc::now() + Duration::milliseconds(50);
        let r = s.submit(req);
        let decided = s.wait(r.id).await;
        assert!(!decided.is_granted());
        assert_eq!(decided.state, ApprovalState::Expired);
    }

    #[test]
    fn pending_lists_only_open_requests() {
        let s = store();
        let a = s.submit(request("claude-code", 1));
        let _b = s.submit(request("claude-code", 1));
        s.approve(a.id, "alice").unwrap();
        assert_eq!(s.pending().len(), 1);
        assert_eq!(s.list().len(), 2);
    }
}
