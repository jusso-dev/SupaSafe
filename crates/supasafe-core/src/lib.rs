//! # supasafe-core
//!
//! The decision engine behind SupaSafe.
//!
//! One statement arrives. Six questions get answered, in this order:
//!
//! 1. **What is it?** ([`supasafe_parser`], via the AST. Never text matching.)
//! 2. **Where is it going?** ([`environment`]: production, staging, local, and
//!    production is the answer when nothing else fits.)
//! 3. **How bad is it?** ([`risk`]: a score from 0 to 100 with every factor
//!    that produced it.)
//! 4. **What does it actually touch?** ([`blast`]: rows, cascades, locks, WAL,
//!    the tables it never mentions.)
//! 5. **Is it allowed?** ([`policy`]: an allow-list, evaluated in order.)
//! 6. **How do we get back?** ([`rollback`] and [`snapshot`].)
//!
//! Then it is written down ([`audit`]), and if a human is needed, one is asked
//! ([`approval`]).
//!
//! [`guard::Guard`] runs all of that in one place, so the proxy, the CLI and
//! the MCP server cannot drift apart.
//!
//! ## Example
//!
//! ```
//! use std::sync::Arc;
//! use supasafe_core::approval::{ApprovalSettings, ApprovalStore};
//! use supasafe_core::audit::AuditLog;
//! use supasafe_core::config::Config;
//! use supasafe_core::environment::ConnectionTarget;
//! use supasafe_core::guard::{Guard, Request};
//!
//! let guard = Guard::new(
//!     Config::default().compile().unwrap(),
//!     Arc::new(AuditLog::in_memory()),
//!     ApprovalStore::new(ApprovalSettings::default()),
//! );
//!
//! let production =
//!     ConnectionTarget::new("db.abcdefghijklmnopqrst.supabase.co", 5432, "postgres");
//! let verdict = guard.evaluate(&Request::new("DROP TABLE users"), &production);
//!
//! assert!(verdict.blocks_execution());
//! assert_eq!(verdict.risk, 100);
//! ```

#![forbid(unsafe_code)]

pub mod approval;
pub mod audit;
pub mod blast;
pub mod catalog;
pub mod config;
pub mod context;
pub mod environment;
pub mod guard;
pub mod policy;
pub mod risk;
pub mod rollback;
pub mod snapshot;

pub use approval::{ApprovalRequest, ApprovalState, ApprovalStore};
pub use audit::{AuditLog, AuditRecord, Outcome};
pub use blast::BlastRadius;
pub use catalog::CatalogSnapshot;
pub use config::{CompiledConfig, Config};
pub use environment::{ConnectionTarget, Environment, EnvironmentInfo};
pub use guard::{Guard, Request, StatementVerdict, Verdict};
pub use policy::{Decision, Policy};
pub use risk::{RiskLevel, RiskScore};
pub use rollback::{Reversibility, RollbackPlan};
pub use snapshot::{Snapshot, SnapshotManager};

/// The version of SupaSafe this build came from.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
