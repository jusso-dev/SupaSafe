//! # supasafe-mcp
//!
//! A Model Context Protocol server that lets an agent ask SupaSafe about a
//! statement *before* it sends it to the database.
//!
//! The proxy is the backstop and it does not rely on the model cooperating.
//! This is the cooperative path: an agent that checks first gets a full
//! explanation of what a statement would do, in structured form, and can fix
//! its own SQL without a human ever seeing a blocked query.
//!
//! Speaks JSON-RPC 2.0 over stdio, which is what every MCP client expects.

#![forbid(unsafe_code)]

pub mod tools;

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use supasafe_core::environment::ConnectionTarget;
use supasafe_core::guard::Guard;
use supasafe_core::snapshot::SnapshotManager;

/// The protocol revision this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Everything the tools need.
pub struct McpServer {
    pub guard: Arc<Guard>,
    pub snapshots: Arc<SnapshotManager>,
    /// The database the agent is working against.
    pub target: ConnectionTarget,
    /// Which agent is connected, for the audit trail.
    pub agent: String,
}

impl McpServer {
    pub fn new(
        guard: Arc<Guard>,
        snapshots: Arc<SnapshotManager>,
        target: ConnectionTarget,
    ) -> McpServer {
        McpServer {
            guard,
            snapshots,
            target,
            agent: "mcp-client".to_string(),
        }
    }

    /// Read requests from stdin and write responses to stdout until the client
    /// closes the stream.
    pub async fn serve_stdio(self: Arc<Self>) -> std::io::Result<()> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut lines = BufReader::new(stdin).lines();

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(request) => self.handle(request).await,
                Err(e) => Some(error_response(
                    Value::Null,
                    -32700,
                    &format!("parse error: {e}"),
                )),
            };
            if let Some(response) = response {
                write_line(&mut stdout, &response).await?;
            }
        }
        Ok(())
    }

    /// Handle one JSON-RPC message. Returns `None` for notifications, which
    /// take no reply.
    pub async fn handle(&self, request: Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));

        // A message with no id is a notification, and notifications take no
        // reply.
        let id = id?;

        let result = match method {
            "initialize" => Ok(self.initialize()),
            "tools/list" => Ok(tools::list()),
            "tools/call" => self.call_tool(&params).await,
            "ping" => Ok(json!({})),
            "prompts/list" => Ok(json!({ "prompts": [] })),
            "resources/list" => Ok(json!({ "resources": [] })),
            other => Err(McpError::MethodNotFound(other.to_string())),
        };

        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => error_response(id, e.code(), &e.to_string()),
        })
    }

    fn initialize(&self) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": {
                "name": "supasafe",
                "version": supasafe_core::VERSION,
            },
            "instructions": self.guard.agent_context(&self.target),
        })
    }

    async fn call_tool(&self, params: &Value) -> Result<Value, McpError> {
        let name = params
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| McpError::InvalidParams("a tool name is required".into()))?;
        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        let outcome = tools::dispatch(self, name, &arguments).await?;

        // MCP wants human-readable content; agents parse the structured
        // payload. Sending both means a client that only renders text still
        // shows something useful.
        Ok(json!({
            "content": [{ "type": "text", "text": outcome.text }],
            "structuredContent": outcome.data,
            "isError": outcome.is_error,
        }))
    }
}

/// What a tool call produced.
#[derive(Debug)]
pub struct ToolOutcome {
    pub text: String,
    pub data: Value,
    pub is_error: bool,
}

impl ToolOutcome {
    pub fn ok(text: impl Into<String>, data: Value) -> ToolOutcome {
        ToolOutcome {
            text: text.into(),
            data,
            is_error: false,
        }
    }

    pub fn failed(text: impl Into<String>) -> ToolOutcome {
        ToolOutcome {
            text: text.into(),
            data: json!({}),
            is_error: true,
        }
    }
}

/// JSON-RPC level errors.
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("unknown method {0:?}")]
    MethodNotFound(String),
    #[error("unknown tool {0:?}")]
    ToolNotFound(String),
    #[error("{0}")]
    InvalidParams(String),
}

impl McpError {
    fn code(&self) -> i64 {
        match self {
            McpError::MethodNotFound(_) => -32601,
            McpError::ToolNotFound(_) => -32602,
            McpError::InvalidParams(_) => -32602,
        }
    }
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use supasafe_core::approval::{ApprovalSettings, ApprovalStore};
    use supasafe_core::audit::AuditLog;
    use supasafe_core::config::Config;
    use supasafe_core::snapshot::SnapshotSettings;

    pub(crate) fn server() -> Arc<McpServer> {
        let guard = Arc::new(Guard::new(
            Config::default().compile().unwrap(),
            Arc::new(AuditLog::in_memory()),
            ApprovalStore::new(ApprovalSettings {
                timeout_seconds: 1,
                ..Default::default()
            }),
        ));
        Arc::new(McpServer::new(
            guard,
            Arc::new(SnapshotManager::new(SnapshotSettings::default(), None)),
            ConnectionTarget::new("db.abcdefghijklmnopqrst.supabase.co", 5432, "postgres"),
        ))
    }

    fn request(id: i64, method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    #[tokio::test]
    async fn initialize_advertises_the_server() {
        let s = server();
        let response = s.handle(request(1, "initialize", json!({}))).await.unwrap();
        let result = &response["result"];
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], "supasafe");
        // The agent is told what it is connected to before it does anything.
        assert!(result["instructions"]
            .as_str()
            .unwrap()
            .contains("PRODUCTION"));
    }

    #[tokio::test]
    async fn notifications_get_no_reply() {
        let s = server();
        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(s.handle(notification).await.is_none());
    }

    #[tokio::test]
    async fn unknown_methods_return_a_jsonrpc_error() {
        let s = server();
        let response = s.handle(request(1, "nope", json!({}))).await.unwrap();
        assert_eq!(response["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn every_advertised_tool_can_be_called() {
        let s = server();
        let listed = tools::list();
        let names: Vec<&str> = listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();

        assert!(names.contains(&"analyze_sql"));
        assert!(names.contains(&"preview_sql"));
        assert!(names.contains(&"estimate_risk"));
        assert!(names.contains(&"request_approval"));
        assert!(names.contains(&"list_policies"));
        assert!(names.contains(&"create_snapshot"));
        assert!(names.contains(&"rollback"));

        for name in names {
            let response = s
                .handle(request(
                    1,
                    "tools/call",
                    json!({ "name": name, "arguments": { "sql": "SELECT 1" } }),
                ))
                .await
                .unwrap();
            assert!(
                response.get("result").is_some(),
                "tool {name} returned an error: {response}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_tools_are_rejected() {
        let s = server();
        let response = s
            .handle(request(1, "tools/call", json!({ "name": "rm_rf" })))
            .await
            .unwrap();
        assert!(response.get("error").is_some());
    }
}
