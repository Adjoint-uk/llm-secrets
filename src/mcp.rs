//! Minimal MCP (Model Context Protocol) server (#10).
//!
//! See `docs/adr/0005-mcp-server.md`. We hand-roll a tiny JSON-RPC 2.0 loop
//! over stdio rather than pulling in an SDK. The exposed tools are
//! deliberately a *subset* of the CLI: nothing that returns plaintext, ever.

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::Result;
use crate::{lease, store};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "llm-secrets";

#[derive(Debug, Deserialize)]
struct Request {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

/// Run the server on stdin/stdout. Each input line is one JSON-RPC message.
/// Notifications (no `id`) get no response. Returns when stdin closes.
pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => l,
            Err(_) => break,
        };

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(RpcError {
                        code: -32700,
                        message: format!("parse error: {e}"),
                    }),
                };
                writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap())?;
                stdout.flush()?;
                continue;
            }
        };

        let id = req.id.clone();
        let result = handle(&req);
        // Notifications (no id) get no reply.
        if id.is_none() {
            continue;
        }
        let resp = match result {
            Ok(value) => Response {
                jsonrpc: "2.0",
                id: id.unwrap_or(Value::Null),
                result: Some(value),
                error: None,
            },
            Err(e) => Response {
                jsonrpc: "2.0",
                id: id.unwrap_or(Value::Null),
                result: None,
                error: Some(RpcError {
                    code: -32000,
                    message: e.to_string(),
                }),
            },
        };
        writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap())?;
        stdout.flush()?;
    }
    Ok(())
}

fn handle(req: &Request) -> std::result::Result<Value, String> {
    match req.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": {
                "name": SERVER_NAME,
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": {
                "tools": {}
            }
        })),

        "tools/list" => Ok(json!({ "tools": tool_list() })),

        "tools/call" => {
            let name = req
                .params
                .get("name")
                .and_then(Value::as_str)
                .ok_or("missing tool name")?;
            let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
            call_tool(name, &args).map_err(|e| e.to_string())
        }

        // Be polite about MCP lifecycle messages we don't act on.
        "notifications/initialized" | "ping" => Ok(json!({})),

        other => Err(format!("method not found: {other}")),
    }
}

fn tool_list() -> Value {
    json!([
        {
            "name": "list_secrets",
            "description": "List secret key names. Never returns values.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "peek_secret",
            "description": "Return a masked preview of a secret. Never returns plaintext.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "chars": { "type": "integer", "default": 4 }
                },
                "required": ["key"]
            }
        },
        {
            "name": "audit_recent",
            "description": "Return the last N audit log entries (oldest first).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "last": { "type": "integer", "default": 20 }
                }
            }
        },
        {
            "name": "status",
            "description": "Return store health (path, presence, secret count).",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ])
}

fn text_result(s: impl Into<String>) -> Value {
    json!({
        "content": [{ "type": "text", "text": s.into() }]
    })
}

fn call_tool(name: &str, args: &Value) -> Result<Value> {
    match name {
        "list_secrets" => {
            let identity = store::load_identity()?;
            let st = store::load_store(&identity)?;
            let keys: Vec<&str> = st.keys().collect();
            Ok(json!({
                "content": [{ "type": "text", "text": keys.join("\n") }],
                "isError": false
            }))
        }

        "peek_secret" => {
            let key = args
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| crate::error::Error::Other("missing 'key'".into()))?;
            let chars = args.get("chars").and_then(Value::as_u64).unwrap_or(4) as usize;

            // v2.0: every read requires a verified macaroon (the dev's root,
            // since the MCP server runs in the dev's process and inherits
            // their identity). Policy is layered on top.
            let root = crate::macaroon::Macaroon::load_root()?;
            let ctx = crate::macaroon::Context::current(key);
            root.verify(&ctx)?;
            crate::policy::check_access(&ctx)?;

            let identity = store::load_identity()?;
            let st = store::load_store(&identity)?;
            let value = st
                .get(key)
                .ok_or_else(|| crate::error::Error::KeyNotFound(key.to_string()))?;
            let _ = lease::audit("mcp.peek", &ctx, None);
            Ok(text_result(store::mask(value, chars)))
        }

        "audit_recent" => {
            let last = args.get("last").and_then(Value::as_u64).unwrap_or(20) as usize;
            let entries = lease::read_recent(last)?;
            let lines: Vec<String> = entries
                .iter()
                .map(|e| {
                    format!(
                        "{}  {}  {}  {}",
                        e.at.to_rfc3339(),
                        e.event,
                        e.key,
                        e.note.as_deref().unwrap_or("")
                    )
                })
                .collect();
            Ok(text_result(if lines.is_empty() {
                "(no audit entries)".to_string()
            } else {
                lines.join("\n")
            }))
        }

        "status" => {
            let dir = store::store_dir()?;
            let id = store::identity_path()?;
            let st_path = store::store_path()?;
            let count = if id.exists() && st_path.exists() {
                let identity = store::load_identity()?;
                store::load_store(&identity)?.len()
            } else {
                0
            };
            Ok(text_result(format!(
                "store: {}\nidentity: {}\nstore: {}\nsecrets: {}",
                dir.display(),
                if id.exists() { "present" } else { "missing" },
                if st_path.exists() {
                    "present"
                } else {
                    "missing"
                },
                count
            )))
        }

        other => Err(crate::error::Error::Other(format!("unknown tool: {other}"))),
    }
}
