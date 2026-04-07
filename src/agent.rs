//! Agent type detection (#6).
//!
//! Best-effort heuristic to identify which AI coding agent (if any) is the
//! parent process. Used as the `agent` claim in session attestation and as
//! a match dimension in policy rules.

use std::env;

/// A normalised identifier for the calling agent. Strings are kebab-case so
/// they're stable across the policy file, the session file, and the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent(pub String);

impl Agent {
    #[allow(dead_code)] // used by tests and v0.4 audit log
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Detect the agent from environment variables. Returns `None` if nothing
/// suggests an agent context (i.e. an interactive shell).
///
/// The probe order matters: the first match wins. New agents go at the top
/// of their family.
pub fn detect() -> Option<Agent> {
    let probes: &[(&[&str], &str)] = &[
        // Claude Code sets CLAUDECODE / CLAUDE_CODE_* in its child processes.
        (
            &["CLAUDECODE", "CLAUDE_CODE", "CLAUDE_CODE_ENTRYPOINT"],
            "claude-code",
        ),
        // Cursor's terminal agent.
        (&["CURSOR_AGENT", "CURSOR_TRACE_ID"], "cursor"),
        // GitHub Copilot CLI / chat.
        (
            &["COPILOT_AGENT_ID", "GITHUB_COPILOT_TOKEN"],
            "github-copilot",
        ),
        // Aider sets AIDER_* env in its shell pop-outs.
        (&["AIDER_CHAT_HISTORY_FILE", "AIDER_MODEL"], "aider"),
        // Continue.dev.
        (&["CONTINUE_GLOBAL_DIR"], "continue"),
        // Codeium / Windsurf.
        (&["WINDSURF_SESSION_ID", "CODEIUM_API_KEY"], "windsurf"),
    ];

    for (vars, name) in probes {
        for v in *vars {
            if env::var(v).is_ok() {
                return Some(Agent(name.to_string()));
            }
        }
    }
    None
}

/// Convenience for places that want a string ("none" if not detected).
pub fn detect_or_none() -> String {
    detect().map(|a| a.0).unwrap_or_else(|| "none".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // We can't easily mutate the global env without affecting other tests, so
    // these stay narrow: just exercise the helper string and the obvious
    // unset case via a synthetic probe.

    #[test]
    fn detect_or_none_returns_string() {
        let s = detect_or_none();
        assert!(!s.is_empty());
    }

    #[test]
    fn agent_as_str() {
        assert_eq!(Agent("claude-code".to_string()).as_str(), "claude-code");
    }
}
