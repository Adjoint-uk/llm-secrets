//! Policy file parsing and evaluation (#5).
//!
//! `.llm-secrets-policy.yaml` lives in the git root of the calling repo. If
//! it exists, every operation that touches secret values is checked against
//! it. If it does not exist, all access is allowed (backwards compatible).
//!
//! Schema:
//!
//! ```yaml
//! secrets:
//!   db_password:
//!     allow:
//!       - repo: adjoint-uk/billing
//!         branch: [main, develop]
//!         user: cptfinch
//!         agent: claude-code
//!         max_ttl: 10m
//!     deny:
//!       - branch: "*"
//! ```
//!
//! Match semantics:
//! - `allow` rules are tried in order; first match wins.
//! - If no `allow` matches, the request is denied.
//! - Each field is optional. A missing field matches anything.
//! - Strings match exactly. Lists match if any element matches. `"*"` is a
//!   wildcard.
//! - `max_ttl` constrains the lease TTL (#7); for v0.3 it is parsed and
//!   stored but not yet enforced.

use std::fs;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::Claims;

const POLICY_FILENAME: &str = ".llm-secrets-policy.yaml";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub secrets: std::collections::BTreeMap<String, SecretPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretPolicy {
    #[serde(default)]
    pub allow: Vec<Rule>,
    #[serde(default)]
    pub deny: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub repo: Option<StringOrList>,
    #[serde(default)]
    pub branch: Option<StringOrList>,
    #[serde(default)]
    pub user: Option<StringOrList>,
    #[serde(default)]
    pub agent: Option<StringOrList>,
    #[serde(default)]
    pub max_ttl: Option<String>,
}

/// A field that may be a single string or a list of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    One(String),
    Many(Vec<String>),
}

impl StringOrList {
    fn matches(&self, value: &str) -> bool {
        let candidates: Vec<&str> = match self {
            StringOrList::One(s) => vec![s.as_str()],
            StringOrList::Many(v) => v.iter().map(String::as_str).collect(),
        };
        candidates.iter().any(|c| *c == "*" || *c == value)
    }
}

impl Rule {
    pub fn matches(&self, claims: &Claims) -> bool {
        let check = |field: &Option<StringOrList>, value: &str| -> bool {
            field.as_ref().map(|f| f.matches(value)).unwrap_or(true)
        };
        check(&self.repo, &claims.repo)
            && check(&self.branch, &claims.branch)
            && check(&self.user, &claims.who)
            && check(&self.agent, &claims.agent)
    }
}

/// Outcome of a policy check.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
}

impl Policy {
    /// Evaluate the policy for a given key + claims. If the key is not
    /// mentioned in the policy, it is denied: explicit allow-list semantics
    /// are safer than implicit allow.
    pub fn evaluate(&self, key: &str, claims: &Claims) -> Decision {
        let entry = match self.secrets.get(key) {
            Some(e) => e,
            None => {
                return Decision::Deny(format!("no rule for '{key}' in policy"));
            }
        };

        // Deny rules are checked first and short-circuit.
        for rule in &entry.deny {
            if rule.matches(claims) {
                return Decision::Deny(format!("denied by deny rule for '{key}'"));
            }
        }
        for rule in &entry.allow {
            if rule.matches(claims) {
                return Decision::Allow;
            }
        }
        Decision::Deny(format!("no allow rule matched for '{key}'"))
    }
}

/// Walk up from CWD looking for the git root, then check for the policy
/// file there. Returns `Ok(None)` if no policy file is found — that means
/// permissive mode (backwards compatible).
pub fn load_for_cwd() -> Result<Option<Policy>> {
    let git_root = find_git_root();
    let path = match git_root {
        Some(root) => root.join(POLICY_FILENAME),
        None => PathBuf::from(POLICY_FILENAME),
    };
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    let policy: Policy = serde_yaml::from_slice(&bytes)
        .map_err(|e| Error::Other(format!("policy file invalid YAML: {e}")))?;
    Ok(Some(policy))
}

fn find_git_root() -> Option<PathBuf> {
    let out = ProcessCommand::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

/// Top-level guard used by every command that reads secret values.
///
/// - If there is no policy file, returns `Ok(())` (permissive default).
/// - If there is a policy, requires an active session and evaluates.
pub fn check_access(key: &str) -> Result<()> {
    let policy = match load_for_cwd()? {
        Some(p) => p,
        None => return Ok(()),
    };

    let session = crate::identity::active_session().map_err(|_| Error::PolicyDenied {
        key: key.to_string(),
        reason: "policy file present but no active session — run `llms session-start`".into(),
    })?;

    match policy.evaluate(key, &session.claims) {
        Decision::Allow => Ok(()),
        Decision::Deny(reason) => Err(Error::PolicyDenied {
            key: key.to_string(),
            reason,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn claims(repo: &str, branch: &str, user: &str, agent: &str) -> Claims {
        let now = Utc::now();
        Claims {
            who: user.into(),
            repo: repo.into(),
            branch: branch.into(),
            agent: agent.into(),
            pid: 1,
            started_at: now,
            expires_at: now + Duration::hours(1),
        }
    }

    fn parse(yaml: &str) -> Policy {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn unmentioned_key_is_denied() {
        let p = parse("secrets: {}");
        let c = claims("a/b", "main", "u", "claude-code");
        matches!(p.evaluate("anything", &c), Decision::Deny(_));
    }

    #[test]
    fn simple_allow() {
        let p = parse(
            r#"
secrets:
  db_password:
    allow:
      - repo: acme/billing
        branch: main
        user: alice
"#,
        );
        let ok = claims("acme/billing", "main", "alice", "claude-code");
        assert_eq!(p.evaluate("db_password", &ok), Decision::Allow);
        let wrong_branch = claims("acme/billing", "feature", "alice", "claude-code");
        matches!(p.evaluate("db_password", &wrong_branch), Decision::Deny(_));
    }

    #[test]
    fn list_field_matches_any() {
        let p = parse(
            r#"
secrets:
  db_password:
    allow:
      - branch: [main, develop]
"#,
        );
        let main = claims("a/b", "main", "u", "claude-code");
        let dev = claims("a/b", "develop", "u", "claude-code");
        let other = claims("a/b", "feature", "u", "claude-code");
        assert_eq!(p.evaluate("db_password", &main), Decision::Allow);
        assert_eq!(p.evaluate("db_password", &dev), Decision::Allow);
        matches!(p.evaluate("db_password", &other), Decision::Deny(_));
    }

    #[test]
    fn deny_overrides_allow() {
        let p = parse(
            r#"
secrets:
  db_password:
    allow:
      - branch: "*"
    deny:
      - branch: forbidden
"#,
        );
        let ok = claims("a/b", "main", "u", "claude-code");
        let bad = claims("a/b", "forbidden", "u", "claude-code");
        assert_eq!(p.evaluate("db_password", &ok), Decision::Allow);
        matches!(p.evaluate("db_password", &bad), Decision::Deny(_));
    }

    #[test]
    fn wildcard_allow() {
        let p = parse(
            r#"
secrets:
  api_key:
    allow:
      - branch: "*"
"#,
        );
        let c = claims("a/b", "anything", "u", "claude-code");
        assert_eq!(p.evaluate("api_key", &c), Decision::Allow);
    }
}
