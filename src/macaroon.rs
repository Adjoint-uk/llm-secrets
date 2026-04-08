//! Macaroon-based capability delegation. See `docs/adr/0006-macaroons.md`.
//!
//! A macaroon is a bearer token whose holder can:
//!   - **attenuate** it (add caveats and derive a weaker child token)
//!   - but not **escalate** it (the HMAC-SHA256 chain enforces every caveat)
//!
//! Verification is stateless: given the per-session root key, we recompute
//! the HMAC chain and constant-time-compare against the stored signature,
//! then evaluate every caveat against the current request context.
//!
//! The dev mints a macaroon scoped to one task; the agent receives a token
//! that does *less* than the dev's session, never more.

use std::fs;
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::identity::Claims;
use crate::store::store_dir;

const ROOT_KEY_FILENAME: &str = "macaroon_root.key";
const ROOT_KEY_LEN: usize = 32;
const ID_LEN: usize = 16;
const LOCATION: &str = "llm-secrets://localhost";

type HmacSha256 = Hmac<Sha256>;

pub fn root_key_path() -> Result<PathBuf> {
    Ok(store_dir()?.join(ROOT_KEY_FILENAME))
}

/// Generate a fresh per-session HMAC root key. Called by `session-start`.
/// Overwrites any existing key — minting a new session invalidates every
/// macaroon derived from the previous one.
pub fn rotate_root_key() -> Result<()> {
    let mut key = [0u8; ROOT_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let path = root_key_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Other("no parent dir for root key".into()))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(".macaroon_root.key.tmp");
    fs::write(&tmp, key)?;
    set_perms(&tmp)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Delete the root key — the killswitch primitive. Every derived macaroon
/// becomes unverifiable in O(1).
pub fn delete_root_key() -> Result<()> {
    let path = root_key_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn load_root_key() -> Result<[u8; ROOT_KEY_LEN]> {
    let path = root_key_path()?;
    if !path.exists() {
        return Err(Error::NoSession);
    }
    let bytes = fs::read(&path)?;
    if bytes.len() != ROOT_KEY_LEN {
        return Err(Error::Other("macaroon root key has wrong length".into()));
    }
    let mut out = [0u8; ROOT_KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(unix)]
fn set_perms(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_perms(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

// ---- caveats --------------------------------------------------------------

/// Stateless predicates evaluated against the current request context.
/// See ADR 0006 for the rationale on which caveats are in v1.1 vs deferred.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Caveat {
    /// Restrict to a single named secret.
    SecretEq(String),
    /// Restrict to a list of named secrets.
    SecretsIn(Vec<String>),
    /// Token invalid after this RFC3339 timestamp.
    ExpiresAt(DateTime<Utc>),
    /// Token only valid in this repo (matches active session's claims.repo).
    RepoEq(String),
    /// Token only valid on this branch.
    BranchEq(String),
    /// Token only valid for this detected agent.
    AgentEq(String),
    /// Token only valid for this user (matches active session's claims.who).
    WhoEq(String),
}

/// Context against which caveats are evaluated. The verifier passes the key
/// being requested plus the active session's claims.
pub struct Context<'a> {
    pub key: &'a str,
    pub claims: &'a Claims,
}

impl Caveat {
    pub fn check(&self, ctx: &Context) -> std::result::Result<(), String> {
        match self {
            Caveat::SecretEq(s) => {
                if ctx.key == s {
                    Ok(())
                } else {
                    Err(format!("secret_eq: requested '{}' != '{}'", ctx.key, s))
                }
            }
            Caveat::SecretsIn(list) => {
                if list.iter().any(|s| s == ctx.key) {
                    Ok(())
                } else {
                    Err(format!("secrets_in: '{}' not in {:?}", ctx.key, list))
                }
            }
            Caveat::ExpiresAt(t) => {
                if Utc::now() < *t {
                    Ok(())
                } else {
                    Err(format!("expires_at: token expired at {}", t.to_rfc3339()))
                }
            }
            Caveat::RepoEq(r) => {
                if ctx.claims.repo == *r {
                    Ok(())
                } else {
                    Err(format!(
                        "repo_eq: session repo '{}' != '{}'",
                        ctx.claims.repo, r
                    ))
                }
            }
            Caveat::BranchEq(b) => {
                if ctx.claims.branch == *b {
                    Ok(())
                } else {
                    Err(format!(
                        "branch_eq: session branch '{}' != '{}'",
                        ctx.claims.branch, b
                    ))
                }
            }
            Caveat::AgentEq(a) => {
                if ctx.claims.agent == *a {
                    Ok(())
                } else {
                    Err(format!(
                        "agent_eq: session agent '{}' != '{}'",
                        ctx.claims.agent, a
                    ))
                }
            }
            Caveat::WhoEq(w) => {
                if ctx.claims.who == *w {
                    Ok(())
                } else {
                    Err(format!(
                        "who_eq: session user '{}' != '{}'",
                        ctx.claims.who, w
                    ))
                }
            }
        }
    }

    /// Canonical byte form of this caveat for HMAC chain input. Two equal
    /// caveats must always produce the same bytes.
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)
            .map_err(|e| Error::Other(format!("caveat serialise: {e}")))?;
        let sorted = sort_value(value);
        serde_json::to_vec(&sorted).map_err(|e| Error::Other(format!("caveat serialise: {e}")))
    }

    /// Human-readable summary for `inspect`.
    pub fn describe(&self) -> String {
        match self {
            Caveat::SecretEq(s) => format!("secret == {s}"),
            Caveat::SecretsIn(list) => format!("secret in {list:?}"),
            Caveat::ExpiresAt(t) => format!("expires at {}", t.to_rfc3339()),
            Caveat::RepoEq(r) => format!("repo == {r}"),
            Caveat::BranchEq(b) => format!("branch == {b}"),
            Caveat::AgentEq(a) => format!("agent == {a}"),
            Caveat::WhoEq(w) => format!("user == {w}"),
        }
    }
}

fn sort_value(v: serde_json::Value) -> serde_json::Value {
    use serde_json::{Map, Value};
    match v {
        Value::Object(m) => {
            let mut sorted: Vec<(String, Value)> = m.into_iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k, sort_value(v));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sort_value).collect()),
        other => other,
    }
}

// ---- macaroon -------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Macaroon {
    pub id: String, // base64url 16 random bytes
    pub location: String,
    pub caveats: Vec<Caveat>,
    pub signature: String, // base64url 32 bytes
}

impl Macaroon {
    /// Mint a fresh macaroon. The HMAC chain begins with `HMAC(root_key, id)`
    /// and folds in each caveat in order.
    pub fn mint(caveats: Vec<Caveat>) -> Result<Self> {
        let root_key = load_root_key()?;
        let mut id_bytes = [0u8; ID_LEN];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        let id = B64URL.encode(id_bytes);

        let mut sig = hmac_step(&root_key, id.as_bytes())?;
        for c in &caveats {
            let bytes = c.canonical_bytes()?;
            sig = hmac_step(&sig, &bytes)?;
        }

        Ok(Self {
            id,
            location: LOCATION.to_string(),
            caveats,
            signature: B64URL.encode(sig),
        })
    }

    /// Verify the signature chain against the loaded root key, then evaluate
    /// every caveat against the request context. Both must pass.
    pub fn verify(&self, ctx: &Context) -> Result<()> {
        let root_key = load_root_key()?;
        let mut sig = hmac_step(&root_key, self.id.as_bytes())?;
        for c in &self.caveats {
            let bytes = c.canonical_bytes()?;
            sig = hmac_step(&sig, &bytes)?;
        }
        let stored = B64URL
            .decode(&self.signature)
            .map_err(|e| Error::Other(format!("macaroon signature invalid base64: {e}")))?;

        // Constant-time comparison to avoid timing oracles.
        if sig.ct_eq(&stored).unwrap_u8() != 1 {
            return Err(Error::Other(
                "macaroon signature invalid (chain mismatch — tampered or wrong root key)".into(),
            ));
        }

        for c in &self.caveats {
            if let Err(reason) = c.check(ctx) {
                return Err(Error::PolicyDenied {
                    key: ctx.key.to_string(),
                    reason: format!("macaroon caveat failed: {reason}"),
                });
            }
        }
        Ok(())
    }

    /// Encode as a single base64url JSON blob — the form passed via
    /// `--macaroon` or `LLM_SECRETS_MACAROON`.
    pub fn encode(&self) -> Result<String> {
        let json =
            serde_json::to_vec(self).map_err(|e| Error::Other(format!("macaroon encode: {e}")))?;
        Ok(B64URL.encode(json))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let json = B64URL
            .decode(s.trim())
            .map_err(|e| Error::Other(format!("macaroon decode (base64): {e}")))?;
        serde_json::from_slice(&json)
            .map_err(|e| Error::Other(format!("macaroon decode (json): {e}")))
    }
}

fn hmac_step(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| Error::Other(format!("hmac init: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ---- helpers used by the CLI ---------------------------------------------

/// Try the explicit flag first, then fall back to the env var.
pub fn pick_macaroon(flag: &Option<String>) -> Option<String> {
    if let Some(s) = flag {
        return Some(s.clone());
    }
    std::env::var("LLM_SECRETS_MACAROON")
        .ok()
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn sample_claims() -> Claims {
        let now = Utc::now();
        Claims {
            who: "alice@acme.com".into(),
            repo: "acme/billing".into(),
            branch: "main".into(),
            agent: "claude-code".into(),
            pid: 99,
            started_at: now,
            expires_at: now + Duration::hours(1),
        }
    }

    #[test]
    fn caveat_secret_eq() {
        let c = Caveat::SecretEq("db".into());
        let claims = sample_claims();
        assert!(
            c.check(&Context {
                key: "db",
                claims: &claims
            })
            .is_ok()
        );
        assert!(
            c.check(&Context {
                key: "other",
                claims: &claims
            })
            .is_err()
        );
    }

    #[test]
    fn caveat_expires_at() {
        let claims = sample_claims();
        let past = Caveat::ExpiresAt(Utc::now() - Duration::seconds(1));
        let future = Caveat::ExpiresAt(Utc::now() + Duration::hours(1));
        assert!(
            past.check(&Context {
                key: "x",
                claims: &claims
            })
            .is_err()
        );
        assert!(
            future
                .check(&Context {
                    key: "x",
                    claims: &claims
                })
                .is_ok()
        );
    }

    #[test]
    fn caveat_branch_eq_against_session() {
        let claims = sample_claims();
        let ok = Caveat::BranchEq("main".into());
        let bad = Caveat::BranchEq("feature".into());
        assert!(
            ok.check(&Context {
                key: "x",
                claims: &claims
            })
            .is_ok()
        );
        assert!(
            bad.check(&Context {
                key: "x",
                claims: &claims
            })
            .is_err()
        );
    }

    #[test]
    fn canonical_bytes_are_stable() {
        let c1 = Caveat::SecretEq("db".into());
        let c2 = Caveat::SecretEq("db".into());
        assert_eq!(c1.canonical_bytes().unwrap(), c2.canonical_bytes().unwrap());
    }

    #[test]
    fn encode_decode_round_trip() {
        // We don't need a real root key for encode/decode of an inert macaroon
        // (we just bypass mint by constructing manually).
        let m = Macaroon {
            id: "abc".into(),
            location: LOCATION.into(),
            caveats: vec![
                Caveat::SecretEq("db".into()),
                Caveat::BranchEq("main".into()),
            ],
            signature: B64URL.encode([0u8; 32]),
        };
        let encoded = m.encode().unwrap();
        let decoded = Macaroon::decode(&encoded).unwrap();
        assert_eq!(decoded.id, "abc");
        assert_eq!(decoded.caveats.len(), 2);
        assert_eq!(decoded.caveats[0], Caveat::SecretEq("db".into()));
    }

    #[test]
    fn tampering_a_caveat_invalidates_signature() {
        // Use a tempdir as $LLM_SECRETS_DIR so we don't pollute the real store.
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var("LLM_SECRETS_DIR").ok();
        unsafe {
            std::env::set_var("LLM_SECRETS_DIR", dir.path());
        }

        rotate_root_key().unwrap();

        let m = Macaroon::mint(vec![
            Caveat::SecretEq("db_password".into()),
            Caveat::BranchEq("main".into()),
        ])
        .unwrap();

        let claims = sample_claims();
        let ctx_ok = Context {
            key: "db_password",
            claims: &claims,
        };

        // Pristine: verifies.
        m.verify(&ctx_ok).unwrap();

        // Tamper: replace SecretEq with a wider one. Signature should fail
        // BEFORE caveat evaluation — this is the chain integrity check.
        let mut tampered = m.clone();
        tampered.caveats[0] = Caveat::SecretEq("admin_password".into());
        let err = tampered.verify(&ctx_ok).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("signature invalid"),
            "expected HMAC chain failure, got: {msg}"
        );

        // Tamper: drop a caveat — same chain failure.
        let mut shorter = m.clone();
        shorter.caveats.pop();
        assert!(shorter.verify(&ctx_ok).is_err());

        // Tamper: reorder caveats — same chain failure.
        let mut reordered = m.clone();
        reordered.caveats.reverse();
        assert!(reordered.verify(&ctx_ok).is_err());

        // Cleanup.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("LLM_SECRETS_DIR", v),
                None => std::env::remove_var("LLM_SECRETS_DIR"),
            }
        }
    }

    #[test]
    fn cannot_escalate_by_removing_caveats() {
        // The defining macaroon property: a holder of an attenuated token
        // cannot recover the original by removing caveats.
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var("LLM_SECRETS_DIR").ok();
        unsafe {
            std::env::set_var("LLM_SECRETS_DIR", dir.path());
        }

        rotate_root_key().unwrap();

        // Imagine a "wide" token with one caveat...
        let wide = Macaroon::mint(vec![Caveat::SecretEq("db".into())]).unwrap();
        // ...and a tight token with two.
        let tight = Macaroon::mint(vec![
            Caveat::SecretEq("db".into()),
            Caveat::ExpiresAt(Utc::now() - chrono::Duration::seconds(1)),
        ])
        .unwrap();

        let claims = sample_claims();
        let ctx = Context {
            key: "db",
            claims: &claims,
        };

        // Wide one verifies.
        wide.verify(&ctx).unwrap();
        // Tight one fails (expired).
        assert!(tight.verify(&ctx).is_err());

        // Attempt to "escalate" tight by removing the expiry caveat. The
        // signature does not match a single-caveat chain (the original
        // signature was computed against TWO caveats), so verify fails.
        let mut escalated = tight.clone();
        escalated.caveats.pop();
        let err = escalated.verify(&ctx).unwrap_err();
        assert!(err.to_string().contains("signature invalid"));

        unsafe {
            match prev {
                Some(v) => std::env::set_var("LLM_SECRETS_DIR", v),
                None => std::env::remove_var("LLM_SECRETS_DIR"),
            }
        }
    }

    #[test]
    fn pick_macaroon_prefers_flag() {
        // Save and restore env to be a good test citizen.
        let prev = std::env::var("LLM_SECRETS_MACAROON").ok();
        // SAFETY: tests run single-threaded by default at the module level for
        // env mutation; remove_var/set_var are unsafe in 2024 edition.
        unsafe {
            std::env::set_var("LLM_SECRETS_MACAROON", "from-env");
        }
        let flag = Some("from-flag".to_string());
        assert_eq!(pick_macaroon(&flag).as_deref(), Some("from-flag"));
        let no_flag: Option<String> = None;
        assert_eq!(pick_macaroon(&no_flag).as_deref(), Some("from-env"));
        unsafe {
            match prev {
                Some(v) => std::env::set_var("LLM_SECRETS_MACAROON", v),
                None => std::env::remove_var("LLM_SECRETS_MACAROON"),
            }
        }
    }
}
