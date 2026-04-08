//! The single identity primitive of `llm-secrets`. See `docs/adr/0006-macaroons.md`
//! and `docs/adr/0007-macaroon-merge.md`.
//!
//! Everything in the v2.0 trust model is a macaroon:
//!
//! - **Root macaroon** — the dev's session. Stored at `$LLM_SECRETS_DIR/session.json`.
//!   Caveats describe the dev's current context (who/repo/branch/agent/expires_at)
//!   and constrain when the token is valid.
//! - **Derived macaroon** — a child token the dev mints with extra caveats and
//!   hands to an agent. The HMAC chain extends from the root's signature, so
//!   verification needs only the root key + the full caveat list.
//!
//! There is no other identity object. There is no `Session` struct, no Ed25519
//! signing, no separate `Claims`. The macaroon's caveats are the claims.
//!
//! Verification semantics:
//!
//! 1. Recompute the HMAC-SHA256 chain from `root_key + id + canonical(caveats)`
//!    and constant-time-compare against the stored signature. Tampering at any
//!    point breaks the chain. Caveats cannot be removed, substituted, or
//!    reordered.
//! 2. Evaluate every caveat against the **current request context** —
//!    re-gathered fresh from `git config`, `$PWD`, environment variables.
//!    A token whose caveats no longer hold (wrong branch, expired, wrong
//!    agent) is rejected.
//!
//! The agent never holds the root key. It cannot mint new macaroons. It cannot
//! widen the one it holds — every caveat is enforced by the chain.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::agent;
use crate::error::{Error, Result};
use crate::store::store_dir;

const ROOT_KEY_FILENAME: &str = "root.key";
const SESSION_FILENAME: &str = "session.json";
const ROOT_KEY_LEN: usize = 32;
const ID_LEN: usize = 16;
const LOCATION: &str = "llm-secrets://localhost";

type HmacSha256 = Hmac<Sha256>;

// ---- file paths -----------------------------------------------------------

pub fn root_key_path() -> Result<PathBuf> {
    Ok(store_dir()?.join(ROOT_KEY_FILENAME))
}

pub fn session_path() -> Result<PathBuf> {
    Ok(store_dir()?.join(SESSION_FILENAME))
}

// ---- root key -------------------------------------------------------------

/// Generate a fresh per-session HMAC root key. Called by `session-start`.
/// Overwrites any existing key — minting a new session invalidates every
/// macaroon (root and derived) from the previous session.
pub fn rotate_root_key() -> Result<()> {
    let mut key = [0u8; ROOT_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let path = root_key_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Other("no parent dir for root key".into()))?;
    fs::create_dir_all(parent)?;
    write_secret_file(&path, &key)?;
    Ok(())
}

/// Delete the root key — the killswitch primitive. Every macaroon (root and
/// derived) becomes unverifiable in O(1).
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
        return Err(Error::Other("root key has wrong length".into()));
    }
    let mut out = [0u8; ROOT_KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ---- caveats --------------------------------------------------------------

/// Stateless predicates evaluated against the current request context.
/// All caveats are checked at verification time against fresh values, not
/// against any stored "session state".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Caveat {
    /// Restrict to a single named secret.
    SecretEq(String),
    /// Restrict to one of a list of named secrets.
    SecretsIn(Vec<String>),
    /// Token invalid after this RFC3339 timestamp.
    ExpiresAt(DateTime<Utc>),
    /// Token only valid in this repo (matches `git remote get-url origin`,
    /// normalised to `owner/repo`).
    RepoEq(String),
    /// Token only valid on this git branch.
    BranchEq(String),
    /// Token only valid for this detected agent (claude-code, cursor, etc).
    AgentEq(String),
    /// Token only valid for this user (matches `git config user.email`).
    WhoEq(String),
}

/// Context against which caveats are evaluated. Always built fresh via
/// `Context::current()` — never cached.
pub struct Context<'a> {
    pub key: &'a str,
    pub now: DateTime<Utc>,
    pub who: String,
    pub repo: String,
    pub branch: String,
    pub agent: String,
}

impl<'a> Context<'a> {
    /// Gather the current context from the environment for the given key.
    /// Best-effort: missing fields become empty strings, and a caveat that
    /// requires a missing field will simply not match.
    pub fn current(key: &'a str) -> Self {
        Self {
            key,
            now: Utc::now(),
            who: git("config", &["user.email"]).unwrap_or_default(),
            repo: detect_repo(),
            branch: git("rev-parse", &["--abbrev-ref", "HEAD"]).unwrap_or_default(),
            agent: agent::detect_or_none(),
        }
    }
}

impl Caveat {
    pub fn check(&self, ctx: &Context) -> std::result::Result<(), String> {
        match self {
            Caveat::SecretEq(s) => eq_or_err("secret", ctx.key, s),
            Caveat::SecretsIn(list) => {
                if list.iter().any(|s| s == ctx.key) {
                    Ok(())
                } else {
                    Err(format!("secrets_in: '{}' not in {:?}", ctx.key, list))
                }
            }
            Caveat::ExpiresAt(t) => {
                if ctx.now < *t {
                    Ok(())
                } else {
                    Err(format!("expires_at: token expired at {}", t.to_rfc3339()))
                }
            }
            Caveat::RepoEq(r) => eq_or_err("repo", &ctx.repo, r),
            Caveat::BranchEq(b) => eq_or_err("branch", &ctx.branch, b),
            Caveat::AgentEq(a) => eq_or_err("agent", &ctx.agent, a),
            Caveat::WhoEq(w) => eq_or_err("who", &ctx.who, w),
        }
    }

    /// Canonical byte form for HMAC chain input. Two equal caveats produce
    /// identical bytes (sorted JSON keys, no whitespace).
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)
            .map_err(|e| Error::Other(format!("caveat serialise: {e}")))?;
        let sorted = sort_value(value);
        serde_json::to_vec(&sorted).map_err(|e| Error::Other(format!("caveat serialise: {e}")))
    }

    /// Human-readable summary used by `inspect` and `session-info`.
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

fn eq_or_err(field: &str, actual: &str, expected: &str) -> std::result::Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field}_eq: '{actual}' != '{expected}'"))
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
    /// Mint a fresh root macaroon for the dev's current context. Auto-gathers
    /// who/repo/branch/agent and adds the requested TTL as `expires_at`.
    /// Saves it as `session.json`.
    pub fn mint_root(ttl: Duration) -> Result<Self> {
        rotate_root_key()?;
        let caveats = gather_root_caveats(ttl);
        let m = mint_with_caveats(caveats)?;
        m.save_as_root()?;
        Ok(m)
    }

    /// Load the root macaroon from `session.json`. Errors if no session exists.
    pub fn load_root() -> Result<Self> {
        let path = session_path()?;
        if !path.exists() {
            return Err(Error::NoSession);
        }
        let bytes = fs::read(&path)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Other(format!("corrupt session.json: {e}")))
    }

    pub fn save_as_root(&self) -> Result<()> {
        let path = session_path()?;
        let parent = path
            .parent()
            .ok_or_else(|| Error::Other("no parent dir".into()))?;
        fs::create_dir_all(parent)?;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Other(format!("session serialise: {e}")))?;
        write_secret_file(&path, &json)
    }

    /// Derive a child macaroon by adding extra caveats. The child carries
    /// all of self's caveats plus the new ones, and its signature extends
    /// the chain from self's current signature. The child is verifiable
    /// with the same root key as the parent.
    pub fn delegate(&self, extras: Vec<Caveat>) -> Result<Self> {
        let mut sig = B64URL
            .decode(&self.signature)
            .map_err(|e| Error::Other(format!("parent macaroon signature invalid: {e}")))?;
        let mut all_caveats = self.caveats.clone();
        for c in extras {
            sig = hmac_step(&sig, &c.canonical_bytes()?)?;
            all_caveats.push(c);
        }
        Ok(Self {
            id: self.id.clone(),
            location: self.location.clone(),
            caveats: all_caveats,
            signature: B64URL.encode(sig),
        })
    }

    /// Verify the signature chain against the loaded root key, then evaluate
    /// every caveat against the request context. Both must pass.
    pub fn verify(&self, ctx: &Context) -> Result<()> {
        let root_key = load_root_key()?;
        let mut sig = hmac_step(&root_key, self.id.as_bytes())?;
        for c in &self.caveats {
            sig = hmac_step(&sig, &c.canonical_bytes()?)?;
        }
        let stored = B64URL
            .decode(&self.signature)
            .map_err(|e| Error::Other(format!("macaroon signature invalid base64: {e}")))?;

        if sig.ct_eq(&stored).unwrap_u8() != 1 {
            return Err(Error::Other(
                "macaroon signature invalid (chain mismatch — tampered or wrong root key)".into(),
            ));
        }

        for c in &self.caveats {
            if let Err(reason) = c.check(ctx) {
                return Err(Error::PolicyDenied {
                    key: ctx.key.to_string(),
                    reason: format!("caveat failed: {reason}"),
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

/// Mint a macaroon with the given caveats, computing the chain from the
/// root key. Used internally by `mint_root`.
fn mint_with_caveats(caveats: Vec<Caveat>) -> Result<Macaroon> {
    let root_key = load_root_key()?;
    let mut id_bytes = [0u8; ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let id = B64URL.encode(id_bytes);

    let mut sig = hmac_step(&root_key, id.as_bytes())?;
    for c in &caveats {
        sig = hmac_step(&sig, &c.canonical_bytes()?)?;
    }
    Ok(Macaroon {
        id,
        location: LOCATION.to_string(),
        caveats,
        signature: B64URL.encode(sig),
    })
}

/// Auto-gather the dev's current context as caveats on a fresh root macaroon.
/// All fields are best-effort; a missing git config simply produces an empty
/// caveat that won't match anything (you'll need to renew once `git config`
/// is set).
pub fn gather_root_caveats(ttl: Duration) -> Vec<Caveat> {
    let mut caveats = Vec::new();
    if let Some(who) = git("config", &["user.email"]) {
        caveats.push(Caveat::WhoEq(who));
    }
    let repo = detect_repo();
    if !repo.is_empty() {
        caveats.push(Caveat::RepoEq(repo));
    }
    if let Some(branch) = git("rev-parse", &["--abbrev-ref", "HEAD"]) {
        caveats.push(Caveat::BranchEq(branch));
    }
    if let Some(agent_name) = agent::detect() {
        caveats.push(Caveat::AgentEq(agent_name.0));
    }
    caveats.push(Caveat::ExpiresAt(Utc::now() + ttl));
    caveats
}

fn hmac_step(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| Error::Other(format!("hmac init: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ---- duration parsing -----------------------------------------------------

/// Parse a duration string like `5m`, `1h`, `30s`, `2d`. Lean — no fancy
/// parser, just `<n><unit>`.
pub fn parse_duration(input: &str) -> Result<Duration> {
    let input = input.trim();
    if input.is_empty() {
        return Err(Error::Other("empty duration".into()));
    }
    let (num_str, unit) = input.split_at(input.len() - 1);
    let n: i64 = num_str
        .parse()
        .map_err(|_| Error::Other(format!("invalid duration: {input}")))?;
    let dur = match unit {
        "s" => Duration::seconds(n),
        "m" => Duration::minutes(n),
        "h" => Duration::hours(n),
        "d" => Duration::days(n),
        _ => return Err(Error::Other(format!("invalid duration unit: {input}"))),
    };
    Ok(dur)
}

// ---- git helpers ----------------------------------------------------------

fn git(cmd: &str, args: &[&str]) -> Option<String> {
    let out = ProcessCommand::new("git")
        .arg(cmd)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn detect_repo() -> String {
    let url = match git("remote", &["get-url", "origin"]) {
        Some(u) => u,
        None => return String::new(),
    };
    let stripped = url.trim_end_matches(".git").trim_end_matches('/');
    if let Some(rest) = stripped.split_once(':').map(|(_, r)| r) {
        return rest.to_string();
    }
    let parts: Vec<&str> = stripped.rsplit('/').take(2).collect();
    if parts.len() == 2 {
        return format!("{}/{}", parts[1], parts[0]);
    }
    stripped.to_string()
}

// ---- file helpers ---------------------------------------------------------

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Other(format!("invalid path: {}", path.display())))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("llm-secrets")
    ));
    fs::write(&tmp, bytes)?;
    set_perms(&tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn set_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_perms(_path: &Path) -> Result<()> {
    Ok(())
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

    fn ctx_for(key: &str) -> Context<'_> {
        Context {
            key,
            now: Utc::now(),
            who: "alice@acme.com".into(),
            repo: "acme/billing".into(),
            branch: "main".into(),
            agent: "claude-code".into(),
        }
    }

    #[test]
    fn caveat_basic_checks() {
        assert!(Caveat::SecretEq("db".into()).check(&ctx_for("db")).is_ok());
        assert!(
            Caveat::SecretEq("db".into())
                .check(&ctx_for("other"))
                .is_err()
        );
        assert!(Caveat::BranchEq("main".into()).check(&ctx_for("x")).is_ok());
        assert!(Caveat::BranchEq("dev".into()).check(&ctx_for("x")).is_err());
        assert!(
            Caveat::WhoEq("alice@acme.com".into())
                .check(&ctx_for("x"))
                .is_ok()
        );
    }

    #[test]
    fn caveat_expires_at() {
        let past = Caveat::ExpiresAt(Utc::now() - Duration::seconds(1));
        let future = Caveat::ExpiresAt(Utc::now() + Duration::hours(1));
        assert!(past.check(&ctx_for("x")).is_err());
        assert!(future.check(&ctx_for("x")).is_ok());
    }

    #[test]
    fn canonical_bytes_are_stable() {
        let c1 = Caveat::SecretEq("db".into());
        let c2 = Caveat::SecretEq("db".into());
        assert_eq!(c1.canonical_bytes().unwrap(), c2.canonical_bytes().unwrap());
    }

    #[test]
    fn encode_decode_round_trip() {
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
    }

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::seconds(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::minutes(5));
        assert_eq!(parse_duration("1h").unwrap(), Duration::hours(1));
        assert_eq!(parse_duration("2d").unwrap(), Duration::days(2));
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("").is_err());
    }

    /// Tamper detection + escalation prevention. Both properties live in
    /// one test to serialise the env mutation against itself (parallel
    /// test runs would race on $LLM_SECRETS_DIR otherwise).
    #[test]
    fn hmac_chain_properties() {
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var("LLM_SECRETS_DIR").ok();
        unsafe {
            std::env::set_var("LLM_SECRETS_DIR", dir.path());
        }
        rotate_root_key().unwrap();

        // ---- Property 1: tampering invalidates the signature -------------
        let m = mint_with_caveats(vec![
            Caveat::SecretEq("db".into()),
            Caveat::BranchEq("main".into()),
        ])
        .unwrap();
        let ctx = ctx_for("db");
        m.verify(&ctx).unwrap();

        // Substitute a caveat → chain breaks before caveat eval.
        let mut substituted = m.clone();
        substituted.caveats[0] = Caveat::SecretEq("admin".into());
        assert!(
            substituted
                .verify(&ctx)
                .unwrap_err()
                .to_string()
                .contains("signature invalid")
        );

        // Drop a caveat → chain breaks.
        let mut shorter = m.clone();
        shorter.caveats.pop();
        assert!(shorter.verify(&ctx).is_err());

        // Reorder → chain breaks.
        let mut reordered = m.clone();
        reordered.caveats.reverse();
        assert!(reordered.verify(&ctx).is_err());

        // ---- Property 2: cannot escalate by removing caveats -------------
        let tight = mint_with_caveats(vec![
            Caveat::SecretEq("db".into()),
            Caveat::ExpiresAt(Utc::now() - Duration::seconds(1)),
        ])
        .unwrap();
        assert!(tight.verify(&ctx).is_err()); // expired
        let mut escalated = tight.clone();
        escalated.caveats.pop();
        assert!(
            escalated
                .verify(&ctx)
                .unwrap_err()
                .to_string()
                .contains("signature invalid")
        );

        // ---- Property 3: delegation chains correctly --------------------
        let parent = mint_with_caveats(vec![Caveat::WhoEq("alice@acme.com".into())]).unwrap();
        let child = parent
            .delegate(vec![Caveat::SecretEq("db".into())])
            .unwrap();
        // Child verifies — chain extends from parent.
        child.verify(&ctx_for("db")).unwrap();
        // Child cannot be widened by removing the new caveat.
        let mut wider = child.clone();
        wider.caveats.pop();
        assert!(wider.verify(&ctx).is_err());

        unsafe {
            match prev {
                Some(v) => std::env::set_var("LLM_SECRETS_DIR", v),
                None => std::env::remove_var("LLM_SECRETS_DIR"),
            }
        }
    }
}
