//! Session identity, claims, and Ed25519 attestation. See `docs/adr/0004-session-identity.md`.
//!
//! A session is a JSON file containing claims plus a signature over those
//! claims. The private key is generated on `session-start`, used once to
//! sign, and then dropped — it is never persisted.

use std::fs;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::agent;
use crate::error::{Error, Result};
use crate::store::store_dir;

const SESSION_FILENAME: &str = "session.json";

pub fn session_path() -> Result<PathBuf> {
    Ok(store_dir()?.join(SESSION_FILENAME))
}

/// Locally-gathered claims about the calling process. Every field is
/// best-effort; missing fields are serialised as empty strings so the JSON
/// shape stays stable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub who: String,
    pub repo: String,
    pub branch: String,
    pub agent: String,
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl Claims {
    /// Gather claims from the local environment. Errors are swallowed into
    /// empty strings — a missing git config should not stop the session.
    pub fn gather(ttl: Duration) -> Self {
        let started_at = Utc::now();
        Self {
            who: git("config", &["user.email"]).unwrap_or_default(),
            repo: detect_repo(),
            branch: git("rev-parse", &["--abbrev-ref", "HEAD"]).unwrap_or_default(),
            agent: agent::detect_or_none(),
            pid: std::process::id(),
            started_at,
            expires_at: started_at + ttl,
        }
    }

    /// Canonical JSON form (sorted keys, no whitespace) for signing /
    /// verifying. Two equal `Claims` always produce the same bytes.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        // serde_json with a BTreeMap-like roundtrip via Value gives us
        // sorted keys cheaply.
        let value = serde_json::to_value(self)
            .map_err(|e| Error::Other(format!("claims serialise: {e}")))?;
        let sorted = sort_value(value);
        serde_json::to_vec(&sorted).map_err(|e| Error::Other(format!("claims serialise: {e}")))
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
    // Normalise common forms to "owner/repo".
    // git@github.com:owner/repo.git
    // https://github.com/owner/repo(.git)?
    let stripped = url.trim_end_matches(".git").trim_end_matches('/');
    if let Some(rest) = stripped.split_once(':').map(|(_, r)| r) {
        // ssh form
        return rest.to_string();
    }
    // Take the last two path segments
    let parts: Vec<&str> = stripped.rsplit('/').take(2).collect();
    if parts.len() == 2 {
        return format!("{}/{}", parts[1], parts[0]);
    }
    stripped.to_string()
}

/// On-disk session: claims + their detached signature + the public half of
/// the ephemeral keypair.
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub claims: Claims,
    pub public_key: String, // base64 32-byte ed25519 verifying key
    pub signature: String,  // base64 64-byte ed25519 signature over canonical claims
}

impl Session {
    /// Generate a fresh keypair, sign the given claims, drop the private key.
    pub fn new(claims: Claims) -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let canonical = claims.canonical_json()?;
        let signature = signing_key.sign(&canonical);

        // Private key falls out of scope here and is dropped.
        Ok(Self {
            claims,
            public_key: BASE64.encode(verifying_key.to_bytes()),
            signature: BASE64.encode(signature.to_bytes()),
        })
    }

    /// Verify the signature against the embedded public key. Does *not*
    /// check expiry — see `is_expired`.
    pub fn verify(&self) -> Result<()> {
        let pk_bytes = BASE64
            .decode(&self.public_key)
            .map_err(|e| Error::Other(format!("invalid session public key: {e}")))?;
        let pk_arr: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Other("session public key wrong length".into()))?;
        let verifying = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| Error::Other(format!("invalid session public key: {e}")))?;

        let sig_bytes = BASE64
            .decode(&self.signature)
            .map_err(|e| Error::Other(format!("invalid session signature: {e}")))?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Other("session signature wrong length".into()))?;
        let signature = Signature::from_bytes(&sig_arr);

        let canonical = self.claims.canonical_json()?;
        verifying
            .verify(&canonical, &signature)
            .map_err(|e| Error::Other(format!("session signature invalid: {e}")))?;
        Ok(())
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.claims.expires_at
    }
}

/// Write the session file with 0600 perms via atomic rename.
pub fn save_session(s: &Session) -> Result<()> {
    let path = session_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Other("no parent".into()))?;
    fs::create_dir_all(parent)?;
    let json = serde_json::to_vec_pretty(s)
        .map_err(|e| Error::Other(format!("session serialise: {e}")))?;
    let tmp = parent.join(".session.json.tmp");
    fs::write(&tmp, &json)?;
    set_perms(&tmp)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn load_session() -> Result<Session> {
    let path = session_path()?;
    if !path.exists() {
        return Err(Error::NoSession);
    }
    let bytes = fs::read(&path)?;
    let session: Session = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Other(format!("corrupt session file: {e}")))?;
    Ok(session)
}

/// Load + verify + check expiry. Returns the session if all three pass.
pub fn active_session() -> Result<Session> {
    let session = load_session()?;
    session.verify()?;
    if session.is_expired() {
        return Err(Error::NoSession);
    }
    Ok(session)
}

#[allow(dead_code)] // used by v0.4 revoke-all
pub fn delete_session() -> Result<()> {
    let path = session_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> Claims {
        let now = Utc::now();
        Claims {
            who: "alice@example.com".into(),
            repo: "acme/billing".into(),
            branch: "main".into(),
            agent: "claude-code".into(),
            pid: 42,
            started_at: now,
            expires_at: now + Duration::hours(1),
        }
    }

    #[test]
    fn canonical_json_is_sorted() {
        let c = sample_claims();
        let bytes = c.canonical_json().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // agent comes alphabetically before who, etc.
        let agent_pos = s.find("\"agent\"").unwrap();
        let who_pos = s.find("\"who\"").unwrap();
        assert!(agent_pos < who_pos, "keys not sorted: {s}");
    }

    #[test]
    fn session_signs_and_verifies() {
        let c = sample_claims();
        let session = Session::new(c).unwrap();
        session.verify().unwrap();
        assert!(!session.is_expired());
    }

    #[test]
    fn tampered_claims_fail_verification() {
        let c = sample_claims();
        let mut session = Session::new(c).unwrap();
        session.claims.who = "evil@example.com".into();
        assert!(session.verify().is_err());
    }

    #[test]
    fn expired_session_is_expired() {
        let mut c = sample_claims();
        c.started_at = Utc::now() - Duration::hours(2);
        c.expires_at = Utc::now() - Duration::hours(1);
        let session = Session::new(c).unwrap();
        assert!(session.is_expired());
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
}
