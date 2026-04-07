//! Time-bounded leases (#7) and append-only audit log (#8).
//!
//! A lease is a time-bounded grant of access to one secret, anchored to a
//! session. It records *that* the access happened, when it expires, and the
//! session identity at the time. Subsequent reads via `exec` consult the
//! lease list — an expired lease counts as no lease.
//!
//! v0.3's `peek` / `exec` flow already enforces policy. Leases add a second
//! layer: even with a policy allow, you must hold a current lease. They
//! also produce the audit trail that #8 needs.
//!
//! For now leases are an *opt-in* gate. They are checked by `exec --leased`
//! and recorded by `llms lease`. The default `exec` path stays
//! lease-less so existing flows are unaffected. v1 can flip the default.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::{Claims, active_session};
use crate::store::store_dir;

const LEASES_FILENAME: &str = "leases.json";
const AUDIT_FILENAME: &str = "audit.jsonl";

pub fn leases_path() -> Result<PathBuf> {
    Ok(store_dir()?.join(LEASES_FILENAME))
}

pub fn audit_path() -> Result<PathBuf> {
    Ok(store_dir()?.join(AUDIT_FILENAME))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub key: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub session_who: String,
    pub session_repo: String,
    pub session_agent: String,
    pub session_pid: u32,
}

impl Lease {
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LeaseSet {
    #[serde(default)]
    pub leases: Vec<Lease>,
}

impl LeaseSet {
    pub fn load() -> Result<Self> {
        let path = leases_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(&path)?;
        let set: LeaseSet = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Other(format!("corrupt leases file: {e}")))?;
        Ok(set)
    }

    pub fn save(&self) -> Result<()> {
        let path = leases_path()?;
        let parent = path
            .parent()
            .ok_or_else(|| Error::Other("no parent".into()))?;
        fs::create_dir_all(parent)?;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Other(format!("leases serialise: {e}")))?;
        let tmp = parent.join(".leases.json.tmp");
        fs::write(&tmp, &json)?;
        set_perms(&tmp)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Drop expired leases. Returns the number removed.
    pub fn prune(&mut self) -> usize {
        let before = self.leases.len();
        self.leases.retain(|l| !l.is_expired());
        before - self.leases.len()
    }

    #[allow(dead_code)] // used by `exec --leased` enforcement (planned)
    pub fn active_for(&self, key: &str) -> Option<&Lease> {
        self.leases
            .iter()
            .filter(|l| l.key == key && !l.is_expired())
            .max_by_key(|l| l.expires_at)
    }
}

/// Grant a new lease, anchoring it to the active session and recording the
/// fact in the audit log.
pub fn grant(key: &str, ttl: chrono::Duration) -> Result<Lease> {
    let session = active_session()?;
    let now = Utc::now();
    let lease = Lease {
        key: key.to_string(),
        granted_at: now,
        expires_at: now + ttl,
        session_who: session.claims.who.clone(),
        session_repo: session.claims.repo.clone(),
        session_agent: session.claims.agent.clone(),
        session_pid: session.claims.pid,
    };
    let mut set = LeaseSet::load()?;
    set.prune();
    set.leases.push(lease.clone());
    set.save()?;
    audit("lease.grant", key, &session.claims, None)?;
    Ok(lease)
}

// ---- audit log ------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: DateTime<Utc>,
    pub event: String,
    pub key: String,
    pub who: String,
    pub repo: String,
    pub branch: String,
    pub agent: String,
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Append a single audit record. Best-effort: if the file cannot be opened
/// for append we still return Err so callers can decide whether to fail
/// the operation. (Default: yes — auditability is load-bearing.)
pub fn audit(event: &str, key: &str, claims: &Claims, note: Option<String>) -> Result<()> {
    let path = audit_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Other("no parent".into()))?;
    fs::create_dir_all(parent)?;

    let entry = AuditEntry {
        at: Utc::now(),
        event: event.to_string(),
        key: key.to_string(),
        who: claims.who.clone(),
        repo: claims.repo.clone(),
        branch: claims.branch.clone(),
        agent: claims.agent.clone(),
        pid: claims.pid,
        note,
    };
    let line =
        serde_json::to_string(&entry).map_err(|e| Error::Other(format!("audit serialise: {e}")))?;

    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    set_perms(&path)?;
    writeln!(f, "{line}")?;
    Ok(())
}

/// Read the last `n` audit entries. Returns oldest-first.
pub fn read_recent(n: usize) -> Result<Vec<AuditEntry>> {
    let path = audit_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let text = fs::read_to_string(&path)?;
    let mut all: Vec<AuditEntry> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let len = all.len();
    if len > n {
        all.drain(0..len - n);
    }
    Ok(all)
}

// ---- killswitch -----------------------------------------------------------

/// Emergency: revoke every active lease and the active session. Audited.
/// Returns the number of leases revoked.
pub fn revoke_all() -> Result<usize> {
    let mut set = LeaseSet::load()?;
    let count = set.leases.len();
    set.leases.clear();
    set.save()?;

    // Best-effort claims for the audit entry — fall back to empty if no
    // session was active.
    let claims = active_session()
        .map(|s| s.claims)
        .unwrap_or_else(|_| Claims {
            who: String::new(),
            repo: String::new(),
            branch: String::new(),
            agent: String::new(),
            pid: std::process::id(),
            started_at: Utc::now(),
            expires_at: Utc::now(),
        });
    audit(
        "revoke.all",
        "*",
        &claims,
        Some(format!("revoked {count} leases")),
    )?;

    crate::identity::delete_session()?;
    Ok(count)
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn lease_expiry() {
        let now = Utc::now();
        let active = Lease {
            key: "k".into(),
            granted_at: now,
            expires_at: now + Duration::hours(1),
            session_who: "u".into(),
            session_repo: "r".into(),
            session_agent: "a".into(),
            session_pid: 1,
        };
        assert!(!active.is_expired());

        let expired = Lease {
            expires_at: now - Duration::seconds(1),
            ..active.clone()
        };
        assert!(expired.is_expired());
    }

    #[test]
    fn prune_drops_expired() {
        let now = Utc::now();
        let mut set = LeaseSet {
            leases: vec![
                Lease {
                    key: "active".into(),
                    granted_at: now,
                    expires_at: now + Duration::hours(1),
                    session_who: "u".into(),
                    session_repo: "r".into(),
                    session_agent: "a".into(),
                    session_pid: 1,
                },
                Lease {
                    key: "expired".into(),
                    granted_at: now - Duration::hours(2),
                    expires_at: now - Duration::hours(1),
                    session_who: "u".into(),
                    session_repo: "r".into(),
                    session_agent: "a".into(),
                    session_pid: 1,
                },
            ],
        };
        let removed = set.prune();
        assert_eq!(removed, 1);
        assert_eq!(set.leases.len(), 1);
        assert_eq!(set.leases[0].key, "active");
    }
}
