//! TOML profile definitions — the recipe layer. See `docs/adr/0008-toml-profiles.md`.
//!
//! A profile is **config**, not a token. It groups secrets, env-var mappings,
//! and default caveats under a name. At mint time the CLI reads the profile,
//! converts it to a `Vec<Caveat>`, and hands it to the existing
//! `Macaroon::delegate` path. The macaroon code does not know profiles
//! exist; this module does not know HMAC chains exist. The two layers meet
//! only at the CLI glue point.
//!
//! Profiles live at `$LLM_SECRETS_CONFIG_DIR/profiles.toml` (default
//! `$XDG_CONFIG_HOME/llm-secrets/profiles.toml`, typically
//! `~/.config/llm-secrets/profiles.toml`). The store at `~/.llm-secrets/`
//! is the security boundary; profiles.toml is non-secret config — diffable,
//! vimmable, dotfile-managed. Stealing it confers no authority.
//!
//! An optional `profiles.d/*.toml` directory next to `profiles.toml` holds
//! per-machine overrides (not synced by dotfiles): each file is a map of
//! `name -> profile`, same shape as `profiles.toml`, and any name it
//! defines fully replaces the same-named entry from `profiles.toml` (or
//! adds a new machine-local profile if the name doesn't exist there). This
//! is a config-loading precedence question, not a security boundary, so —
//! unlike `extends` — there is no narrowing constraint: the override simply
//! wins. See `docs/adr/0008-toml-profiles.md`, Phase 2.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Duration;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::macaroon::{Caveat, parse_duration};

const PROFILES_FILENAME: &str = "profiles.toml";
const PROFILES_D_DIRNAME: &str = "profiles.d";
const CONFIG_DIR_ENV: &str = "LLM_SECRETS_CONFIG_DIR";

/// Resolve the config directory. Honours `$LLM_SECRETS_CONFIG_DIR`,
/// otherwise `$XDG_CONFIG_HOME/llm-secrets` (typically
/// `~/.config/llm-secrets`). The override exists so tests can isolate.
pub fn config_dir() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var(CONFIG_DIR_ENV)
        && !custom.is_empty()
    {
        return Ok(PathBuf::from(custom));
    }
    let base = dirs::config_dir()
        .ok_or_else(|| Error::Other("could not determine config directory".into()))?;
    Ok(base.join("llm-secrets"))
}

pub fn profiles_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(PROFILES_FILENAME))
}

pub fn profiles_d_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join(PROFILES_D_DIRNAME))
}

/// In-memory representation of one profile, ready to be turned into caveats.
#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub secrets: Vec<String>,
    /// `ENV_VAR -> secret_key`. CLI sugar, not crypto. Used by `profile exec`
    /// to drive `-i` injections after minting.
    pub env: BTreeMap<String, String>,
    pub ttl: Duration,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub agent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProfileToml {
    /// Parent profile name. When set, `secrets`/`ttl` become optional
    /// (inherited from the parent if omitted) and every field this profile
    /// does specify may only narrow what the parent already grants — never
    /// widen it. See `resolve()`.
    #[serde(default)]
    extends: Option<String>,
    /// Required unless `extends` is set (in which case it defaults to the
    /// parent's list, or may be a subset of it).
    #[serde(default)]
    secrets: Option<Vec<String>>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Required unless `extends` is set (in which case it defaults to the
    /// parent's ttl, or may be shorter than it).
    #[serde(default)]
    ttl: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    agent: Option<String>,
}

fn parse_profiles_toml(path: &Path, text: &str) -> Result<BTreeMap<String, ProfileToml>> {
    toml::from_str(text).map_err(|e| Error::Other(format!("{} invalid: {e}", path.display())))
}

/// Reads `profiles.toml`, then layers any `profiles.d/*.toml` overrides on
/// top (sorted by filename for determinism). A name defined in `profiles.d`
/// fully replaces the same-named entry from `profiles.toml` — that's the
/// point (per-machine override) — but the same name appearing in two
/// different `profiles.d` files is almost certainly a mistake, so that's
/// rejected loudly rather than silently picked by sort order.
fn read_profiles_file() -> Result<BTreeMap<String, ProfileToml>> {
    let path = profiles_path()?;
    let file_exists = path.exists();
    let mut map: BTreeMap<String, ProfileToml> = if file_exists {
        let text = fs::read_to_string(&path)?;
        parse_profiles_toml(&path, &text)?
    } else {
        BTreeMap::new()
    };

    let d_dir = profiles_d_dir()?;
    let mut had_d_files = false;
    if d_dir.is_dir() {
        let mut entries: Vec<PathBuf> = fs::read_dir(&d_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
            .collect();
        entries.sort();
        had_d_files = !entries.is_empty();

        let mut override_sources: BTreeMap<String, PathBuf> = BTreeMap::new();
        for file_path in entries {
            let text = fs::read_to_string(&file_path)?;
            let overrides = parse_profiles_toml(&file_path, &text)?;
            for (name, t) in overrides {
                if let Some(prev) = override_sources.insert(name.clone(), file_path.clone()) {
                    return Err(Error::Other(format!(
                        "profile '{name}' is defined in multiple profiles.d files: {} and {}",
                        prev.display(),
                        file_path.display()
                    )));
                }
                map.insert(name, t);
            }
        }
    }

    if !file_exists && !had_d_files {
        return Err(Error::Other(format!(
            "no profiles file at {} — create one to use profiles",
            path.display()
        )));
    }
    Ok(map)
}

fn parse_ttl(name: &str, s: &str) -> Result<Duration> {
    parse_duration(s).map_err(|_| {
        Error::Other(format!(
            "profile '{name}' has invalid ttl '{s}' (expected duration like '8h', '30m', '1d')"
        ))
    })
}

/// Resolve `name` to a fully-materialised `Profile`, following `extends`
/// chains. `chain` tracks names currently being resolved (for cycle
/// detection) — callers pass an empty `Vec`.
///
/// Inheritance is additive-only, mirroring the macaroon rule that a
/// derived token can never widen what its parent grants (see
/// `docs/adr/0008-toml-profiles.md`, Phase 2):
/// - `secrets`, if given, must be a subset of the parent's.
/// - `ttl`, if given, must not exceed the parent's.
/// - `repo`/`branch`/`agent` may only be set by the child if the parent
///   left them unset — a child can never override an inherited caveat.
/// - `env` is pure CLI sugar (not a caveat), so the child's entries are
///   simply merged on top of the parent's.
fn resolve(
    name: &str,
    map: &BTreeMap<String, ProfileToml>,
    chain: &mut Vec<String>,
) -> Result<Profile> {
    if chain.iter().any(|n| n == name) {
        let mut cyc = chain.clone();
        cyc.push(name.to_string());
        return Err(Error::Other(format!(
            "profile inheritance cycle: {}",
            cyc.join(" -> ")
        )));
    }
    chain.push(name.to_string());
    let out = resolve_one(name, map, chain);
    chain.pop();
    out
}

fn resolve_one(
    name: &str,
    map: &BTreeMap<String, ProfileToml>,
    chain: &mut Vec<String>,
) -> Result<Profile> {
    let t = map.get(name).ok_or_else(|| {
        Error::Other(format!(
            "profile '{name}' not found in {}",
            profiles_path()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ))
    })?;

    let profile = if let Some(parent_name) = &t.extends {
        if !map.contains_key(parent_name) {
            return Err(Error::Other(format!(
                "profile '{name}' extends unknown profile '{parent_name}'"
            )));
        }
        let parent = resolve(parent_name, map, chain)?;

        let secrets = match &t.secrets {
            Some(list) => {
                for s in list {
                    if !parent.secrets.contains(s) {
                        return Err(Error::Other(format!(
                            "profile '{name}' extends '{parent_name}' but secret '{s}' is not in the parent's secrets list — inheritance can only narrow, never widen"
                        )));
                    }
                }
                list.clone()
            }
            None => parent.secrets.clone(),
        };

        let ttl = match &t.ttl {
            Some(s) => {
                let d = parse_ttl(name, s)?;
                if d > parent.ttl {
                    return Err(Error::Other(format!(
                        "profile '{name}' extends '{parent_name}' but ttl '{s}' exceeds the parent's ttl ({}) — inheritance can only narrow, never widen",
                        format_duration(parent.ttl)
                    )));
                }
                d
            }
            None => parent.ttl,
        };

        let repo = narrow_field(name, parent_name, "repo", &parent.repo, &t.repo)?;
        let branch = narrow_field(name, parent_name, "branch", &parent.branch, &t.branch)?;
        let agent = narrow_field(name, parent_name, "agent", &parent.agent, &t.agent)?;

        let mut env = parent.env.clone();
        env.extend(t.env.clone());

        Profile {
            name: name.to_string(),
            secrets,
            env,
            ttl,
            repo,
            branch,
            agent,
        }
    } else {
        let secrets = t.secrets.clone().ok_or_else(|| {
            Error::Other(format!(
                "profile '{name}' has no 'secrets' (required unless it uses 'extends')"
            ))
        })?;
        let ttl_str = t.ttl.as_deref().ok_or_else(|| {
            Error::Other(format!(
                "profile '{name}' has no 'ttl' (required unless it uses 'extends')"
            ))
        })?;
        let ttl = parse_ttl(name, ttl_str)?;
        Profile {
            name: name.to_string(),
            secrets,
            env: t.env.clone(),
            ttl,
            repo: t.repo.clone(),
            branch: t.branch.clone(),
            agent: t.agent.clone(),
        }
    };

    profile.validate()?;
    Ok(profile)
}

/// A child may only set a caveat field the parent left unset — never
/// override one the parent already restricts to. Returns the resolved
/// value (inherited, newly added, or unset).
fn narrow_field(
    name: &str,
    parent_name: &str,
    field: &str,
    parent_value: &Option<String>,
    child_value: &Option<String>,
) -> Result<Option<String>> {
    match (parent_value, child_value) {
        (Some(_), Some(_)) => Err(Error::Other(format!(
            "profile '{name}' extends '{parent_name}' but overrides the inherited '{field}' caveat — inheritance can only add new caveats, not change existing ones"
        ))),
        (Some(p), None) => Ok(Some(p.clone())),
        (None, Some(c)) => Ok(Some(c.clone())),
        (None, None) => Ok(None),
    }
}

impl Profile {
    pub fn load(name: &str) -> Result<Self> {
        let map = read_profiles_file()?;
        resolve(name, &map, &mut Vec::new())
    }

    pub fn list() -> Result<Vec<Profile>> {
        let map = read_profiles_file()?;
        let mut out = Vec::with_capacity(map.len());
        for name in map.keys() {
            out.push(resolve(name, &map, &mut Vec::new())?);
        }
        Ok(out)
    }

    /// Validate internal consistency. Every secret referenced by an env
    /// mapping must appear in the profile's `secrets` list — otherwise the
    /// env mapping is dangling and would silently fail at exec time. Loud
    /// at load is better than silent at 3am.
    pub fn validate(&self) -> Result<()> {
        for (env_var, secret_key) in &self.env {
            if !self.secrets.contains(secret_key) {
                return Err(Error::Other(format!(
                    "profile '{}' env var '{env_var}' references secret '{secret_key}' which is not in the profile's secrets list",
                    self.name
                )));
            }
        }
        Ok(())
    }

    /// Convert to the caveat list handed to `Macaroon::delegate`. The env
    /// map is intentionally NOT a caveat — it's CLI sugar, not crypto.
    /// (See ADR 0008, "Phase 1 — No `EnvMap` macaroon caveat".)
    pub fn to_caveats(&self, ttl_override: Option<Duration>) -> Vec<Caveat> {
        let mut caveats = Vec::new();
        match self.secrets.len() {
            0 => {} // technically allowed but useless; mint will still produce a token
            1 => caveats.push(Caveat::SecretEq(self.secrets[0].clone())),
            _ => caveats.push(Caveat::SecretsIn(self.secrets.clone())),
        }
        let ttl = ttl_override.unwrap_or(self.ttl);
        caveats.push(Caveat::ExpiresAt(chrono::Utc::now() + ttl));
        if let Some(r) = &self.repo {
            caveats.push(Caveat::RepoEq(r.clone()));
        }
        if let Some(b) = &self.branch {
            caveats.push(Caveat::BranchEq(b.clone()));
        }
        if let Some(a) = &self.agent {
            caveats.push(Caveat::AgentEq(a.clone()));
        }
        caveats
    }
}

/// Render a duration in the same format `parse_duration` accepts. Largest
/// whole-unit wins.
pub fn format_duration(d: Duration) -> String {
    let secs = d.num_seconds();
    if secs == 0 {
        return "0s".into();
    }
    if secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All file-system tests live in one body so they share the
    /// `LLM_SECRETS_CONFIG_DIR` env var without racing other parallel
    /// tests. (Same pattern as `macaroon::tests::hmac_chain_properties`.)
    #[test]
    fn file_system_load_paths() {
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var(CONFIG_DIR_ENV).ok();
        unsafe {
            std::env::set_var(CONFIG_DIR_ENV, dir.path());
        }

        let write = |body: &str| {
            std::fs::create_dir_all(dir.path()).unwrap();
            std::fs::write(dir.path().join("profiles.toml"), body).unwrap();
        };

        // Happy path
        write(
            r#"
[iba]
secrets = ["a", "b"]
ttl = "8h"

[iba.env]
A = "a"
B = "b"
"#,
        );
        let p = Profile::load("iba").unwrap();
        assert_eq!(p.name, "iba");
        assert_eq!(p.secrets, vec!["a", "b"]);
        assert_eq!(p.ttl, Duration::hours(8));
        assert_eq!(p.env.get("A").unwrap(), "a");

        // Missing profile
        write(
            r#"[iba]
secrets = ["a"]
ttl = "1h"
"#,
        );
        let err = Profile::load("nope").unwrap_err().to_string();
        assert!(err.contains("not found"), "{err}");

        // Invalid ttl
        write(
            r#"[iba]
secrets = ["a"]
ttl = "8 hours"
"#,
        );
        let err = Profile::load("iba").unwrap_err().to_string();
        assert!(err.contains("invalid ttl"), "{err}");

        // Dangling env reference
        write(
            r#"[iba]
secrets = ["a"]
ttl = "1h"

[iba.env]
A = "a"
B = "missing"
"#,
        );
        let err = Profile::load("iba").unwrap_err().to_string();
        assert!(err.contains("missing"), "{err}");
        assert!(err.contains("not in the profile"), "{err}");

        // extends: inherits secrets/ttl/env when the child omits them
        write(
            r#"
[iba]
secrets = ["a", "b", "c"]
ttl = "8h"
branch = "main"

[iba.env]
A = "a"

[iba-prod]
extends = "iba"

[iba-prod.env]
B = "b"
"#,
        );
        let p = Profile::load("iba-prod").unwrap();
        assert_eq!(p.secrets, vec!["a", "b", "c"]);
        assert_eq!(p.ttl, Duration::hours(8));
        assert_eq!(p.branch.as_deref(), Some("main"));
        assert_eq!(p.env.get("A").unwrap(), "a"); // inherited
        assert_eq!(p.env.get("B").unwrap(), "b"); // added

        // extends: child may narrow secrets to a subset
        write(
            r#"
[iba]
secrets = ["a", "b", "c"]
ttl = "8h"

[iba-prod]
extends = "iba"
secrets = ["a", "b"]
"#,
        );
        let p = Profile::load("iba-prod").unwrap();
        assert_eq!(p.secrets, vec!["a", "b"]);

        // extends: child cannot widen secrets beyond the parent's list
        write(
            r#"
[iba]
secrets = ["a"]
ttl = "8h"

[iba-prod]
extends = "iba"
secrets = ["a", "z"]
"#,
        );
        let err = Profile::load("iba-prod").unwrap_err().to_string();
        assert!(err.contains("'z'"), "{err}");
        assert!(err.contains("never widen"), "{err}");

        // extends: child may shorten ttl, but not lengthen it
        write(
            r#"
[iba]
secrets = ["a"]
ttl = "8h"

[iba-prod]
extends = "iba"
ttl = "1h"

[iba-staging]
extends = "iba"
ttl = "1d"
"#,
        );
        assert_eq!(Profile::load("iba-prod").unwrap().ttl, Duration::hours(1));
        let err = Profile::load("iba-staging").unwrap_err().to_string();
        assert!(err.contains("exceeds the parent's ttl"), "{err}");

        // extends: child may add a caveat the parent left unset, but cannot
        // override one the parent already set
        write(
            r#"
[iba]
secrets = ["a"]
ttl = "8h"

[iba-prod]
extends = "iba"
branch = "main"

[iba-locked]
extends = "iba-prod"
branch = "dev"
"#,
        );
        assert_eq!(
            Profile::load("iba-prod").unwrap().branch.as_deref(),
            Some("main")
        );
        let err = Profile::load("iba-locked").unwrap_err().to_string();
        assert!(err.contains("overrides the inherited 'branch'"), "{err}");

        // extends: unknown parent
        write(
            r#"
[iba-prod]
extends = "nope"
secrets = ["a"]
ttl = "1h"
"#,
        );
        let err = Profile::load("iba-prod").unwrap_err().to_string();
        assert!(err.contains("extends unknown profile 'nope'"), "{err}");

        // extends: cycle detection
        write(
            r#"
[a]
extends = "b"
secrets = ["x"]
ttl = "1h"

[b]
extends = "a"
secrets = ["x"]
ttl = "1h"
"#,
        );
        let err = Profile::load("a").unwrap_err().to_string();
        assert!(err.contains("inheritance cycle"), "{err}");

        // profiles.d: fully overrides a same-named entry from profiles.toml
        let d_dir = dir.path().join("profiles.d");
        let write_d = |filename: &str, body: &str| {
            std::fs::create_dir_all(&d_dir).unwrap();
            std::fs::write(d_dir.join(filename), body).unwrap();
        };
        std::fs::remove_dir_all(&d_dir).ok(); // clean slate between scenarios below
        write(
            r#"
[iba]
secrets = ["a", "b"]
ttl = "8h"
"#,
        );
        write_d(
            "local.toml",
            r#"
[iba]
secrets = ["z"]
ttl = "30m"
"#,
        );
        let p = Profile::load("iba").unwrap();
        assert_eq!(p.secrets, vec!["z"]); // profiles.d wins, not merged field-by-field
        assert_eq!(p.ttl, Duration::minutes(30));

        // profiles.d: adds a profile that doesn't exist in profiles.toml at all
        write_d(
            "local.toml",
            r#"
[iba]
secrets = ["z"]
ttl = "30m"

[homelab]
secrets = ["a"]
ttl = "1h"
"#,
        );
        let p = Profile::load("homelab").unwrap();
        assert_eq!(p.secrets, vec!["a"]);

        // profiles.d: same name defined in two different files is rejected
        std::fs::remove_dir_all(&d_dir).ok();
        write_d(
            "a.toml",
            r#"
[iba]
secrets = ["a"]
ttl = "1h"
"#,
        );
        write_d(
            "b.toml",
            r#"
[iba]
secrets = ["b"]
ttl = "1h"
"#,
        );
        let err = Profile::load("iba").unwrap_err().to_string();
        assert!(
            err.contains("defined in multiple profiles.d files"),
            "{err}"
        );

        // profiles.d alone (no profiles.toml) is sufficient
        std::fs::remove_dir_all(&d_dir).ok();
        std::fs::remove_file(dir.path().join("profiles.toml")).ok();
        write_d(
            "local.toml",
            r#"
[solo]
secrets = ["a"]
ttl = "1h"
"#,
        );
        let p = Profile::load("solo").unwrap();
        assert_eq!(p.secrets, vec!["a"]);

        // Neither profiles.toml nor profiles.d present: still a clear error
        std::fs::remove_dir_all(&d_dir).ok();
        let err = Profile::load("solo").unwrap_err().to_string();
        assert!(err.contains("no profiles file"), "{err}");

        unsafe {
            match prev {
                Some(v) => std::env::set_var(CONFIG_DIR_ENV, v),
                None => std::env::remove_var(CONFIG_DIR_ENV),
            }
        }
    }

    #[test]
    fn to_caveats_single_secret_uses_secret_eq() {
        let p = Profile {
            name: "p".into(),
            secrets: vec!["a".into()],
            env: BTreeMap::new(),
            ttl: Duration::hours(1),
            repo: None,
            branch: None,
            agent: None,
        };
        let caveats = p.to_caveats(None);
        assert!(matches!(caveats[0], Caveat::SecretEq(_)));
    }

    #[test]
    fn to_caveats_multi_secret_uses_secrets_in() {
        let p = Profile {
            name: "p".into(),
            secrets: vec!["a".into(), "b".into()],
            env: BTreeMap::new(),
            ttl: Duration::hours(1),
            repo: None,
            branch: None,
            agent: None,
        };
        let caveats = p.to_caveats(None);
        assert!(matches!(caveats[0], Caveat::SecretsIn(_)));
    }

    #[test]
    fn to_caveats_includes_optional_caveats() {
        let p = Profile {
            name: "p".into(),
            secrets: vec!["a".into()],
            env: BTreeMap::new(),
            ttl: Duration::hours(1),
            repo: Some("acme/billing".into()),
            branch: Some("main".into()),
            agent: Some("claude-code".into()),
        };
        let caveats = p.to_caveats(None);
        assert!(caveats.iter().any(|c| matches!(c, Caveat::RepoEq(_))));
        assert!(caveats.iter().any(|c| matches!(c, Caveat::BranchEq(_))));
        assert!(caveats.iter().any(|c| matches!(c, Caveat::AgentEq(_))));
    }

    #[test]
    fn ttl_override_wins() {
        let p = Profile {
            name: "p".into(),
            secrets: vec!["a".into()],
            env: BTreeMap::new(),
            ttl: Duration::hours(8),
            repo: None,
            branch: None,
            agent: None,
        };
        let caveats = p.to_caveats(Some(Duration::minutes(5)));
        let exp = caveats
            .iter()
            .find_map(|c| match c {
                Caveat::ExpiresAt(t) => Some(t),
                _ => None,
            })
            .unwrap();
        // 5m override should be far less than the 8h default
        let delta = (*exp - chrono::Utc::now()).num_seconds();
        assert!((290..=310).contains(&delta), "delta = {delta}");
    }

    #[test]
    fn format_duration_round_trip() {
        assert_eq!(format_duration(Duration::seconds(30)), "30s");
        assert_eq!(format_duration(Duration::minutes(5)), "5m");
        assert_eq!(format_duration(Duration::hours(8)), "8h");
        assert_eq!(format_duration(Duration::days(2)), "2d");
    }
}
