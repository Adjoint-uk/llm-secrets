//! On-disk encrypted store. See `docs/adr/0003-store-layout.md`.
//!
//! Layout:
//!
//! ```text
//! $LLM_SECRETS_DIR/        (default ~/.llm-secrets/, mode 0700)
//! ├── identity.txt         (age x25519 secret key, mode 0600)
//! └── store.age            (age-encrypted JSON map, mode 0600)
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const STORE_FILENAME: &str = "store.age";
const IDENTITY_FILENAME: &str = "identity.txt";
const STORE_DIR_ENV: &str = "LLM_SECRETS_DIR";

/// Resolve the store directory.
///
/// Priority:
/// 1. `$LLM_SECRETS_DIR` (explicit override, e.g. for tests)
/// 2. `$XDG_DATA_HOME/llm-secrets` (default `~/.local/share/llm-secrets`)
/// 3. `~/.llm-secrets` (legacy fallback — used if it exists and the XDG
///    path does not, so existing installs keep working without migration)
pub fn store_dir() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var(STORE_DIR_ENV)
        && !custom.is_empty()
    {
        return Ok(PathBuf::from(custom));
    }

    let xdg = dirs::data_dir()
        .ok_or_else(|| Error::Other("could not determine data directory".into()))?
        .join("llm-secrets");

    let home = dirs::home_dir()
        .ok_or_else(|| Error::Other("could not determine home directory".into()))?;
    let legacy = home.join(".llm-secrets");

    // XDG path exists → use it (new installs, or already migrated).
    // XDG doesn't exist but legacy does → use legacy (existing installs).
    // Neither exists → use XDG (new install will create it via `init`).
    if xdg.exists() {
        Ok(xdg)
    } else if legacy.exists() {
        Ok(legacy)
    } else {
        Ok(xdg)
    }
}

pub fn identity_path() -> Result<PathBuf> {
    Ok(store_dir()?.join(IDENTITY_FILENAME))
}

pub fn store_path() -> Result<PathBuf> {
    Ok(store_dir()?.join(STORE_FILENAME))
}

/// In-memory representation of the decrypted store. Drop as soon as possible.
#[derive(Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    secrets: BTreeMap<String, String>,
}

impl Store {
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.secrets.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.secrets.contains_key(key)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.secrets.get(key).map(String::as_str)
    }

    pub fn insert(&mut self, key: String, value: String) {
        self.secrets.insert(key, value);
    }

    pub fn remove(&mut self, key: &str) -> Result<String> {
        self.secrets
            .remove(key)
            .ok_or_else(|| Error::KeyNotFound(key.to_string()))
    }
}

/// Initialise a fresh store directory. Fails if an identity already exists.
/// Returns `(identity_path, store_path)`.
pub fn init() -> Result<(PathBuf, PathBuf)> {
    let dir = store_dir()?;
    let id_path = identity_path()?;
    let store_p = store_path()?;

    if id_path.exists() {
        return Err(Error::Other(format!(
            "identity already exists at {} — refusing to overwrite",
            id_path.display()
        )));
    }

    fs::create_dir_all(&dir)?;
    set_dir_perms(&dir)?;

    let identity = Identity::generate();
    let recipient = identity.to_public();

    write_secret_file(&id_path, identity.to_string().expose_secret().as_bytes())?;
    save_store(&Store::default(), &recipient)?;

    Ok((id_path, store_p))
}

/// Load the age identity from disk. Errors if the store has not been
/// initialised.
pub fn load_identity() -> Result<Identity> {
    let path = identity_path()?;
    if !path.exists() {
        return Err(Error::StoreNotFound);
    }
    let contents = fs::read_to_string(&path)?;
    Identity::from_str(contents.trim())
        .map_err(|e| Error::Other(format!("invalid identity file: {e}")))
}

/// Decrypt and parse the store. Errors if not initialised.
pub fn load_store(identity: &Identity) -> Result<Store> {
    let path = store_path()?;
    if !path.exists() {
        return Err(Error::StoreNotFound);
    }
    let ciphertext = fs::read(&path)?;

    let decryptor =
        age::Decryptor::new(&ciphertext[..]).map_err(|e| Error::Decryption(e.to_string()))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| Error::Decryption(e.to_string()))?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| Error::Decryption(e.to_string()))?;

    let store: Store = serde_json::from_slice(&plaintext)
        .map_err(|e| Error::Other(format!("corrupt store: {e}")))?;
    Ok(store)
}

/// Encrypt and write the store atomically.
pub fn save_store(store: &Store, recipient: &Recipient) -> Result<()> {
    let path = store_path()?;
    let plaintext =
        serde_json::to_vec(store).map_err(|e| Error::Other(format!("serialise: {e}")))?;

    let recipients: Vec<&dyn age::Recipient> = vec![recipient];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|e| Error::Encryption(e.to_string()))?;

    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| Error::Encryption(e.to_string()))?;
    writer
        .write_all(&plaintext)
        .map_err(|e| Error::Encryption(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| Error::Encryption(e.to_string()))?;

    write_atomic(&path, &ciphertext)?;
    set_file_perms(&path)?;
    Ok(())
}

/// Rotate the age keypair: decrypt the store under the current identity,
/// generate a fresh identity, re-encrypt the store under the new recipient,
/// and atomically swap both files. Used by `revoke-all --rotate`.
///
/// Crash-safety note: between the two atomic renames there is a microsecond
/// window where store.age is encrypted with the new key but identity.txt
/// still points at the old key (or vice-versa). A crash in that window
/// requires restoring identity.txt from backup. Acceptable for an emergency
/// killswitch operation; documented in `docs/SECURITY-MODEL.md`.
pub fn rotate_age_key() -> Result<()> {
    let old_identity = load_identity()?;
    let store = load_store(&old_identity)?;

    let new_identity = Identity::generate();
    let new_recipient = new_identity.to_public();

    // Order: write the new store first (encrypted under new recipient),
    // then swap the identity. If the second step fails, restoring the
    // identity from backup recovers the store.
    save_store(&store, &new_recipient)?;
    let id_path = identity_path()?;
    write_secret_file(
        &id_path,
        new_identity.to_string().expose_secret().as_bytes(),
    )?;
    Ok(())
}

// ---- atomic file helpers --------------------------------------------------

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
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
    fs::rename(&tmp, path)?;
    Ok(())
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic(path, bytes)?;
    set_file_perms(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_file_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_dir_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_perms(_path: &Path) -> Result<()> {
    Ok(())
}

// ---- masking --------------------------------------------------------------

/// Render a masked preview of a secret. Used by `peek`.
///
/// - Secrets shorter than `2 * chars` are fully masked.
/// - Otherwise: first `chars` + `*`s + last `chars`.
pub fn mask(value: &str, chars: usize) -> String {
    let chars_count = value.chars().count();
    if chars == 0 || chars_count <= chars * 2 {
        return "*".repeat(chars_count.max(4));
    }
    let prefix: String = value.chars().take(chars).collect();
    let suffix: String = value.chars().skip(chars_count - chars).collect();
    format!(
        "{}{}{}",
        prefix,
        "*".repeat(chars_count - 2 * chars),
        suffix
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_long_value() {
        assert_eq!(mask("db_password_hunter2", 4), "db_p***********ter2");
    }

    #[test]
    fn mask_short_value() {
        assert_eq!(mask("abc", 4), "****");
    }

    #[test]
    fn mask_exactly_at_threshold() {
        // len == 2 * chars → fully masked
        assert_eq!(mask("abcdefgh", 4), "********");
    }

    #[test]
    fn store_roundtrip_in_memory() {
        let mut s = Store::default();
        s.insert("a".into(), "1".into());
        s.insert("b".into(), "2".into());
        assert_eq!(s.len(), 2);
        assert!(s.contains("a"));
        assert_eq!(s.get("a"), Some("1"));
        assert_eq!(s.remove("a").unwrap(), "1");
        assert!(!s.contains("a"));
    }
}
