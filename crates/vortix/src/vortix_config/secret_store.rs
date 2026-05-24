//! `SecretStore` trait + `LayeredSecretStore` (plan #006 U3).
//!
//! OS-keyring-first with an AES-256-GCM + argon2id encrypted-file fallback
//! for headless environments. The trait is sync today (no I/O blocking
//! concerns at the call sites we have in scope); plan #005's async engine
//! migration can wrap it later.
//!
//! Secrets are typed (`Secret(Vec<u8>)`) with `Zeroize + ZeroizeOnDrop` so
//! they zero their memory on drop. `Debug` is implemented manually to
//! redact the byte content.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Argon2, Params};
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Tag for which backend owns a [`SecretRef`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackendTag {
    Keyring,
    EncryptedFile,
}

/// Reference to a stored secret. Sidecars persist these; the actual bytes
/// stay in the backend until [`SecretStore::get`] materialises them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub backend: SecretBackendTag,
    pub id: String,
}

impl SecretRef {
    #[must_use]
    pub fn new(backend: SecretBackendTag, id: impl Into<String>) -> Self {
        Self {
            backend,
            id: id.into(),
        }
    }
}

/// Owned secret bytes. Implements `Zeroize` + `ZeroizeOnDrop`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(pub Vec<u8>);

impl Secret {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<{} bytes redacted>)", self.0.len())
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Errors returned by [`SecretStore`] implementations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretStoreError {
    #[error("secret {0:?} not found")]
    NotFound(SecretRef),
    #[error("no passphrase available — set $VORTIX_PASSPHRASE or run interactively")]
    PassphraseRequired,
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("encrypted-file I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("decrypt failed (wrong passphrase, corrupted file, or tampered ciphertext)")]
    DecryptFailed,
    #[error("invalid base64 in secret payload: {0}")]
    BadBase64(#[from] base64::DecodeError),
    #[error("serialisation error: {0}")]
    Serde(String),
}

/// The secret-storage port.
pub trait SecretStore: Send + Sync {
    /// Materialise the secret pointed to by `secret_ref`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::NotFound`] if the entry is missing, or
    /// backend-specific errors on decryption / keyring failures.
    fn get(&self, secret_ref: &SecretRef) -> Result<Secret, SecretStoreError>;

    /// Store `secret` under `id`. Returns the [`SecretRef`] callers persist
    /// in their sidecars.
    ///
    /// # Errors
    ///
    /// Returns backend-specific errors.
    fn set(&self, id: &str, secret: Secret) -> Result<SecretRef, SecretStoreError>;

    /// Delete a single secret.
    ///
    /// # Errors
    ///
    /// Backend-specific.
    fn delete(&self, secret_ref: &SecretRef) -> Result<(), SecretStoreError>;
}

// ───────────────────────────────────────────────────────────────────────────
// Layered store with runtime backend selection
// ───────────────────────────────────────────────────────────────────────────

/// Config governing which backend the layered store chooses.
#[derive(Debug, Clone)]
pub struct SecretStoreConfig {
    /// Where the encrypted-file fallback stores its data.
    pub fallback_path: PathBuf,
    /// Optional explicit passphrase — overrides `VORTIX_PASSPHRASE`.
    pub passphrase: Option<String>,
    /// Force the fallback backend even when keyring is available (useful
    /// for testing / headless).
    pub force_fallback: bool,
}

/// Composite secret store. Picks the backend at construction time.
pub struct LayeredSecretStore {
    inner: Box<dyn SecretStore>,
}

impl std::fmt::Debug for LayeredSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayeredSecretStore").finish_non_exhaustive()
    }
}

impl LayeredSecretStore {
    /// Construct the store. Probes keyring availability unless
    /// `force_fallback = true`. Falls back to the encrypted file when the
    /// keyring is missing or when a passphrase source is explicitly given.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::PassphraseRequired`] when no keyring is
    /// available and no passphrase source is set.
    pub fn new(config: SecretStoreConfig) -> Result<Self, SecretStoreError> {
        if !config.force_fallback && keyring_available() {
            return Ok(Self {
                inner: Box::new(KeyringSecretStore::new("vortix")),
            });
        }
        // Fallback: resolve a passphrase.
        let passphrase = config
            .passphrase
            .clone()
            .or_else(|| std::env::var("VORTIX_PASSPHRASE").ok())
            .ok_or(SecretStoreError::PassphraseRequired)?;
        Ok(Self {
            inner: Box::new(EncryptedFileSecretStore::open(
                config.fallback_path,
                &passphrase,
            )?),
        })
    }

    /// Construct a layered store using only the encrypted-file backend
    /// (useful for tests and explicit headless deployments).
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] from the underlying file backend.
    pub fn encrypted_file(path: PathBuf, passphrase: &str) -> Result<Self, SecretStoreError> {
        Ok(Self {
            inner: Box::new(EncryptedFileSecretStore::open(path, passphrase)?),
        })
    }
}

impl SecretStore for LayeredSecretStore {
    fn get(&self, secret_ref: &SecretRef) -> Result<Secret, SecretStoreError> {
        self.inner.get(secret_ref)
    }
    fn set(&self, id: &str, secret: Secret) -> Result<SecretRef, SecretStoreError> {
        self.inner.set(id, secret)
    }
    fn delete(&self, secret_ref: &SecretRef) -> Result<(), SecretStoreError> {
        self.inner.delete(secret_ref)
    }
}

fn keyring_available() -> bool {
    // Best-effort probe: try to construct an entry and read a sentinel.
    let Ok(entry) = keyring::Entry::new("vortix", "_keyring_probe") else {
        return false;
    };
    // Setting + deleting a sentinel proves the keyring actually accepts
    // writes (some headless boxes can construct an Entry but error on use).
    match entry.set_password("probe") {
        Ok(()) => {
            let _ = entry.delete_credential();
            true
        }
        Err(_) => false,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Keyring backend
// ───────────────────────────────────────────────────────────────────────────

/// OS keyring backend.
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

impl SecretStore for KeyringSecretStore {
    fn get(&self, secret_ref: &SecretRef) -> Result<Secret, SecretStoreError> {
        let entry = keyring::Entry::new(&self.service, &secret_ref.id)
            .map_err(|e| SecretStoreError::Keyring(e.to_string()))?;
        let pwd = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => SecretStoreError::NotFound(secret_ref.clone()),
            other => SecretStoreError::Keyring(other.to_string()),
        })?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(&pwd)?;
        Ok(Secret::new(bytes))
    }

    fn set(&self, id: &str, secret: Secret) -> Result<SecretRef, SecretStoreError> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
        let entry = keyring::Entry::new(&self.service, id)
            .map_err(|e| SecretStoreError::Keyring(e.to_string()))?;
        entry
            .set_password(&encoded)
            .map_err(|e| SecretStoreError::Keyring(e.to_string()))?;
        Ok(SecretRef::new(SecretBackendTag::Keyring, id))
    }

    fn delete(&self, secret_ref: &SecretRef) -> Result<(), SecretStoreError> {
        let entry = keyring::Entry::new(&self.service, &secret_ref.id)
            .map_err(|e| SecretStoreError::Keyring(e.to_string()))?;
        entry
            .delete_credential()
            .map_err(|e| SecretStoreError::Keyring(e.to_string()))?;
        Ok(())
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Encrypted-file backend
// ───────────────────────────────────────────────────────────────────────────

/// AES-256-GCM + argon2id encrypted JSON file. Format:
///
/// ```text
/// <16-byte salt><12-byte nonce><ciphertext>
/// ```
///
/// Plaintext is a serde-JSON `HashMap<String, Vec<u8>>` of secret ids to
/// raw bytes.
#[derive(Debug)]
pub struct EncryptedFileSecretStore {
    path: PathBuf,
    key: [u8; 32],
    salt: [u8; 16],
    cache: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl EncryptedFileSecretStore {
    /// Open (or initialise) the store at `path` using `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::DecryptFailed`] when the passphrase
    /// doesn't match an existing file; I/O errors otherwise.
    pub fn open(path: PathBuf, passphrase: &str) -> Result<Self, SecretStoreError> {
        let (salt, key, cache) = if path.exists() {
            let mut file = std::fs::File::open(&path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            if buf.len() < 16 + 12 {
                return Err(SecretStoreError::DecryptFailed);
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&buf[..16]);
            let nonce_bytes = &buf[16..28];
            let ciphertext = &buf[28..];

            let key = derive_key(passphrase, &salt)?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
            let plaintext = cipher
                .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
                .map_err(|_| SecretStoreError::DecryptFailed)?;
            let cache: HashMap<String, Vec<u8>> = serde_json::from_slice(&plaintext)
                .map_err(|e| SecretStoreError::Serde(e.to_string()))?;
            (salt, key, cache)
        } else {
            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            let key = derive_key(passphrase, &salt)?;
            (salt, key, HashMap::new())
        };
        Ok(Self {
            path,
            key,
            salt,
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    fn flush(&self, cache: &HashMap<String, Vec<u8>>) -> Result<(), SecretStoreError> {
        let plaintext =
            serde_json::to_vec(cache).map_err(|e| SecretStoreError::Serde(e.to_string()))?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|_| SecretStoreError::DecryptFailed)?;

        let mut buf = Vec::with_capacity(16 + 12 + ciphertext.len());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("enc.tmp");
        std::fs::write(&tmp, &buf)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

impl SecretStore for EncryptedFileSecretStore {
    fn get(&self, secret_ref: &SecretRef) -> Result<Secret, SecretStoreError> {
        let cache = self.cache.lock().unwrap();
        cache
            .get(&secret_ref.id)
            .cloned()
            .map(Secret::new)
            .ok_or_else(|| SecretStoreError::NotFound(secret_ref.clone()))
    }

    fn set(&self, id: &str, secret: Secret) -> Result<SecretRef, SecretStoreError> {
        let snapshot = {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(id.to_string(), secret.as_bytes().to_vec());
            cache.clone()
        };
        self.flush(&snapshot)?;
        Ok(SecretRef::new(SecretBackendTag::EncryptedFile, id))
    }

    fn delete(&self, secret_ref: &SecretRef) -> Result<(), SecretStoreError> {
        let snapshot = {
            let mut cache = self.cache.lock().unwrap();
            if cache.remove(&secret_ref.id).is_none() {
                return Err(SecretStoreError::NotFound(secret_ref.clone()));
            }
            cache.clone()
        };
        self.flush(&snapshot)?;
        Ok(())
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], SecretStoreError> {
    let params =
        Params::new(64 * 1024, 3, 4, None).map_err(|e| SecretStoreError::Serde(e.to_string()))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| SecretStoreError::Serde(e.to_string()))?;
    Ok(key)
}

#[allow(dead_code)]
fn _is_path(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_redacts_bytes() {
        let s = Secret::new(b"super-secret".to_vec());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("12 bytes redacted"));
    }

    #[test]
    fn encrypted_file_set_then_get_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secrets.enc");
        let store = EncryptedFileSecretStore::open(path.clone(), "passphrase").unwrap();

        let r = store
            .set("creds/corp", Secret::new(b"my-password".to_vec()))
            .unwrap();
        assert_eq!(r.backend, SecretBackendTag::EncryptedFile);

        let back = store.get(&r).unwrap();
        assert_eq!(back.as_bytes(), b"my-password");
    }

    #[test]
    fn encrypted_file_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secrets.enc");

        {
            let store = EncryptedFileSecretStore::open(path.clone(), "pw").unwrap();
            store
                .set("creds/corp", Secret::new(b"my-password".to_vec()))
                .unwrap();
        }

        let store = EncryptedFileSecretStore::open(path.clone(), "pw").unwrap();
        let r = SecretRef::new(SecretBackendTag::EncryptedFile, "creds/corp");
        let back = store.get(&r).unwrap();
        assert_eq!(back.as_bytes(), b"my-password");
    }

    #[test]
    fn wrong_passphrase_decrypts_to_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secrets.enc");

        {
            let store = EncryptedFileSecretStore::open(path.clone(), "right").unwrap();
            store.set("k", Secret::new(b"v".to_vec())).unwrap();
        }

        let err = EncryptedFileSecretStore::open(path.clone(), "wrong").unwrap_err();
        assert!(matches!(err, SecretStoreError::DecryptFailed));
    }

    #[test]
    fn delete_removes_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secrets.enc");
        let store = EncryptedFileSecretStore::open(path, "pw").unwrap();
        let r = store.set("k", Secret::new(b"v".to_vec())).unwrap();
        store.delete(&r).unwrap();
        let err = store.get(&r).unwrap_err();
        assert!(matches!(err, SecretStoreError::NotFound(_)));
    }
}
