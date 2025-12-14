// Stronghold Excavator - Minimal read-only extraction tool
// Pure stable Rust, no mlock/mprotect security features

mod crypto;
mod lz4;
mod types;

pub use types::*;

use crypto::{age_decrypt, xchacha_decrypt, CryptoError};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

/// Magic bytes for Stronghold snapshot files
const MAGIC: [u8; 5] = [0x50, 0x41, 0x52, 0x54, 0x49]; // "PARTI"
/// Version 3 bytes
const VERSION_V3: [u8; 2] = [0x03, 0x00];

#[derive(Debug, Error)]
pub enum ExcavatorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid snapshot file: not a stronghold snapshot")]
    InvalidFile,

    #[error("Unsupported version: expected {expected:?}, found {found:?}")]
    UnsupportedVersion { expected: [u8; 2], found: [u8; 2] },

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Decompression error: {0}")]
    Decompress(#[from] lz4::Lz4DecodeError),

    #[error("Deserialization error: {0}")]
    Deserialize(#[from] bincode::Error),

    #[error("Client not found: {0:?}")]
    ClientNotFound(ClientId),

    #[error("Vault not found: {0:?}")]
    VaultNotFound(VaultId),

    #[error("Record not found: {0:?}")]
    RecordNotFound(RecordId),

    #[error("Invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
}

/// Maximum Age work factor to accept (prevents DoS)
const MAX_WORK_FACTOR: u8 = 22;

/// Excavator for reading Stronghold snapshot files
pub struct Excavator {
    state: SnapshotState,
}

impl Excavator {
    /// Open a snapshot file with a 32-byte key (Blake2b hash of password)
    pub fn open<P: AsRef<Path>>(path: P, key: &[u8; 32]) -> Result<Self, ExcavatorError> {
        let mut file = File::open(path)?;

        // Check magic bytes
        let mut magic = [0u8; 5];
        file.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(ExcavatorError::InvalidFile);
        }

        // Check version
        let mut version = [0u8; 2];
        file.read_exact(&mut version)?;
        if version != VERSION_V3 {
            return Err(ExcavatorError::UnsupportedVersion {
                expected: VERSION_V3,
                found: version,
            });
        }

        // Read encrypted body
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)?;

        // Age decrypt
        let compressed = age_decrypt(key, MAX_WORK_FACTOR, &encrypted)?;

        // LZ4 decompress
        let serialized = lz4::decompress(&compressed)?;

        // Deserialize
        let state: SnapshotState = bincode::deserialize(&serialized)?;

        Ok(Excavator { state })
    }

    /// Open with a password (will hash with Blake2b)
    pub fn open_with_password<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Self, ExcavatorError> {
        use iota_crypto::hashes::{blake2b::Blake2b256, Digest};

        let mut hasher = Blake2b256::new();
        hasher.update(password);
        let key: [u8; 32] = hasher.finalize().into();

        Self::open(path, &key)
    }

    /// List all client IDs in the snapshot
    pub fn clients(&self) -> Vec<ClientId> {
        self.state.0.keys().copied().collect()
    }

    /// Get client state by ID
    pub fn get_client(&self, client_id: ClientId) -> Option<&ClientState> {
        self.state.0.get(&client_id)
    }

    /// List all vault IDs for a client
    pub fn vaults(&self, client_id: ClientId) -> Result<Vec<VaultId>, ExcavatorError> {
        let (_, db, _) = self.state.0.get(&client_id)
            .ok_or(ExcavatorError::ClientNotFound(client_id))?;
        Ok(db.vaults.keys().copied().collect())
    }

    /// List all record IDs in a vault
    pub fn records(&self, client_id: ClientId, vault_id: VaultId) -> Result<Vec<RecordId>, ExcavatorError> {
        let (_, db, _) = self.state.0.get(&client_id)
            .ok_or(ExcavatorError::ClientNotFound(client_id))?;
        let vault = db.vaults.get(&vault_id)
            .ok_or(ExcavatorError::VaultNotFound(vault_id))?;
        Ok(vault.entries.keys().map(|&id| RecordId(id)).collect())
    }

    /// Extract a secret from a vault record
    /// Returns the decrypted blob data
    pub fn extract_secret(
        &self,
        client_id: ClientId,
        vault_id: VaultId,
        record_id: RecordId,
    ) -> Result<ExtractedSecret, ExcavatorError> {
        let (keys, db, _) = self.state.0.get(&client_id)
            .ok_or(ExcavatorError::ClientNotFound(client_id))?;

        let vault = db.vaults.get(&vault_id)
            .ok_or(ExcavatorError::VaultNotFound(vault_id))?;

        let record = vault.entries.get(&record_id.0)
            .ok_or(ExcavatorError::RecordNotFound(record_id))?;

        // Get the vault key
        let vault_key = keys.get(&vault_id)
            .ok_or(ExcavatorError::VaultNotFound(vault_id))?;

        // Decrypt the transaction metadata to get blob_id and hint
        let tx_plain = xchacha_decrypt(&vault_key.bytes, record.id.as_ref(), &record.data.0)?;
        let tx = DataTransaction::from_bytes(&tx_plain)
            .ok_or_else(|| ExcavatorError::Deserialize(
                bincode::Error::from(bincode::ErrorKind::Custom("Invalid transaction".into()))
            ))?;

        // Decrypt the blob
        let blob_plain = xchacha_decrypt(&vault_key.bytes, tx.blob.as_ref(), record.blob.as_ref())?;

        // Truncate to actual length
        let actual_len = tx.len.u64() as usize;
        let data = if blob_plain.len() > actual_len {
            blob_plain[..actual_len].to_vec()
        } else {
            blob_plain
        };

        Ok(ExtractedSecret {
            record_id,
            hint: tx.record_hint,
            data,
        })
    }

    /// Extract all secrets from all vaults for a client
    pub fn extract_all(&self, client_id: ClientId) -> Result<Vec<ExtractedSecret>, ExcavatorError> {
        let mut secrets = Vec::new();

        for vault_id in self.vaults(client_id)? {
            for record_id in self.records(client_id, vault_id)? {
                match self.extract_secret(client_id, vault_id, record_id) {
                    Ok(secret) => secrets.push(secret),
                    Err(e) => {
                        // Skip revoked or corrupted records
                        eprintln!("Warning: failed to extract {:?}: {}", record_id, e);
                    }
                }
            }
        }

        Ok(secrets)
    }

    /// Get the store/cache for a client
    pub fn get_store(&self, client_id: ClientId) -> Result<&Cache, ExcavatorError> {
        let (_, _, cache) = self.state.0.get(&client_id)
            .ok_or(ExcavatorError::ClientNotFound(client_id))?;
        Ok(cache)
    }
}

/// An extracted secret with metadata
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExtractedSecret {
    #[serde(serialize_with = "serialize_record_id")]
    pub record_id: RecordId,
    #[serde(serialize_with = "serialize_hint")]
    pub hint: RecordHint,
    #[serde(serialize_with = "serialize_data")]
    pub data: Vec<u8>,
}

fn serialize_record_id<S>(id: &RecordId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(&id.0 .0))
}

fn serialize_hint<S>(hint: &RecordHint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match hint.as_str() {
        Some(s) => serializer.serialize_str(s),
        None => serializer.serialize_str(&format!("0x{}", hint.as_hex())),
    }
}

fn serialize_data<S>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match std::str::from_utf8(data) {
        Ok(s) => serializer.serialize_str(s),
        Err(_) => serializer.serialize_str(&hex::encode(data)),
    }
}

impl ExtractedSecret {
    /// Try to interpret data as UTF-8 string
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.data).ok()
    }

    /// Get data as hex string
    pub fn as_hex(&self) -> String {
        hex::encode(&self.data)
    }
}
