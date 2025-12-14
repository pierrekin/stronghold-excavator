// Stronghold data types - minimal definitions for deserialization
// These mirror the engine/client types but without runtime dependencies

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 24-byte identifier used for various IDs
#[derive(Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Default, Serialize, Deserialize)]
pub struct Id(pub [u8; 24]);

impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Default, Serialize, Deserialize)]
pub struct ClientId(pub Id);

impl std::fmt::Debug for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Client({})", hex::encode(&self.0 .0))
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct VaultId(pub Id);

impl std::fmt::Debug for VaultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vault({})", hex::encode(&self.0 .0))
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ChainId(pub [u8; 24]);

impl std::fmt::Debug for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Chain({})", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for ChainId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct RecordId(pub ChainId);

impl std::fmt::Debug for RecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Record({})", hex::encode(&self.0 .0))
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct BlobId(pub [u8; 24]);

impl std::fmt::Debug for BlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blob({})", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for BlobId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct RecordHint(pub [u8; 24]);

impl RecordHint {
    pub fn as_str(&self) -> Option<&str> {
        let len = self.0.iter().position(|&b| b == 0).unwrap_or(24);
        std::str::from_utf8(&self.0[..len]).ok()
    }

    pub fn as_hex(&self) -> String {
        let len = self.0.iter().position(|&b| b == 0).unwrap_or(24);
        hex::encode(&self.0[..len])
    }
}

impl std::fmt::Debug for RecordHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "Hint({})", s),
            None => write!(f, "Hint(0x{})", self.as_hex()),
        }
    }
}

/// Big-endian encoded u64
#[derive(Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Val(pub [u8; 8]);

impl Val {
    pub fn u64(self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

impl std::fmt::Debug for Val {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.u64())
    }
}

/// Sealed (encrypted) transaction metadata
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedTransaction(pub Vec<u8>);

/// Sealed (encrypted) blob data
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedBlob(pub Vec<u8>);

impl AsRef<[u8]> for SealedBlob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A record in a vault
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: ChainId,
    pub data: SealedTransaction,
    pub revoke: Option<SealedTransaction>,
    pub blob: SealedBlob,
}

/// Vault key - stored as raw bytes in the excavator
/// Format: serialized Buffer<u8> from stronghold-runtime
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultKey {
    // The serialized format is a Buffer<u8> which contains the raw key bytes
    // We need to handle the serde format
    #[serde(with = "vault_key_serde")]
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VaultKey({} bytes)", self.bytes.len())
    }
}

mod vault_key_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)
    }
}

/// A vault containing encrypted records
#[derive(Clone, Serialize, Deserialize)]
pub struct Vault {
    pub key: VaultKey,
    pub entries: HashMap<ChainId, Record>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("key", &self.key)
            .field("entries", &self.entries.len())
            .finish()
    }
}

/// Database view containing vaults
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DbView {
    pub vaults: HashMap<VaultId, Vault>,
}

impl std::fmt::Debug for DbView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbView")
            .field("vaults", &self.vaults.len())
            .finish()
    }
}

/// Cache type (key-value store)
pub type Cache = HashMap<Vec<u8>, Vec<u8>>;

/// Client state: (vault keys map, database, cache)
pub type ClientState = (HashMap<VaultId, VaultKey>, DbView, Cache);

/// Top-level snapshot state
#[derive(Default, Serialize, Deserialize)]
pub struct SnapshotState(pub HashMap<ClientId, ClientState>);

impl std::fmt::Debug for SnapshotState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotState")
            .field("clients", &self.0.len())
            .finish()
    }
}

/// Data transaction structure (for decrypted transaction metadata)
/// Layout: type_id(8) + len(8) + id(24) + blob(24) + hint(24) = 88 bytes
/// But actual size is 112 bytes (TRANSACTION_MAX_BYTES)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DataTransaction {
    pub type_id: Val,
    pub len: Val,
    pub id: ChainId,
    pub blob: BlobId,
    pub record_hint: RecordHint,
}

impl DataTransaction {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 88 {
            return None;
        }

        let type_id = Val(bytes[0..8].try_into().ok()?);
        let len = Val(bytes[8..16].try_into().ok()?);
        let id = ChainId(bytes[16..40].try_into().ok()?);
        let blob = BlobId(bytes[40..64].try_into().ok()?);
        let record_hint = RecordHint(bytes[64..88].try_into().ok()?);

        // type_id should be 1 for DataTransaction
        if type_id.u64() != 1 {
            return None;
        }

        Some(DataTransaction {
            type_id,
            len,
            id,
            blob,
            record_hint,
        })
    }
}
