//! Per-vault encrypted index: data model and (de)serialization.
//!
//! Layout (all inside vault-owned chunks, encrypted under keys derived from the vault
//! master key, see `vault.rs`):
//! - anchor chunk (physical, from the key slot): two fixed-size records A/B
//!   `{generation, root pointer, last uploaded root, logical→physical chunk map}`;
//! - root blob: `{generation, counters, logical chunk versions, page table, albums, tags}`;
//! - page blobs: up to [`PAGE_ITEMS`] items each, keyed by item id ranges;
//! - item content and thumbnail streams: segments of `segment_plain_len` bytes.

use core::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::secret::SecretVec;

/// Items per index page (pages split further if a page exceeds one chunk).
pub const PAGE_ITEMS: usize = 128;
/// "No physical chunk" marker in the anchor map.
pub const NO_CHUNK: u32 = u32::MAX;
/// Index format version.
pub const INDEX_VERSION: u8 = 4;
/// Anchor record format version (independent of the index format).
pub const ANCHOR_VERSION: u8 = 1;
/// Maximum thumbnail size in bytes.
pub const MAX_THUMBNAIL_LEN: usize = 4 * 1024 * 1024;
/// Maximum content size accepted by in-place replacement.
pub const MAX_REPLACE_LEN: usize = 16 * 1024 * 1024;
/// Maximum vault display name length in Unicode scalar values.
pub const MAX_VAULT_NAME_CHARS: usize = 64;
/// Maximum length of an item's opaque `extra` field.
pub const MAX_EXTRA: usize = 4096;
/// Maximum byte length of an item, album or tag name (the common file-system
/// `NAME_MAX`).
pub const MAX_NAME_LEN: usize = 255;
/// Maximum byte length of an item's MIME type (RFC 6838 allows at most 127
/// characters each for type and subtype).
pub const MAX_MIME_LEN: usize = 255;

/// Location of an encrypted blob inside a vault chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    /// Logical chunk id (vault-local).
    pub chunk: u32,
    /// First block.
    pub block: u16,
    /// Number of contiguous blocks.
    pub nblocks: u16,
    /// Sealed length in bytes (≤ nblocks × block size).
    pub len: u32,
}

/// An encrypted segmented byte stream (file content or thumbnail).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Stream {
    /// Plaintext size.
    pub size: u64,
    /// Segments in order.
    pub segments: Vec<BlobRef>,
    /// Written without a known size: segment AADs carry sentinel count/size.
    pub streamed: bool,
}

/// An item record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Item {
    /// Item id (monotonic per vault).
    pub id: u64,
    /// File name.
    pub name: String,
    /// MIME type.
    pub mime: String,
    /// Creation time (Unix seconds, caller-defined).
    pub created: i64,
    /// Modification time.
    pub modified: i64,
    /// Album ids.
    pub albums: Vec<u32>,
    /// Tag ids.
    pub tags: Vec<u32>,
    /// Content stream.
    #[zeroize(skip)]
    pub content: Stream,
    /// Optional thumbnail stream.
    #[zeroize(skip)]
    pub thumbnail: Option<Stream>,
    /// Opaque app metadata (≤ [`MAX_EXTRA`] bytes), e.g. Live Photo pairing.
    pub extra: Vec<u8>,
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Album record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Album {
    /// Id.
    pub id: u32,
    /// Name.
    pub name: String,
    /// Creation time.
    pub created: i64,
}

/// Tag record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Tag {
    /// Id.
    pub id: u32,
    /// Name.
    pub name: String,
}

macro_rules! redacted_debug {
    ($t:ty) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($t))
                    .field("id", &self.id)
                    .finish_non_exhaustive()
            }
        }
    };
}
redacted_debug!(Album);
redacted_debug!(Tag);

/// Link from a real vault to a duress vault it created. Lives only inside the
/// creating vault's encrypted index (and its backup).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DecoyLink {
    /// Link id (per owning vault).
    pub id: u32,
    /// Decoy key slot (= manifest index; preserved by restore).
    pub slot: u8,
    /// Decoy anchor chunk on this device (re-located after restore).
    pub anchor: u32,
    /// Decoy master key.
    pub master_key: [u8; 32],
    /// Cached display name of the decoy.
    pub name: String,
}

redacted_debug!(DecoyLink);

/// A backup entry authentication key `K_i = HKDF(recovery_key, "hidewell/entry-auth/v1"
/// || i)` held by a vault.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntryKey {
    /// Manifest index.
    pub index: u8,
    /// Key.
    pub key: [u8; 32],
}

impl fmt::Debug for EntryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryKey")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// Index page reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRef {
    /// Smallest item id that belongs to this page.
    pub first_id: u64,
    /// Where the page blob is.
    pub blob: BlobRef,
    /// Generation the page was written at (bound into its AAD).
    pub generation: u64,
}

/// Index root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    /// Format version.
    pub version: u8,
    /// Commit generation (bound into AAD; equals the anchor's root pointer generation).
    pub generation: u64,
    /// Next item id.
    pub next_item_id: u64,
    /// Next album id.
    pub next_album_id: u32,
    /// Next tag id.
    pub next_tag_id: u32,
    /// Logical chunk id → content version (generation of last modification); None = unused id.
    pub chunks: Vec<Option<u64>>,
    /// Pages ordered by `first_id`.
    pub pages: Vec<PageRef>,
    /// Albums.
    pub albums: Vec<Album>,
    /// Tags.
    pub tags: Vec<Tag>,
    /// Next decoy link id.
    pub next_decoy_id: u32,
    /// Duress vaults created from this vault.
    pub decoys: Vec<DecoyLink>,
    /// Backup entry authentication keys this vault holds (own, or all 16).
    pub entry_keys: Vec<EntryKey>,
    /// Display name of this vault, empty if unset.
    pub name: String,
}

impl Drop for Root {
    fn drop(&mut self) {
        // Names and keys; the element types also zeroize themselves on drop.
        self.albums.iter_mut().for_each(Zeroize::zeroize);
        self.tags.iter_mut().for_each(Zeroize::zeroize);
        self.decoys.iter_mut().for_each(Zeroize::zeroize);
        self.entry_keys.iter_mut().for_each(Zeroize::zeroize);
        self.name.zeroize();
    }
}

/// Pointer to a committed root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootPtr {
    /// Root generation; also the version of the chunk holding the root.
    pub generation: u64,
    /// Root blob.
    pub blob: BlobRef,
}

/// Anchor record: the device-local commit point of a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRecord {
    /// Format version.
    pub version: u8,
    /// Anchor generation (strictly increasing; the higher valid copy wins).
    pub generation: u64,
    /// Committed root.
    pub root: RootPtr,
    /// Root last confirmed uploaded in this vault's backup manifest entry.
    pub uploaded: Option<RootPtr>,
    /// Logical chunk id → physical chunk ([`NO_CHUNK`] if unused). Device-local; not backed up.
    pub map: Vec<u32>,
}

/// Serialize with postcard.
pub fn to_bytes<T: Serialize>(v: &T) -> SecretVec {
    SecretVec::new(postcard::to_stdvec(v).expect("serialization of in-memory values cannot fail"))
}

/// Deserialize strictly (no trailing bytes).
pub fn from_bytes<T: DeserializeOwned>(b: &[u8]) -> Result<T> {
    let (v, rest) = postcard::take_from_bytes(b).map_err(|_| Error::Corrupt)?;
    if !rest.is_empty() {
        return Err(Error::Corrupt);
    }
    Ok(v)
}

/// Serialize into exactly `len` bytes: `u32le(n) || postcard (n bytes) || zero padding`.
/// The result is only ever stored encrypted, so the padding is not visible.
pub fn to_padded<T: Serialize>(v: &T, len: usize) -> Result<SecretVec> {
    let body = to_bytes(v);
    if body.len() + 4 > len {
        return Err(Error::NoSpace);
    }
    let mut out = SecretVec::new(vec![0u8; len]);
    out[..4].copy_from_slice(&(body.len() as u32).to_le_bytes());
    out[4..4 + body.len()].copy_from_slice(&body);
    Ok(out)
}

/// Inverse of [`to_padded`]; the padding must be zero.
pub fn from_padded<T: DeserializeOwned>(b: &[u8]) -> Result<T> {
    if b.len() < 4 {
        return Err(Error::Corrupt);
    }
    let n = u32::from_le_bytes(b[..4].try_into().expect("4 bytes")) as usize;
    if n > b.len() - 4 || b[4 + n..].iter().any(|&x| x != 0) {
        return Err(Error::Corrupt);
    }
    from_bytes(&b[4..4 + n])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_roundtrip_and_strictness() {
        let r = RootPtr {
            generation: 7,
            blob: BlobRef {
                chunk: 1,
                block: 2,
                nblocks: 3,
                len: 4,
            },
        };
        let b = to_padded(&r, 64).unwrap();
        assert_eq!(b.len(), 64);
        assert_eq!(from_padded::<RootPtr>(&b).unwrap(), r);
        let mut bad = b.to_vec();
        bad[63] = 1;
        assert_eq!(from_padded::<RootPtr>(&bad), Err(Error::Corrupt));
        assert_eq!(to_padded(&r, 4).err(), Some(Error::NoSpace));
    }
}
