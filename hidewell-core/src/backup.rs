//! Phrase-keyed cloud backup: manifest entries, object naming, sync planning and
//! restore inputs. Core produces and consumes bytes; platforms only transport them.
//!
//! Cloud layout, inside folder [`namespace`]`(backup_pk)`:
//! - `entry-00` … `entry-15`: fixed manifest entries, one per key slot. Entry i is only
//!   ever rewritten by the vault in slot i. Each is
//!   `HPKE-Seal(backup_pk, info = "hidewell/manifest/v1" || u8(i), 128-byte plaintext)`;
//!   unused entries seal 128 random bytes (same size).
//! - chunk objects: immutable raw container chunks (already ciphertext ∪ random), named
//!   `hex(nonce || AES-256-GCM(names_key, u32be(logical) || u64be(version),
//!   aad = "hidewell/objname/v1"))` — only the owning vault can recognise its names.
//!
//! Entry plaintext: `"hidewell/entry/2" (16) || flags || master_key (32) ||
//! root generation u64le || root chunk u32le || block u16le || nblocks u16le ||
//! len u32le || tag (32) || zero padding` to 128 bytes, where
//! `tag = HMAC-SHA256(K_i, "hidewell/entry-tag/v1" || u8(i) || bytes 0..69)` and
//! `K_i = HKDF(recovery_key, "hidewell/entry-auth/v1" || u8(i))`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::crypto;
use crate::device::DeviceInner;
use crate::error::{Error, Result};
use crate::index::{BlobRef, RootPtr};
use crate::phrase::{BackupKeypair, RecoveryPhrase, seal_to_backup_key};
use crate::secret::SecretKey;
use crate::slots::SLOT_COUNT;
use crate::vault::{VaultKeys, VaultState};

const ENTRY_MARKER: &[u8; 16] = b"hidewell/entry/2";
/// Sealed (HPKE) manifest entry length.
pub const ENTRY_SEALED_LEN: usize = crate::phrase::HPKE_OVERHEAD + ENTRY_PLAIN_LEN;
/// Local (device-key-wrapped) manifest entry length in the superblock.
pub const LOCAL_ENTRY_LEN: usize = ENTRY_SEALED_LEN + crypto::AEAD_OVERHEAD;
/// Manifest entry plaintext length.
pub const ENTRY_PLAIN_LEN: usize = 128;

/// Fetches backup objects by name (platform callback; e.g. iCloud Drive / Google Drive).
pub trait ObjectSource: Send + Sync {
    /// Object bytes, or [`Error::NotFound`].
    fn get(&self, name: &str) -> Result<Vec<u8>>;
}

/// One backup operation, executed in plan order.
#[derive(Clone, PartialEq, Eq)]
pub enum SyncOp {
    /// Upload a new immutable chunk object.
    PutObject {
        /// Object name.
        name: String,
        /// Object bytes (one container chunk).
        data: Vec<u8>,
    },
    /// Overwrite this vault's manifest entry.
    PutEntry {
        /// Entry object name.
        name: String,
        /// Sealed entry.
        data: Vec<u8>,
    },
    /// Delete one of this vault's superseded chunk objects.
    DeleteObject {
        /// Object name.
        name: String,
    },
}

impl fmt::Debug for SyncOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SyncOp::PutObject { .. } => "PutObject",
            SyncOp::PutEntry { .. } => "PutEntry",
            SyncOp::DeleteObject { .. } => "DeleteObject",
        })
    }
}

/// Ordered operations; execute sequentially, stop at the first failure.
#[derive(Debug)]
pub struct SyncPlan {
    /// Operations in order.
    pub ops: Vec<SyncOp>,
    entry_root: Option<RootPtr>,
    /// For a vault-deletion plan: the slot whose reservation is released by
    /// `Device::confirm_vault_deleted` once the plan has run.
    deleted_slot: Option<u8>,
}

impl SyncPlan {
    pub(crate) fn entry_root(&self) -> Option<RootPtr> {
        self.entry_root
    }

    pub(crate) fn deleted_slot(&self) -> Option<u8> {
        self.deleted_slot
    }

    /// Nothing to do.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    b.iter()
        .flat_map(|&x| [D[(x >> 4) as usize] as char, D[(x & 15) as usize] as char])
        .collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(v(p[0])? << 4 | v(p[1])?))
        .collect()
}

/// Cloud folder name for a backup public key.
pub fn namespace(backup_pk: &[u8; 32]) -> String {
    hex(&crypto::sha256(&[b"hidewell/backup-ns/v1", backup_pk])[..16])
}

/// Name of manifest entry `index`.
pub fn entry_object_name(index: u8) -> String {
    format!("entry-{index:02}")
}

pub(crate) fn entry_info(index: u8) -> Vec<u8> {
    crypto::label(b"hidewell/manifest/v1", &[&[index]])
}

/// A filler manifest entry (HPKE seal of random bytes).
pub(crate) fn filler_entry(pk: &[u8; 32], index: u8) -> Result<Vec<u8>> {
    let mut junk = [0u8; ENTRY_PLAIN_LEN];
    crate::rng::fill_os(&mut junk);
    seal_to_backup_key(pk, &entry_info(index), &junk)
}

fn entry_tag(auth: &SecretKey, index: u8, body: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac =
        <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(auth.expose()).expect("any key length");
    mac.update(b"hidewell/entry-tag/v1");
    mac.update(&[index]);
    mac.update(body);
    mac.finalize().into_bytes().into()
}

/// Seal a real, authenticated entry.
pub(crate) fn seal_entry(
    pk: &[u8; 32],
    index: u8,
    flags: u8,
    master: &SecretKey,
    root: RootPtr,
    auth: &SecretKey,
) -> Result<Vec<u8>> {
    let mut p = zeroize::Zeroizing::new([0u8; ENTRY_PLAIN_LEN]);
    p[..16].copy_from_slice(ENTRY_MARKER);
    p[16] = flags;
    p[17..49].copy_from_slice(master.expose());
    p[49..57].copy_from_slice(&root.generation.to_le_bytes());
    p[57..61].copy_from_slice(&root.blob.chunk.to_le_bytes());
    p[61..63].copy_from_slice(&root.blob.block.to_le_bytes());
    p[63..65].copy_from_slice(&root.blob.nblocks.to_le_bytes());
    p[65..69].copy_from_slice(&root.blob.len.to_le_bytes());
    let tag = entry_tag(auth, index, &p[..69]);
    p[69..101].copy_from_slice(&tag);
    seal_to_backup_key(pk, &entry_info(index), &p[..])
}

/// The entry a vault publishes for its own slot: real and authenticated if it holds its
/// entry key, otherwise filler (such a vault is not backed up).
pub(crate) fn vault_entry(pk: &[u8; 32], s: &VaultState, root: RootPtr) -> Result<Vec<u8>> {
    match s.entry_key(s.slot) {
        Some(k) => seal_entry(pk, s.slot, s.flags, &s.keys.master, root, &k),
        None => filler_entry(pk, s.slot),
    }
}

/// A decrypted real manifest entry.
pub(crate) struct Entry {
    pub(crate) flags: u8,
    pub(crate) master_key: SecretKey,
    pub(crate) root: RootPtr,
}

/// Open entry `index` with the phrase-derived keys. `Ok(None)` for a filler entry;
/// `Corrupt` if it is not authentic under `K_index` (forged).
pub(crate) fn open_entry(
    phrase: &RecoveryPhrase,
    kp: &BackupKeypair,
    index: u8,
    sealed: &[u8],
) -> Result<Option<Entry>> {
    use subtle::ConstantTimeEq;
    let p = kp.open(&entry_info(index), sealed)?;
    if p.len() != ENTRY_PLAIN_LEN {
        return Err(Error::Corrupt);
    }
    if p[..16] != ENTRY_MARKER[..] {
        return Ok(None);
    }
    let tag = entry_tag(&phrase.entry_auth_key(index), index, &p[..69]);
    if !bool::from(tag.ct_eq(&p[69..101])) || p[101..].iter().any(|&b| b != 0) {
        return Err(Error::Corrupt);
    }
    let u16_at = |o: usize| u16::from_le_bytes([p[o], p[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes(p[o..o + 4].try_into().expect("4"));
    Ok(Some(Entry {
        flags: p[16] & crate::slots::FLAG_DURESS,
        master_key: SecretKey::from_slice(&p[17..49]).expect("32"),
        root: RootPtr {
            generation: u64::from_le_bytes(p[49..57].try_into().expect("8")),
            blob: BlobRef {
                chunk: u32_at(57),
                block: u16_at(61),
                nblocks: u16_at(63),
                len: u32_at(65),
            },
        },
    }))
}

/// Read all 16 manifest entries with the phrase; returns the indices of real,
/// authentic entries. A missing entry is `BackupIncomplete` (never assumed filler: that
/// could free a hidden vault's slot); a forged one is `Corrupt`.
pub fn scan(phrase: &RecoveryPhrase, source: &dyn ObjectSource) -> Result<Vec<u8>> {
    let kp = phrase.backup_keypair();
    let mut out = Vec::new();
    for i in 0..SLOT_COUNT as u8 {
        let bytes = match source.get(&entry_object_name(i)) {
            Ok(b) => b,
            Err(Error::NotFound) => return Err(Error::BackupIncomplete),
            Err(e) => return Err(e),
        };
        if open_entry(phrase, &kp, i, &bytes)?.is_some() {
            out.push(i);
        }
    }
    Ok(out)
}

fn name_aad() -> &'static [u8] {
    b"hidewell/objname/v1"
}

fn object_name(keys: &VaultKeys, logical: u32, version: u64) -> String {
    let mut pt = [0u8; 12];
    pt[..4].copy_from_slice(&logical.to_be_bytes());
    pt[4..].copy_from_slice(&version.to_be_bytes());
    hex(&crypto::seal(&keys.names, name_aad(), &pt))
}

fn decode_name(keys: &VaultKeys, name: &str) -> Option<(u32, u64)> {
    let raw = unhex(name)?;
    if raw.len() != 12 + crypto::AEAD_OVERHEAD {
        return None;
    }
    let pt = crypto::open(&keys.names, name_aad(), &raw).ok()?;
    Some((
        u32::from_be_bytes(pt[..4].try_into().ok()?),
        u64::from_be_bytes(pt[4..].try_into().ok()?),
    ))
}

/// This vault's objects in `listing`: (logical, version) → name (first occurrence).
pub(crate) fn our_objects(keys: &VaultKeys, listing: &[String]) -> BTreeMap<(u32, u64), String> {
    let mut m = BTreeMap::new();
    for n in listing {
        if let Some(k) = decode_name(keys, n) {
            m.entry(k).or_insert_with(|| n.clone());
        }
    }
    m
}

/// Build a sync plan (see [`crate::Vault::sync_plan`]).
pub(crate) fn plan(
    s: &VaultState,
    d: &DeviceInner,
    listing: &[String],
    max_puts: usize,
) -> Result<SyncPlan> {
    if s.entry_key(s.slot).is_none() {
        // No entry key: this vault cannot publish an authentic entry, so it is not
        // backed up.
        return Ok(SyncPlan {
            ops: Vec::new(),
            entry_root: None,
            deleted_slot: None,
        });
    }
    let needed: BTreeSet<(u32, u64)> = s.chunk_versions().into_iter().collect();
    let mut present = BTreeSet::new();
    let mut deletes = Vec::new();
    for n in listing {
        if let Some(k) = decode_name(&s.keys, n) {
            // Keep one copy of each needed object; everything else of ours is superseded.
            if needed.contains(&k) && present.insert(k) {
                continue;
            }
            deletes.push(SyncOp::DeleteObject { name: n.clone() });
        }
    }
    let missing: Vec<(u32, u64)> = needed.difference(&present).copied().collect();
    let mut ops = Vec::new();
    for &(l, v) in missing.iter().take(max_puts) {
        ops.push(SyncOp::PutObject {
            name: object_name(&s.keys, l, v),
            data: s.read_physical_chunk(d, l)?,
        });
    }
    if missing.len() > max_puts {
        // Partial upload: the uploaded entry still references the old objects, so
        // neither the entry nor any deletion may happen yet.
        return Ok(SyncPlan {
            ops,
            entry_root: None,
            deleted_slot: None,
        });
    }
    let root = s.root_ptr().ok_or(Error::Corrupt)?;
    let mut entry_root = None;
    if s.uploaded != Some(root) {
        ops.push(SyncOp::PutEntry {
            name: entry_object_name(s.slot),
            data: vault_entry(&d.state.backup_pk, s, root)?,
        });
        entry_root = Some(root);
    }
    // Deletes come last: by then the cloud entry references only `needed` objects.
    ops.extend(deletes);
    Ok(SyncPlan {
        ops,
        entry_root,
        deleted_slot: None,
    })
}

/// Cloud cleanup for a deleted vault: overwrite its entry with a filler seal first
/// (privacy-critical), then delete all of its objects.
pub(crate) fn delete_plan(s: &VaultState, d: &DeviceInner, listing: &[String]) -> Result<SyncPlan> {
    let mut ops = vec![SyncOp::PutEntry {
        name: entry_object_name(s.slot),
        data: filler_entry(&d.state.backup_pk, s.slot)?,
    }];
    ops.extend(
        listing
            .iter()
            .filter(|n| decode_name(&s.keys, n).is_some())
            .map(|n| SyncOp::DeleteObject { name: n.clone() }),
    );
    Ok(SyncPlan {
        ops,
        entry_root: None,
        deleted_slot: Some(s.slot),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex(&b), "0001abff");
        assert_eq!(unhex("0001abff").unwrap(), b);
        assert!(unhex("0g").is_none());
        assert!(unhex("abc").is_none());
    }

    #[test]
    fn names_are_private_to_the_vault() {
        let a = VaultKeys::derive(&SecretKey::random());
        let b = VaultKeys::derive(&SecretKey::random());
        let n = object_name(&a, 7, 42);
        assert_eq!(n.len(), 80);
        assert_eq!(decode_name(&a, &n), Some((7, 42)));
        assert_eq!(decode_name(&b, &n), None);
        assert_ne!(n, object_name(&a, 7, 42), "names are randomised");
    }

    #[test]
    fn entries_roundtrip_and_filler_is_recognised() {
        let phrase = RecoveryPhrase::generate();
        let kp = phrase.backup_keypair();
        let mk = SecretKey::random();
        let root = RootPtr {
            generation: 9,
            blob: BlobRef {
                chunk: 3,
                block: 1,
                nblocks: 2,
                len: 300,
            },
        };
        let e = seal_entry(&kp.pk, 4, 1, &mk, root, &phrase.entry_auth_key(4)).unwrap();
        let f = filler_entry(&kp.pk, 5).unwrap();
        assert_eq!(e.len(), f.len(), "real and filler entries have equal size");
        let got = open_entry(&phrase, &kp, 4, &e).unwrap().unwrap();
        assert_eq!(got.master_key, mk);
        assert_eq!(got.root, root);
        assert_eq!(got.flags, 1);
        assert!(open_entry(&phrase, &kp, 5, &f).unwrap().is_none());
        // Entries are bound to their index.
        assert_eq!(open_entry(&phrase, &kp, 3, &e).err(), Some(Error::Corrupt));
        // Someone with only the public key can seal entries but not authenticate them.
        let forged = seal_entry(&kp.pk, 4, 1, &mk, root, &SecretKey::random()).unwrap();
        assert_eq!(
            open_entry(&phrase, &kp, 4, &forged).err(),
            Some(Error::Corrupt)
        );
    }
}
