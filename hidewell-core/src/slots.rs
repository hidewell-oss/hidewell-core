//! Fixed-size key-slot table.
//!
//! [`SLOT_COUNT`] slots of [`SLOT_LEN`] bytes each. A used slot is
//! `nonce(12) || AES-256-GCM(KEK_i, payload, aad = "hidewell/slot/v1" || u8(i))`;
//! an unused slot is [`SLOT_LEN`] uniformly random bytes. Unlock trial-decrypts all slots
//! (no early exit). The table is always full and its size constant, so it reveals
//! nothing about the number of vaults. The slot index doubles as the vault's backup
//! manifest entry index.
//!
//! Payload (48 bytes):
//! `version u8 = 1 || flags u8 || zero u16 || anchor_chunk u32le || zero [8] || master_key [32]`.

use crate::crypto::{self, AEAD_OVERHEAD};
use crate::error::{Error, Result};
use crate::kdf;
use crate::secret::SecretKey;

/// Number of key slots.
pub const SLOT_COUNT: usize = 16;
/// Plaintext payload length.
pub const SLOT_PLAIN_LEN: usize = 48;
/// Bytes per slot.
pub const SLOT_LEN: usize = SLOT_PLAIN_LEN + AEAD_OVERHEAD;
/// Bytes of the whole table.
pub const TABLE_LEN: usize = SLOT_COUNT * SLOT_LEN;

const PAYLOAD_VERSION: u8 = 1;
/// Payload flag: this vault is the duress (decoy) vault.
pub const FLAG_DURESS: u8 = 1;

/// Decrypted slot contents.
#[derive(Debug, PartialEq, Eq)]
pub struct SlotPayload {
    /// Flags ([`FLAG_DURESS`]).
    pub flags: u8,
    /// Physical chunk holding the vault's anchor (index root pointer records).
    pub anchor_chunk: u32,
    /// Vault master key.
    pub master_key: SecretKey,
}

impl SlotPayload {
    /// Whether this is the duress vault.
    pub fn is_duress(&self) -> bool {
        self.flags & FLAG_DURESS != 0
    }

    fn encode(&self) -> [u8; SLOT_PLAIN_LEN] {
        let mut b = [0u8; SLOT_PLAIN_LEN];
        b[0] = PAYLOAD_VERSION;
        b[1] = self.flags;
        b[4..8].copy_from_slice(&self.anchor_chunk.to_le_bytes());
        b[16..48].copy_from_slice(self.master_key.expose());
        b
    }

    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != SLOT_PLAIN_LEN
            || b[0] != PAYLOAD_VERSION
            || b[1] & !FLAG_DURESS != 0
            || b[2..4] != [0, 0]
            || b[8..16] != [0; 8]
        {
            return Err(Error::Corrupt);
        }
        Ok(SlotPayload {
            flags: b[1],
            anchor_chunk: u32::from_le_bytes(b[4..8].try_into().expect("4 bytes")),
            master_key: SecretKey::from_slice(&b[16..48]).expect("32 bytes"),
        })
    }
}

fn aad(slot: u8) -> Vec<u8> {
    crypto::label(b"hidewell/slot/v1", &[&[slot]])
}

/// Encrypt a payload for slot `slot` under the per-slot KEK derived from `unlock_key`.
pub fn seal_slot(unlock_key: &SecretKey, slot: u8, payload: &SlotPayload) -> [u8; SLOT_LEN] {
    assert!((slot as usize) < SLOT_COUNT);
    let kek = kdf::slot_kek(unlock_key, slot);
    let mut pt = payload.encode();
    let mut out = [0u8; SLOT_LEN];
    crypto::seal_into(&kek, &aad(slot), &pt, &mut out);
    zeroize::Zeroize::zeroize(&mut pt);
    out
}

/// Fresh random bytes for an unused slot.
pub fn random_slot() -> [u8; SLOT_LEN] {
    crate::rng::array()
}

/// Trial-decrypt every slot of `table` (exactly [`SLOT_COUNT`] attempts, no early exit).
/// Returns the matching slot. More than one match is impossible by construction
/// (creation rejects patterns that already open a slot) and is reported as corruption.
pub fn trial_open(unlock_key: &SecretKey, table: &[u8]) -> Result<Option<(u8, SlotPayload)>> {
    if table.len() != TABLE_LEN {
        return Err(Error::Corrupt);
    }
    let mut found: Option<(u8, SlotPayload)> = None;
    let mut matches = 0usize;
    for i in 0..SLOT_COUNT {
        let kek = kdf::slot_kek(unlock_key, i as u8);
        let bytes = &table[i * SLOT_LEN..(i + 1) * SLOT_LEN];
        if let Ok(pt) = crypto::open(&kek, &aad(i as u8), bytes) {
            matches += 1;
            if let Ok(p) = SlotPayload::decode(&pt) {
                found = Some((i as u8, p));
            }
        }
    }
    match matches {
        0 => Ok(None),
        1 => found.map(Some).ok_or(Error::Corrupt),
        _ => Err(Error::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn table_with(entries: &[(u8, &SecretKey, &SlotPayload)]) -> Vec<u8> {
        let mut t = Vec::with_capacity(TABLE_LEN);
        for _ in 0..SLOT_COUNT {
            t.extend_from_slice(&random_slot());
        }
        for (i, k, p) in entries {
            let i = *i as usize;
            t[i * SLOT_LEN..(i + 1) * SLOT_LEN].copy_from_slice(&seal_slot(k, i as u8, p));
        }
        t
    }

    fn payload(flags: u8, anchor: u32) -> SlotPayload {
        SlotPayload {
            flags,
            anchor_chunk: anchor,
            master_key: SecretKey::random(),
        }
    }

    #[test]
    fn slot_is_bound_to_index() {
        let k = SecretKey::random();
        let p = payload(0, 3);
        let sealed = seal_slot(&k, 2, &p);
        let mut t = table_with(&[]);
        // Same bytes moved to slot 3 must not open.
        t[3 * SLOT_LEN..4 * SLOT_LEN].copy_from_slice(&sealed);
        assert!(trial_open(&k, &t).unwrap().is_none());
        t[2 * SLOT_LEN..3 * SLOT_LEN].copy_from_slice(&sealed);
        assert_eq!(trial_open(&k, &t).unwrap().unwrap().0, 2);
    }

    #[test]
    fn duplicate_match_is_corrupt() {
        let k = SecretKey::random();
        let (a, b) = (payload(0, 1), payload(0, 2));
        let t = table_with(&[(1, &k, &a), (4, &k, &b)]);
        assert_eq!(trial_open(&k, &t).err(), Some(Error::Corrupt));
    }

    proptest! {
        #[test]
        fn trial_decryption_finds_exactly_the_right_slot(
            slots in proptest::sample::subsequence((0u8..16).collect::<Vec<_>>(), 1..6),
            pick in any::<proptest::sample::Index>(),
            duress in any::<bool>(),
            anchor in any::<u32>(),
        ) {
            let keys: Vec<SecretKey> = slots.iter().map(|_| SecretKey::random()).collect();
            let payloads: Vec<SlotPayload> = slots.iter().map(|_| payload(if duress { FLAG_DURESS } else { 0 }, anchor)).collect();
            let entries: Vec<_> = slots.iter().zip(&keys).zip(&payloads).map(|((&s, k), p)| (s, k, p)).collect();
            let t = table_with(&entries);
            let i = pick.index(slots.len());
            let (idx, got) = trial_open(&keys[i], &t).unwrap().unwrap();
            prop_assert_eq!(idx, slots[i]);
            prop_assert_eq!(&got, &payloads[i]);
            prop_assert_eq!(got.is_duress(), duress);
            prop_assert!(trial_open(&SecretKey::random(), &t).unwrap().is_none());
        }
    }
}
