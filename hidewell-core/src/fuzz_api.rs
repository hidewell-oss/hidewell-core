//! Thin wrappers over crate-private decoders for the libFuzzer targets in `fuzz/`.
//! Compiled only with the `fuzzing` feature (which implies `mock-oracle`, so it can never
//! reach a release build). Nothing here is part of the supported API.

use crate::backup;
use crate::device;
use crate::error::Result;
use crate::index::{self, AnchorRecord, Item, Root};
use crate::phrase::{BackupKeypair, RecoveryPhrase, seal_to_backup_key};

/// Decode a root blob plaintext.
pub fn decode_root(bytes: &[u8]) -> Result<()> {
    index::from_bytes::<Root>(bytes).map(drop)
}

/// Decode a (padded) anchor record plaintext.
pub fn decode_anchor(bytes: &[u8]) -> Result<()> {
    index::from_padded::<AnchorRecord>(bytes).map(drop)
}

/// Decode a page blob plaintext (item list).
pub fn decode_page(bytes: &[u8]) -> Result<()> {
    index::from_bytes::<Vec<Item>>(bytes).map(drop)
}

/// Decode and validate a device state plaintext.
pub fn decode_device_state(bytes: &[u8]) -> Result<()> {
    device::decode_state(bytes).map(drop)
}

/// Open a sealed manifest entry; `Ok(true)` for a real entry, `Ok(false)` for filler.
pub fn open_entry(
    phrase: &RecoveryPhrase,
    kp: &BackupKeypair,
    index: u8,
    sealed: &[u8],
) -> Result<bool> {
    backup::open_entry(phrase, kp, index, sealed).map(|e| e.is_some())
}

/// Seal arbitrary bytes as manifest entry `index` (what a cloud writer with the
/// public key can produce), so the post-decryption parser can be reached.
pub fn seal_entry_plaintext(pk: &[u8; 32], index: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_to_backup_key(pk, &backup::entry_info(index), plaintext)
}

#[cfg(test)]
mod seeds {
    //! Writes one valid input per decoder target into `fuzz/seeds/<target>/`.
    //! Run after a format change:
    //! `cargo test -p hidewell-core --features fuzzing -- --ignored write_fuzz_seeds`.

    use std::sync::Arc;

    use crate::device::Device;
    use crate::index;
    use crate::kdf::KdfParams;
    use crate::mock::MockOracle;
    use crate::vault::VaultState;
    use crate::{ContainerConfig, MemStorage, NewItem, Pattern, RecoveryPhrase};

    fn save(target: &str, bytes: &[u8]) {
        let dir = format!("{}/../fuzz/seeds/{target}", env!("CARGO_MANIFEST_DIR"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/seed"), bytes).unwrap();
    }

    #[test]
    #[ignore = "writes fuzz seed files; run after a format change"]
    fn write_fuzz_seeds() {
        let pattern = Pattern::new(vec![vec![7, 0, 11, 22, 13, 4, 8, 15, 21]]).unwrap();
        save("pattern_decode", &pattern.encode());
        let phrase = RecoveryPhrase::from_entropy(&[7u8; 16]).unwrap();
        let c = Device::create(
            Box::new(MemStorage::new()),
            Arc::new(MockOracle::new([3u8; 32])),
            ContainerConfig::tiny(),
            KdfParams::insecure_test_params(),
            &phrase,
            &pattern,
        )
        .unwrap();
        let v = c.vault;
        v.import(
            NewItem {
                name: "seed.jpg".into(),
                mime: "image/jpeg".into(),
                ..Default::default()
            },
            b"seed content",
            Some(b"thumb"),
        )
        .unwrap();
        v.create_album("album", 1).unwrap();
        v.create_tag("tag").unwrap();
        v.with_internals(|s, d| {
            let (root, page) = s.encoded_root_and_page();
            save("root_decode", &root);
            save("page_decode", &page);
            let anchor = VaultState::read_anchor(d, &s.keys, s.anchor_phys).unwrap();
            save(
                "anchor_decode",
                &index::to_padded(&anchor, d.cfg.anchor_plain_len()).unwrap(),
            );
            save(
                "device_state_decode",
                &index::to_padded(&d.state, d.cfg.device_state_plain_len()).unwrap(),
            );
        });
        // A 128-byte real-entry plaintext for the seal-then-open path.
        let mut entry = [0u8; 128];
        entry[..16].copy_from_slice(b"hidewell/entry/2");
        save("entry_open", &entry);
    }
}
