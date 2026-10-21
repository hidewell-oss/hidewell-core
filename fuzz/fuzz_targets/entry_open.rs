#![no_main]
//! Backup manifest entries: arbitrary sealed bytes, and arbitrary plaintext sealed under
//! the backup public key (what anyone with the public key can upload). Must never panic;
//! a forged entry must never open as real.

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use hidewell_core::phrase::BackupKeypair;
use hidewell_core::{RecoveryPhrase, fuzz_api};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    index: u8,
    raw: Vec<u8>,
    plaintext: Vec<u8>,
}

fn keys() -> &'static (RecoveryPhrase, BackupKeypair) {
    static KEYS: OnceLock<(RecoveryPhrase, BackupKeypair)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let phrase = RecoveryPhrase::from_entropy(&[7u8; 16]).expect("16 bytes");
        let kp = phrase.backup_keypair();
        (phrase, kp)
    })
}

fuzz_target!(|input: Input| {
    let (phrase, kp) = keys();
    let _ = fuzz_api::open_entry(phrase, kp, input.index, &input.raw);
    if let Ok(sealed) = fuzz_api::seal_entry_plaintext(&kp.pk, input.index, &input.plaintext) {
        // The fuzzer never holds the phrase-derived entry key, so a real entry can
        // only be produced by the core itself; sealed junk must be filler or Corrupt.
        assert_ne!(
            fuzz_api::open_entry(phrase, kp, input.index, &sealed),
            Ok(true),
            "forged entry authenticated"
        );
    }
});
