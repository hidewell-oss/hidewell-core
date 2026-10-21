#![no_main]
//! `Device::open` and unlock over a mutated copy of a small valid container: overwrite
//! arbitrary byte runs, optionally truncate, then open, unlock and read everything.
//! Must never panic; everything else (Corrupt, Io, WrongPattern) is acceptable.

use std::sync::{Arc, OnceLock};

use arbitrary::Arbitrary;
use hidewell_core::mock::MockOracle;
use hidewell_core::{ContainerConfig, Device, KdfParams, MemStorage, NewItem, Pattern, RecoveryPhrase};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    truncate_to: Option<u32>,
    writes: Vec<(u32, Vec<u8>)>,
}

struct Base {
    bytes: Vec<u8>,
    sealed: Vec<u8>,
    phrase: RecoveryPhrase,
}

fn pattern(i: u8) -> Pattern {
    let strokes: [&[u8]; 2] = [&[7, 0, 11, 22, 13, 4, 8, 15, 21], &[12, 1, 10, 23, 14, 3, 6, 19]];
    Pattern::new(vec![strokes[i as usize].to_vec()]).expect("valid")
}

fn oracle() -> Arc<MockOracle> {
    Arc::new(MockOracle::new([3u8; 32]))
}

/// One vault with an item, album, tag and a managed decoy; built once.
fn base() -> &'static Base {
    static BASE: OnceLock<Base> = OnceLock::new();
    BASE.get_or_init(|| {
        let storage = MemStorage::new();
        let phrase = RecoveryPhrase::from_entropy(&[7u8; 16]).expect("16 bytes");
        let created = Device::create(
            Box::new(storage.clone()),
            oracle(),
            ContainerConfig::tiny(),
            KdfParams::insecure_test_params(),
            &phrase,
            &pattern(0),
        )
        .expect("create");
        let v = created.vault;
        v.import(
            NewItem {
                name: "seed.jpg".into(),
                mime: "image/jpeg".into(),
                ..Default::default()
            },
            &[0x5a; 700],
            Some(b"thumb"),
        )
        .expect("import");
        v.create_album("album", 1).expect("album");
        v.create_tag("tag").expect("tag");
        drop(v.create_vault(&pattern(1), true).expect("decoy"));
        drop(v);
        Base {
            bytes: storage.snapshot(),
            sealed: created.sealed_device_secret,
            phrase,
        }
    })
}

fuzz_target!(|input: Input| {
    let base = base();
    let mut bytes = base.bytes.clone();
    for (offset, run) in input.writes.iter().take(64) {
        let start = (*offset as usize) % bytes.len();
        let end = (start + run.len()).min(bytes.len());
        bytes[start..end].copy_from_slice(&run[..end - start]);
    }
    if let Some(n) = input.truncate_to {
        bytes.truncate((n as usize) % (bytes.len() + 1));
    }
    let Ok(dev) = Device::open(
        Box::new(MemStorage::from_bytes(bytes)),
        oracle(),
        ContainerConfig::tiny(),
        &base.sealed,
    ) else {
        return;
    };
    let _ = dev.failed_attempts();
    let _ = dev.recover_with_phrase(&base.phrase);
    let Ok(vault) = dev.unlock(&pattern(0)) else {
        return;
    };
    if let Ok(items) = vault.list_items() {
        for it in items {
            let _ = vault.read(it.id, 0, it.size);
            let _ = vault.thumbnail(it.id);
        }
    }
    let _ = vault.albums();
    let _ = vault.tags();
    for id in vault.decoy_vaults().unwrap_or_default() {
        let _ = vault.open_managed_decoy(id);
    }
    let _ = vault.sync_plan(&[], 4);
});
