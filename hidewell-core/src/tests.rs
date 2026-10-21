//! Internal tests that need access to crate-private state.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use proptest::prelude::*;

use crate::device::Device;
use crate::kdf::KdfParams;
use crate::mock::MockOracle;
use crate::slots::SLOT_COUNT;
use crate::{ContainerConfig, Error, MemStorage, NewItem, Pattern, RecoveryPhrase, Vault};

fn pat(i: usize) -> Pattern {
    let strokes: [&[u8]; 4] = [
        &[7, 0, 11, 22, 13, 4, 8, 15, 21],
        &[12, 1, 10, 23, 14, 3, 6, 19],
        &[2, 13, 20, 11, 4, 17, 5, 16],
        &[24, 13, 2, 9, 20, 7, 18, 1],
    ];
    Pattern::new(vec![strokes[i].to_vec()]).unwrap()
}

fn setup() -> (MemStorage, Device, Vault) {
    let storage = MemStorage::new();
    let c = Device::create(
        Box::new(storage.clone()),
        Arc::new(MockOracle::new([5u8; 32])),
        ContainerConfig::tiny(),
        KdfParams::insecure_test_params(),
        &RecoveryPhrase::generate(),
        &pat(0),
    )
    .unwrap();
    (storage, c.device, c.vault)
}

fn meta(n: &str) -> NewItem {
    NewItem {
        name: n.into(),
        ..Default::default()
    }
}

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn segment_tamper_and_reorder_detected() {
    let (storage, _dev, v) = setup();
    let sp = ContainerConfig::tiny().segment_plain_len() as usize;
    let body = data(3 * sp, 1); // three full, equally sized segments
    let id = v.import(meta("f"), &body, None).unwrap();
    let offs: Vec<(u64, usize)> = v.with_internals(|s, d| {
        s.blob_refs(id)
            .iter()
            .map(|b| (s.blob_abs(d, b), b.len as usize))
            .collect()
    });
    let raw = storage.snapshot();
    let seg = |i: usize| raw[offs[i].0 as usize..offs[i].0 as usize + offs[i].1].to_vec();
    // Swap segments 0 and 1 on disk: both fail (AAD binds the index).
    storage.poke(offs[0].0 as usize, &seg(1));
    storage.poke(offs[1].0 as usize, &seg(0));
    assert_eq!(v.read(id, 0, 1), Err(Error::Corrupt));
    assert_eq!(v.read(id, sp as u64, 1), Err(Error::Corrupt));
    // Untouched segment 2 still reads (random access does not need the others).
    assert_eq!(
        v.read(id, 2 * sp as u64, 5).unwrap(),
        body[2 * sp..2 * sp + 5]
    );
    // Restore, then flip one bit.
    storage.poke(offs[0].0 as usize, &seg(0));
    storage.poke(offs[1].0 as usize, &seg(1));
    assert_eq!(v.read(id, 0, body.len() as u64).unwrap(), body);
    let mut s2 = seg(2);
    s2[20] ^= 1;
    storage.poke(offs[2].0 as usize, &s2);
    assert_eq!(v.read(id, 2 * sp as u64, 1), Err(Error::Corrupt));
    // A segment from another item at the same index is rejected too.
    let id2 = v.import(meta("g"), &data(3 * sp, 2), None).unwrap();
    let o2 = v.with_internals(|s, d| s.blob_abs(d, &s.blob_refs(id2)[0]));
    let raw = storage.snapshot();
    storage.poke(
        offs[0].0 as usize,
        &raw[o2 as usize..o2 as usize + offs[0].1],
    );
    assert_eq!(v.read(id, 0, 1), Err(Error::Corrupt));
}

#[test]
fn replace_content_scrubs_old_segments_and_stays_authenticated() {
    let (storage, _dev, v) = setup();
    let sp = ContainerConfig::tiny().segment_plain_len() as usize;
    let body = data(2 * sp, 1);
    let id = v.import(meta("f"), &body, None).unwrap();
    let other = v.import(meta("g"), &data(sp, 2), None).unwrap();
    let segs = |id| -> Vec<(usize, usize)> {
        v.with_internals(|s, d| {
            s.blob_refs(id)
                .iter()
                .map(|b| (s.blob_abs(d, b) as usize, b.len as usize))
                .collect()
        })
    };
    let old = segs(id);
    let raw = storage.snapshot();
    let old_ct: Vec<Vec<u8>> = old.iter().map(|&(o, l)| raw[o..o + l].to_vec()).collect();
    let edited = data(2 * sp + 3, 3);
    v.replace_content(id, &edited, 9).unwrap();
    // Old ciphertext is gone from the container (scrubbed like delete).
    let raw = storage.snapshot();
    for ct in &old_ct {
        assert!(
            !raw.windows(ct.len()).any(|w| w == &ct[..]),
            "old segment kept"
        );
    }
    assert_eq!(v.read(id, 0, u64::MAX).unwrap(), edited);
    let new = segs(id);
    // An old segment spliced back in is rejected (size is bound into the AAD) ...
    storage.poke(new[0].0, &old_ct[0]);
    assert_eq!(v.read(id, 0, 1), Err(Error::Corrupt));
    // ... as is another item's segment at the same index, and a flipped bit.
    let o = segs(other)[0];
    storage.poke(new[0].0, &raw[o.0..o.0 + o.1]);
    assert_eq!(v.read(id, 0, 1), Err(Error::Corrupt));
    let mut ct = raw[new[1].0..new[1].0 + new[1].1].to_vec();
    ct[20] ^= 1;
    storage.poke(new[1].0, &ct);
    assert_eq!(v.read(id, sp as u64, 1), Err(Error::Corrupt));
    // The unmodified last segment still reads.
    assert_eq!(v.read(id, 2 * sp as u64, 3).unwrap(), edited[2 * sp..]);
}

/// Storage that tears the `fail_at`-th write (writes half, then errors) and fails all
/// later writes: a crash at that point.
struct FaultStorage {
    inner: MemStorage,
    writes: Arc<AtomicU64>,
    fail_at: Arc<AtomicU64>,
}

/// FaultStorage that only starts counting towards a crash once `arm(k)` is called.
fn fault_storage(inner: MemStorage) -> (FaultStorage, impl Fn(u64)) {
    let writes = Arc::new(AtomicU64::new(0));
    let fail_at = Arc::new(AtomicU64::new(u64::MAX));
    let (w, f) = (writes.clone(), fail_at.clone());
    let arm = move |k: u64| f.store(w.load(Ordering::SeqCst) + k, Ordering::SeqCst);
    (
        FaultStorage {
            inner,
            writes,
            fail_at,
        },
        arm,
    )
}

impl crate::Storage for FaultStorage {
    fn len(&self) -> crate::Result<u64> {
        self.inner.len()
    }
    fn read_at(&self, o: u64, b: &mut [u8]) -> crate::Result<()> {
        self.inner.read_at(o, b)
    }
    fn write_at(&mut self, o: u64, d: &[u8]) -> crate::Result<()> {
        let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        let fail_at = self.fail_at.load(Ordering::SeqCst);
        if n == fail_at {
            self.inner.write_at(o, &d[..d.len() / 2])?;
        }
        if n >= fail_at {
            return Err(Error::Io(std::io::ErrorKind::Other));
        }
        self.inner.write_at(o, d)
    }
    fn sync(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

/// Disk-full fault at an absolute file length, including a partial final write.
struct GrowthFaultStorage {
    inner: MemStorage,
    limit: Arc<AtomicU64>,
}

impl crate::Storage for GrowthFaultStorage {
    fn len(&self) -> crate::Result<u64> {
        self.inner.len()
    }
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> crate::Result<()> {
        self.inner.read_at(offset, bytes)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> crate::Result<()> {
        let limit = self.limit.load(Ordering::SeqCst);
        if offset + bytes.len() as u64 > limit {
            let available = limit.saturating_sub(offset) as usize;
            if available > 0 {
                self.inner.write_at(offset, &bytes[..available])?;
            }
            return Err(Error::Io(std::io::ErrorKind::StorageFull));
        }
        self.inner.write_at(offset, bytes)
    }
    fn sync(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

#[test]
fn interrupted_growth_preserves_committed_vault_and_can_resume() {
    let cfg = ContainerConfig::tiny();
    let old_len = cfg.buckets[0];
    let added_len = cfg.buckets[1] - old_len;
    // Fail before any append, inside a chunk, after a complete chunk, and one byte
    // before the next bucket. Every previous commit must remain recoverable.
    for appended in [0, 1, u64::from(cfg.chunk_size) + 17, added_len - 1] {
        let storage = MemStorage::new();
        let limit = Arc::new(AtomicU64::new(u64::MAX));
        let oracle = Arc::new(MockOracle::new([42; 32]));
        let created = Device::create(
            Box::new(GrowthFaultStorage {
                inner: storage.clone(),
                limit: limit.clone(),
            }),
            oracle.clone(),
            cfg.clone(),
            KdfParams::insecure_test_params(),
            &RecoveryPhrase::generate(),
            &pat(0),
        )
        .unwrap();
        let saved = created.vault.import(meta("saved"), b"SAVED", None).unwrap();
        let sealed = created.sealed_device_secret.clone();
        limit.store(old_len + appended, Ordering::SeqCst);
        let large = data(70 * cfg.chunk_size as usize, 3);
        assert_eq!(
            created.vault.import(meta("interrupted"), &large, None),
            Err(Error::Io(std::io::ErrorKind::StorageFull))
        );
        drop(created);

        let device = Device::open(Box::new(storage.clone()), oracle, cfg.clone(), &sealed).unwrap();
        let vault = device.unlock(&pat(0)).unwrap();
        assert_eq!(vault.item_count().unwrap(), 1);
        assert_eq!(vault.read(saved, 0, 5).unwrap(), b"SAVED");
        let imported = vault.import(meta("resumed"), &large, None).unwrap();
        assert_eq!(vault.read(imported, 0, large.len() as u64).unwrap(), large);
        assert_eq!(vault.read(saved, 0, 5).unwrap(), b"SAVED");
        assert_eq!(storage.snapshot().len() as u64, cfg.buckets[1]);
    }
}

#[test]
fn crash_at_every_write_of_a_commit_is_recoverable() {
    let oracle = Arc::new(MockOracle::new([6u8; 32]));
    let storage = MemStorage::new();
    let c = Device::create(
        Box::new(storage.clone()),
        oracle.clone(),
        ContainerConfig::tiny(),
        KdfParams::insecure_test_params(),
        &RecoveryPhrase::generate(),
        &pat(0),
    )
    .unwrap();
    let sealed = c.sealed_device_secret.clone();
    let sp = ContainerConfig::tiny().segment_plain_len() as usize;
    let old = data(2 * sp + 10, 3);
    let new = data(sp + 7, 4);
    let edited = data(3 * sp + 1, 5);
    let old_id = c.vault.import(meta("old"), &old, Some(b"t")).unwrap();
    c.vault.import(meta("doomed"), b"zz", None).unwrap();
    drop(c);
    let base = storage.snapshot();
    let open = |s: Box<dyn crate::Storage>| {
        Device::open(s, oracle.clone(), ContainerConfig::tiny(), &sealed).unwrap()
    };
    let mut k = 1;
    loop {
        let mem = MemStorage::from_bytes(base.clone());
        let (fs, arm) = fault_storage(mem.clone());
        let dev = open(Box::new(fs));
        let v = dev.unlock(&pat(0)).unwrap();
        arm(k);
        // Operations that add an item, delete one (frees + scrubs) and replace the
        // content of another in place.
        let doomed = v.list_items().unwrap()[1].id;
        let r = v
            .import(meta("new"), &new, None)
            .and_then(|_| v.delete_item(doomed))
            .and_then(|_| v.replace_content(old_id, &edited, 9));
        drop(v);
        // Recover from whatever reached the disk.
        let v = open(Box::new(MemStorage::from_bytes(mem.snapshot())))
            .unlock(&pat(0))
            .unwrap();
        let names: Vec<String> = v
            .list_items()
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        assert!(
            [
                vec!["old", "doomed"],
                vec!["old", "doomed", "new"],
                vec!["old", "new"]
            ]
            .iter()
            .any(|w| *w == names),
            "crash at write {k}: {names:?}"
        );
        // The replaced item holds exactly the old or exactly the new content.
        let info = v.item(old_id).unwrap();
        let content = v.read(old_id, 0, u64::MAX).unwrap();
        assert!(
            content == old || (content == edited && names == ["old", "new"]),
            "crash at write {k}: mixed content"
        );
        assert_eq!(info.size, content.len() as u64);
        assert_eq!(v.thumbnail(old_id).unwrap().unwrap(), b"t");
        if let Some(n) = v.list_items().unwrap().iter().find(|i| i.name == "new") {
            assert_eq!(v.read(n.id, 0, new.len() as u64).unwrap(), new);
        }
        // The recovered vault keeps working.
        v.import(meta("after"), b"ok", None).unwrap();
        if r.is_ok() {
            break;
        }
        k += 1;
    }
    assert!(k > 10, "exercised {k} crash points");
}

#[test]
fn crash_during_pattern_change_leaves_exactly_one_pattern() {
    let oracle = Arc::new(MockOracle::new([8u8; 32]));
    let storage = MemStorage::new();
    let c = Device::create(
        Box::new(storage.clone()),
        oracle.clone(),
        ContainerConfig::tiny(),
        KdfParams::insecure_test_params(),
        &RecoveryPhrase::generate(),
        &pat(0),
    )
    .unwrap();
    let sealed = c.sealed_device_secret.clone();
    c.vault.import(meta("x"), b"payload", None).unwrap();
    drop(c);
    let base = storage.snapshot();
    let open = |s: Box<dyn crate::Storage>| {
        Device::open(s, oracle.clone(), ContainerConfig::tiny(), &sealed).unwrap()
    };
    let mut k = 1;
    loop {
        let mem = MemStorage::from_bytes(base.clone());
        let (fs, arm) = fault_storage(mem.clone());
        let dev = open(Box::new(fs));
        let v = dev.unlock(&pat(0)).unwrap();
        arm(k);
        let r = v.change_pattern(&pat(1));
        let dev = open(Box::new(MemStorage::from_bytes(mem.snapshot())));
        let old = dev.unlock(&pat(0)).is_ok();
        let new = dev.unlock(&pat(1)).is_ok();
        assert!(old ^ new, "crash at write {k}: old {old} new {new}");
        if r.is_ok() {
            assert!(new);
            break;
        }
        k += 1;
    }
}

/// Check global invariants: vault chunks allocated and disjoint; returns
/// (allocated non-superblock chunks, vault-owned chunks, total non-superblock chunks).
fn check_alloc(dev: &Device, vaults: &[&Vault]) -> (usize, usize, usize) {
    let mut owned = std::collections::BTreeSet::new();
    for v in vaults {
        for c in v.with_internals(|s, _| s.physical_chunks()) {
            assert!(owned.insert(c), "chunk shared between vaults");
        }
    }
    let d = dev.inner.lock().unwrap();
    let sb = d.cfg.superblock_chunks();
    for &c in &owned {
        assert!(c >= sb && d.is_allocated(c), "vault chunk not allocated");
    }
    let total = (d.state.total_chunks - sb) as usize;
    let alloc = (sb..d.state.total_chunks)
        .filter(|&c| d.is_allocated(c))
        .count();
    (alloc, owned.len(), total)
}

#[test]
fn filler_and_duress_bitmap() {
    let (_storage, dev, a) = setup();
    let (alloc, owned, total) = check_alloc(&dev, &[&a]);
    let filler = alloc - owned;
    assert!(
        filler * 1000 >= total * 50 - 1000 && filler * 1000 <= total * 150,
        "filler {filler}/{total}"
    );
    let b = a.create_vault(&pat(1), false).unwrap();
    let c = a.create_vault(&pat(2), true).unwrap();
    for (i, v) in [&a, &b, &c].iter().enumerate() {
        for k in 0..4 {
            v.import(meta("x"), &data(2000 + 500 * k, i as u8), Some(b"t"))
                .unwrap();
        }
    }
    check_alloc(&dev, &[&a, &b, &c]);
    let reserved = dev.inner.lock().unwrap().state.reserved_slots.count_ones();
    drop((a, b, c));
    let c = dev.unlock(&pat(2)).unwrap();
    let (alloc, owned, total) = check_alloc(&dev, &[&c]);
    let filler = alloc - owned;
    assert!(
        filler * 1000 >= total * 50 - 1000 && filler * 1000 <= total * 150,
        "post-duress filler {filler}/{total}"
    );
    // Slot reservations survive duress, other slots are unrecoverable.
    // (Deletion, in contrast, drops the deleted vault's reservation.)
    assert_eq!(
        dev.inner.lock().unwrap().state.reserved_slots.count_ones(),
        reserved
    );
    assert!(reserved as usize <= SLOT_COUNT);
    // Old handles from before the duress epoch are dead.
    assert_eq!(dev.unlock(&pat(0)).err(), Some(Error::WrongPattern));
    assert_eq!(c.item_count().unwrap(), 4);
}

#[test]
fn explicit_lock_kills_handle() {
    let (_storage, dev, a) = setup();
    a.import(meta("x"), b"y", None).unwrap();
    a.lock();
    assert_eq!(a.item_count(), Err(Error::Locked));
    assert_eq!(dev.unlock(&pat(0)).unwrap().item_count().unwrap(), 1);
}

#[test]
fn stale_handle_after_duress_is_locked() {
    let (_storage, dev, a) = setup();
    let c = a.create_vault(&pat(2), true).unwrap();
    drop(c);
    let _decoy = dev.unlock(&pat(2)).unwrap();
    assert_eq!(a.item_count(), Err(Error::Locked));
    assert_eq!(a.import(meta("x"), b"y", None), Err(Error::Locked));
}

#[test]
fn ten_thousand_items_scale() {
    let (_storage, dev, v) = setup();
    let n = 10_000u64;
    for i in 0..n {
        v.import(meta(&format!("IMG_{i:05}.HEIC")), &[], None)
            .unwrap();
    }
    drop(v);
    let v = dev.unlock(&pat(0)).unwrap();
    let items = v.list_items().unwrap();
    assert_eq!(items.len() as u64, n);
    assert_eq!(items[9_999].name, "IMG_09999.HEIC");
    v.with_internals(|s, _| {
        assert!(s.page_count() >= (n as usize).div_ceil(crate::index::PAGE_ITEMS))
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn random_access_reads_match(
        len in 0usize..6000,
        reads in proptest::collection::vec((0u64..6500, 0u64..3000), 1..12),
    ) {
        let (_s, _d, v) = setup();
        let body = data(len, 9);
        let id = v.import(meta("p"), &body, None).unwrap();
        for (off, l) in reads {
            let start = (off as usize).min(len);
            let end = (off.saturating_add(l) as usize).min(len);
            prop_assert_eq!(v.read(id, off, l).unwrap(), &body[start..end.max(start)]);
        }
    }

    #[test]
    fn replace_content_matches_model(
        sizes in proptest::collection::vec(0usize..3000, 1..4),
        ops in proptest::collection::vec((0usize..4, 0usize..3000), 1..12),
    ) {
        let (_s, dev, v) = setup();
        let mut model: Vec<(u64, Vec<u8>)> = sizes
            .iter()
            .enumerate()
            .map(|(i, &n)| {
                let body = data(n, i as u8);
                (v.import(meta("m"), &body, Some(b"t")).unwrap(), body)
            })
            .collect();
        for (step, (i, n)) in ops.into_iter().enumerate() {
            let k = i % model.len();
            let body = data(n, 100u8.wrapping_add(step as u8));
            v.replace_content(model[k].0, &body, step as i64).unwrap();
            model[k].1 = body;
            check_alloc(&dev, &[&v]);
        }
        drop(v);
        let v = dev.unlock(&pat(0)).unwrap();
        prop_assert_eq!(v.item_count().unwrap(), model.len() as u64);
        for (id, body) in &model {
            prop_assert_eq!(&v.read(*id, 0, u64::MAX).unwrap(), body);
            prop_assert_eq!(v.item(*id).unwrap().size, body.len() as u64);
            prop_assert_eq!(v.thumbnail(*id).unwrap().unwrap(), b"t");
        }
    }

    #[test]
    fn allocation_invariants_under_random_ops(ops in proptest::collection::vec((0usize..2, 0usize..3, 0usize..5000), 1..25)) {
        let (_s, dev, a) = setup();
        let b = a.create_vault(&pat(1), false).unwrap();
        let vaults = [&a, &b];
        let mut live: Vec<Vec<(u64, Vec<u8>)>> = vec![Vec::new(), Vec::new()];
        for (vi, kind, size) in ops {
            let v = vaults[vi];
            if kind < 2 || live[vi].is_empty() {
                let body = data(size, size as u8);
                let id = v.import(meta("r"), &body, (kind == 1).then_some(&b"thumb"[..])).unwrap();
                live[vi].push((id, body));
            } else {
                let k = size % live[vi].len();
                let (id, _) = live[vi].remove(k);
                v.delete_item(id).unwrap();
            }
            check_alloc(&dev, &vaults);
        }
        for (vi, v) in vaults.iter().enumerate() {
            for (id, body) in &live[vi] {
                prop_assert_eq!(&v.read(*id, 0, body.len() as u64).unwrap(), body);
            }
        }
    }
}

/// Oracle that can be made to fail, simulating the app being killed mid-KDF.
struct FlakyOracle {
    inner: MockOracle,
    fail: std::sync::atomic::AtomicBool,
}

impl crate::HardwareOracle for FlakyOracle {
    fn security_level(&self) -> crate::SecurityLevel {
        self.inner.security_level()
    }
    fn clock_sample(&self) -> Result<crate::ClockSample, crate::OracleError> {
        self.inner.clock_sample()
    }
    fn chain_step(&self, input: Vec<u8>) -> Result<Vec<u8>, crate::OracleError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(crate::OracleError::Failed);
        }
        self.inner.chain_step(input)
    }
    fn seal_device_secret(&self, s: Vec<u8>) -> Result<Vec<u8>, crate::OracleError> {
        self.inner.seal_device_secret(s)
    }
    fn open_device_secret(&self, s: Vec<u8>) -> Result<Vec<u8>, crate::OracleError> {
        self.inner.open_device_secret(s)
    }
}

#[test]
fn attempt_is_durable_before_the_kdf() {
    let oracle = Arc::new(FlakyOracle {
        inner: MockOracle::new([9u8; 32]),
        fail: false.into(),
    });
    let storage = MemStorage::new();
    let c = Device::create(
        Box::new(storage.clone()),
        oracle.clone(),
        ContainerConfig::tiny(),
        KdfParams::insecure_test_params(),
        &RecoveryPhrase::generate(),
        &pat(0),
    )
    .unwrap();
    oracle.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        c.vault.create_vault(&pat(1), false),
        Err(Error::Oracle(_))
    ));
    assert!(matches!(c.device.unlock(&pat(1)), Err(Error::Oracle(_))));
    // "Kill" the app: reopen from what is on disk.
    oracle.fail.store(false, Ordering::SeqCst);
    let dev = Device::open(
        Box::new(MemStorage::from_bytes(storage.snapshot())),
        oracle.clone(),
        ContainerConfig::tiny(),
        &c.sealed_device_secret,
    )
    .unwrap();
    assert_eq!(dev.failed_attempts().unwrap(), 2);
}

#[test]
fn matched_pattern_on_unloadable_vault_is_not_a_counted_attempt() {
    let oracle = Arc::new(MockOracle::new([5u8; 32]));
    let storage = MemStorage::new();
    let c = Device::create(
        Box::new(storage.clone()),
        oracle.clone(),
        ContainerConfig::tiny(),
        KdfParams::insecure_test_params(),
        &RecoveryPhrase::generate(),
        &pat(0),
    )
    .unwrap();
    let b = c.vault.create_vault(&pat(1), false).unwrap();
    b.set_wipe_after(2).unwrap();
    let (anchor, chunk_size) = b.with_internals(|s, d| (s.anchor_phys, d.cfg.chunk_size));
    drop(b);
    let before = c.device.failed_attempts().unwrap();
    storage.poke(
        anchor as usize * chunk_size as usize,
        &vec![0u8; chunk_size as usize],
    );
    // The pattern matches its slot but the vault cannot load: not a guess, so it
    // never counts towards the delay or the wipe, and the other vault survives.
    for _ in 0..3 {
        assert_eq!(c.device.unlock(&pat(1)).err(), Some(Error::Corrupt));
    }
    assert_eq!(c.device.failed_attempts().unwrap(), before);
    assert_eq!(c.device.retry_after_seconds().unwrap(), 0);
    let reopened = Device::open(
        Box::new(MemStorage::from_bytes(storage.snapshot())),
        oracle,
        ContainerConfig::tiny(),
        &c.sealed_device_secret,
    )
    .unwrap();
    assert_eq!(reopened.failed_attempts().unwrap(), before);
    assert!(reopened.unlock(&pat(0)).is_ok());
}

#[test]
fn deleted_slot_is_released_only_on_confirm() {
    let (_storage, dev, a) = setup();
    let b = a.create_vault(&pat(1), false).unwrap();
    let reserved = || dev.inner.lock().unwrap().state.reserved_slots.count_ones();
    let before = reserved();
    let plan = b.delete(&[]).unwrap();
    assert_eq!(reserved(), before, "kept until the cloud entry is filler");
    dev.confirm_vault_deleted(&plan).unwrap();
    assert_eq!(reserved(), before - 1);
}

/// Someone with only the backup public key (readable via the device key) and cloud
/// write access cannot plant a duress-flagged entry: the forgery is rejected.
#[test]
fn forged_entry_is_rejected() {
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    struct Cloud(Mutex<BTreeMap<String, Vec<u8>>>);
    impl crate::ObjectSource for Cloud {
        fn get(&self, n: &str) -> crate::Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .get(n)
                .cloned()
                .ok_or(Error::NotFound)
        }
    }
    let phrase = RecoveryPhrase::generate();
    let c = Device::create(
        Box::new(MemStorage::new()),
        Arc::new(MockOracle::new([4u8; 32])),
        ContainerConfig::tiny(),
        KdfParams::insecure_test_params(),
        &phrase,
        &pat(0),
    )
    .unwrap();
    let cloud = Cloud(Mutex::new(c.initial_entries.iter().cloned().collect()));
    let plan = c.vault.sync_plan(&[], 100).unwrap();
    for op in &plan.ops {
        match op {
            crate::SyncOp::PutObject { name, data } | crate::SyncOp::PutEntry { name, data } => {
                cloud.0.lock().unwrap().insert(name.clone(), data.clone());
            }
            crate::SyncOp::DeleteObject { .. } => {}
        }
    }
    let real = crate::backup::scan(&phrase, &cloud).unwrap();
    assert_eq!(real.len(), 1);
    let j = (0..16u8).find(|j| !real.contains(j)).unwrap();
    let pk = phrase.backup_keypair().pk;
    let root = crate::index::RootPtr {
        generation: 1,
        blob: crate::index::BlobRef {
            chunk: 0,
            block: 0,
            nblocks: 1,
            len: 100,
        },
    };
    let forged = crate::backup::seal_entry(
        &pk,
        j,
        crate::slots::FLAG_DURESS,
        &crate::secret::SecretKey::random(),
        root,
        &crate::secret::SecretKey::random(),
    )
    .unwrap();
    cloud
        .0
        .lock()
        .unwrap()
        .insert(crate::backup::entry_object_name(j), forged);
    assert_eq!(crate::backup::scan(&phrase, &cloud), Err(Error::Corrupt));
}

#[test]
fn argon_memory_is_capped() {
    let mut p = KdfParams::insecure_test_params();
    p.argon_m_kib = crate::kdf::MAX_ARGON_M_KIB + 1;
    assert_eq!(p.validate(), Err(Error::InvalidParams));
}
