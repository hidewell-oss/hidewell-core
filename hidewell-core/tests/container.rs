//! End-to-end tests through the public API only (what the FFI will wrap).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hidewell_core::backup;
use hidewell_core::mock::MockOracle;
use hidewell_core::{
    ContainerConfig, Device, Error, KdfParams, Label, MemStorage, NewItem, ObjectSource, Pattern,
    RecoveryPhrase, SyncOp, SyncPlan, Vault,
};

// ------------------------------------------------------------------ fixtures

/// In-memory cloud folder.
#[derive(Default)]
struct Cloud {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl Cloud {
    fn listing(&self) -> Vec<String> {
        self.objects.lock().unwrap().keys().cloned().collect()
    }

    fn apply(&self, plan: &SyncPlan) {
        let mut o = self.objects.lock().unwrap();
        for op in &plan.ops {
            match op {
                SyncOp::PutObject { name, data } => {
                    assert!(
                        o.insert(name.clone(), data.clone()).is_none(),
                        "objects are immutable"
                    );
                }
                SyncOp::PutEntry { name, data } => {
                    assert!(o.contains_key(name), "entries pre-exist from setup");
                    o.insert(name.clone(), data.clone());
                }
                SyncOp::DeleteObject { name } => {
                    assert!(o.remove(name).is_some());
                }
            }
        }
    }

    fn put_if_absent(&self, entries: &[(String, Vec<u8>)]) {
        let mut o = self.objects.lock().unwrap();
        for (n, d) in entries {
            o.entry(n.clone()).or_insert_with(|| d.clone());
        }
    }

    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        self.objects.lock().unwrap().clone()
    }
}

impl ObjectSource for Cloud {
    fn get(&self, name: &str) -> hidewell_core::Result<Vec<u8>> {
        self.objects
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or(Error::NotFound)
    }
}

fn sync(v: &Vault, cloud: &Cloud) {
    for _ in 0..1000 {
        let plan = v.sync_plan(&cloud.listing(), 3).unwrap();
        if plan.is_empty() {
            return;
        }
        cloud.apply(&plan);
        v.sync_complete(&plan).unwrap();
    }
    panic!("sync did not converge");
}

fn pat(i: usize) -> Pattern {
    let strokes: [&[u8]; 6] = [
        &[7, 0, 11, 22, 13, 4, 8, 15, 21],
        &[12, 1, 10, 23, 14, 3, 6, 19],
        &[2, 13, 20, 11, 4, 17, 5, 16],
        &[24, 13, 2, 9, 20, 7, 18, 1],
        &[0, 7, 14, 21, 12, 3, 10, 17],
        &[4, 13, 22, 11, 0, 9, 18, 5],
    ];
    Pattern::new(vec![strokes[i].to_vec()]).unwrap()
}

/// Unlock after waiting out any retry delay (tests that make many attempts on purpose).
fn unlock_now(dev: &Device, oracle: &MockOracle, p: &Pattern) -> hidewell_core::Result<Vault> {
    oracle.advance_clock_for_tests(3600);
    dev.unlock(p)
}

fn params() -> KdfParams {
    KdfParams::insecure_test_params()
}

fn meta(name: &str) -> NewItem {
    NewItem {
        name: name.into(),
        mime: "image/heic".into(),
        created: 1_700_000_000,
        modified: 1_700_000_001,
        ..Default::default()
    }
}

/// Deterministic pseudo-random payload.
fn payload(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// name → (content, thumbnail)
type Contents = BTreeMap<String, (Vec<u8>, Option<Vec<u8>>)>;

fn contents(v: &Vault) -> Contents {
    v.list_items()
        .unwrap()
        .into_iter()
        .map(|it| {
            let data = v.read(it.id, 0, it.size).unwrap();
            assert_eq!(data.len() as u64, it.size);
            (it.name.clone(), (data, v.thumbnail(it.id).unwrap()))
        })
        .collect()
}

fn fill(v: &Vault, tag: &str, n: usize, expect: &mut Contents) {
    for i in 0..n {
        let name = format!("{tag}-{i}.heic");
        let data = payload((tag.len() * 1000 + i) as u64, 700 + i * 997);
        let thumb = (i % 2 == 0).then(|| payload(i as u64 + 77, 150));
        v.import(meta(&name), &data, thumb.as_deref()).unwrap();
        expect.insert(name, (data, thumb));
    }
}

struct Setup {
    storage: MemStorage,
    oracle: Arc<MockOracle>,
    device: Device,
    sealed: Vec<u8>,
    phrase_words: Vec<String>,
    cloud: Cloud,
}

fn setup() -> (Setup, Vault) {
    let storage = MemStorage::new();
    let oracle = Arc::new(MockOracle::new([1u8; 32]));
    let phrase = RecoveryPhrase::generate();
    let created = Device::create(
        Box::new(storage.clone()),
        oracle.clone(),
        ContainerConfig::tiny(),
        params(),
        &phrase,
        &pat(0),
    )
    .unwrap();
    let cloud = Cloud::default();
    cloud.put_if_absent(&created.initial_entries);
    (
        Setup {
            storage,
            oracle,
            device: created.device,
            sealed: created.sealed_device_secret,
            phrase_words: phrase.words(),
            cloud,
        },
        created.vault,
    )
}

// ------------------------------------------------------------------ tests

#[test]
fn reopening_a_vault_invalidates_older_snapshots_and_writers() {
    let (s, old) = setup();
    let first = old.import(meta("first"), b"FIRST", None).unwrap();
    let mut pending = old.begin_import(meta("unfinished"), 2000).unwrap();
    pending.write(&vec![7; 1200]).unwrap();
    let finishing = old.begin_import(meta("also-unfinished"), 0).unwrap();

    let current = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(
        old.import(meta("stale"), b"STALE", None),
        Err(Error::Locked)
    );
    assert_eq!(old.read(first, 0, 5), Err(Error::Locked));
    assert_eq!(pending.write(&[0; 800]), Err(Error::Locked));
    assert_eq!(finishing.finish(None), Err(Error::Locked));
    old.lock(); // Locking the stale handle must not lock the current one.
    let second = current.import(meta("second"), b"SECOND", None).unwrap();
    // A stale writer may outlive new commits. Its cleanup must not free blocks
    // now used by the current snapshot.
    drop(pending);
    current.rename_item(second, "second-renamed").unwrap();
    assert_ne!(first, second);
    assert_eq!(current.read(first, 0, 5).unwrap(), b"FIRST");

    let reopened = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(reopened.item_count().unwrap(), 2);
    assert_eq!(reopened.read(first, 0, 5).unwrap(), b"FIRST");
    assert_eq!(reopened.read(second, 0, 6).unwrap(), b"SECOND");
    assert_eq!(current.item_count(), Err(Error::Locked));
}

#[test]
fn reopening_a_managed_decoy_invalidates_only_its_old_handle() {
    let (s, owner) = setup();
    let old_decoy = owner.create_vault(&pat(1), true).unwrap();
    let first = old_decoy.import(meta("first"), b"FIRST", None).unwrap();
    let decoy = owner.open_managed_decoy(1).unwrap();
    assert_eq!(old_decoy.item_count(), Err(Error::Locked));
    let second = decoy.import(meta("second"), b"SECOND", None).unwrap();
    assert_eq!(owner.item_count().unwrap(), 0);
    assert_eq!(decoy.read(first, 0, 5).unwrap(), b"FIRST");

    let duress = s.device.unlock(&pat(1)).unwrap();
    assert_eq!(owner.item_count(), Err(Error::Locked));
    assert_eq!(decoy.item_count(), Err(Error::Locked));
    assert_eq!(duress.read(second, 0, 6).unwrap(), b"SECOND");
}

#[test]
fn phrase_pattern_reset_invalidates_existing_vault_handles() {
    let (s, old) = setup();
    let id = old.import(meta("saved"), b"SAVED", None).unwrap();
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    let index = s.device.recover_with_phrase(&phrase).unwrap()[0].index;
    s.device
        .reset_pattern_with_phrase(&phrase, index, &pat(1))
        .unwrap();
    assert_eq!(old.read(id, 0, 5), Err(Error::Locked));
    assert_eq!(s.device.unlock(&pat(0)).err(), Some(Error::WrongPattern));
    let current = s.device.unlock(&pat(1)).unwrap();
    assert_eq!(current.read(id, 0, 5).unwrap(), b"SAVED");
}

#[test]
fn roots_near_block_boundaries_reopen_and_restore() {
    let (s, v) = setup();
    // The root estimate includes an extra chunk-table entry and is larger than the
    // serialized root. This name puts the estimate across a 256-byte boundary.
    let name = "a".repeat(193);
    let album = v.create_album(&name, 0).unwrap();
    sync(&v, &s.cloud);
    let reopened = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(reopened.albums().unwrap()[0].name, name);
    reopened.rename_label(true, album, "renamed").unwrap();
    assert_eq!(
        s.device.unlock(&pat(0)).unwrap().albums().unwrap()[0].name,
        "renamed"
    );

    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    let indices = backup::scan(&phrase, &s.cloud).unwrap();
    let (restored, _) = Device::create_for_restore(
        Box::new(MemStorage::new()),
        Arc::new(MockOracle::new([9; 32])),
        ContainerConfig::tiny(),
        params(),
        &phrase,
        &indices,
    )
    .unwrap();
    restored
        .restore_vault(&phrase, indices[0], &pat(1), &s.cloud.listing(), &s.cloud)
        .unwrap();
    assert_eq!(
        restored.unlock(&pat(1)).unwrap().albums().unwrap()[0].name,
        name
    );
}

#[test]
fn root_across_production_block_boundary_reopens() {
    let storage = MemStorage::new();
    let mut cfg = ContainerConfig::production();
    // Keep production chunks/blocks, but avoid allocating a GiB in a unit test and
    // skip cover traffic (4 MiB random rewrites per commit).
    cfg.buckets = vec![16 * 1024 * 1024];
    cfg.cover_chunks_per_commit = 0;
    let created = Device::create(
        Box::new(storage),
        Arc::new(MockOracle::new([1; 32])),
        cfg,
        params(),
        &RecoveryPhrase::generate(),
        &pat(0),
    )
    .unwrap();
    // Each album adds about MAX_NAME_LEN + 4 bytes to the root, so the root (and its
    // size estimate, which runs one chunk-table entry ahead) crosses the 64 KiB block
    // boundary inside this range. Reopen after every commit near it.
    let name = "a".repeat(hidewell_core::MAX_NAME_LEN);
    let mut vault = created.vault;
    for i in 0..265u32 {
        vault.create_album(&name, i64::from(i)).unwrap();
        if i >= 240 {
            vault = created.device.unlock(&pat(0)).unwrap();
            let albums = vault.albums().unwrap();
            assert_eq!(albums.len(), i as usize + 1);
            assert_eq!(albums[i as usize].name, name);
        }
    }
}

#[test]
fn name_limits_are_enforced_before_any_change() {
    use hidewell_core::{MAX_MIME_LEN, MAX_NAME_LEN};
    let (s, v) = setup();
    let max = "n".repeat(MAX_NAME_LEN);
    let over = "n".repeat(MAX_NAME_LEN + 1);
    // Two bytes per character: the limit is in bytes, not characters.
    let over_multibyte = "é".repeat(MAX_NAME_LEN / 2 + 1);
    let with_name = |name: &str| NewItem {
        name: name.to_owned(),
        ..meta("x")
    };
    let id = v
        .import(
            NewItem {
                mime: "m".repeat(MAX_MIME_LEN),
                ..with_name(&max)
            },
            b"1",
            None,
        )
        .unwrap();
    let album = v.create_album(&max, 0).unwrap();
    let tag = v.create_tag(&max).unwrap();
    v.rename_item(id, &max).unwrap();
    v.rename_label(true, album, &max).unwrap();
    v.rename_label(false, tag, &max).unwrap();
    for bad in [&over, &over_multibyte] {
        let e = Some(Error::InvalidArgument);
        assert_eq!(v.import(with_name(bad), b"1", None).err(), e);
        assert_eq!(v.begin_import(with_name(bad), 1).err(), e);
        assert_eq!(v.begin_import_unsized(with_name(bad)).err(), e);
        assert_eq!(v.rename_item(id, bad).err(), e);
        assert_eq!(v.create_album(bad, 0).err(), e);
        assert_eq!(v.create_tag(bad).err(), e);
        assert_eq!(v.rename_label(true, album, bad).err(), e);
        assert_eq!(v.rename_label(false, tag, bad).err(), e);
    }
    let long_mime = NewItem {
        mime: "m".repeat(MAX_MIME_LEN + 1),
        ..meta("x")
    };
    assert_eq!(v.import(long_mime, b"1", None), Err(Error::InvalidArgument));
    // Nothing changed, no id was consumed, and the handle is still usable.
    assert_eq!(v.item(id).unwrap().name, max);
    assert_eq!(
        v.albums().unwrap(),
        vec![Label {
            id: album,
            name: max.clone()
        }]
    );
    assert_eq!(
        v.tags().unwrap(),
        vec![Label {
            id: tag,
            name: max.clone()
        }]
    );
    assert_eq!(v.import(meta("after"), b"2", None).unwrap(), id + 1);
    let reopened = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(reopened.item_count().unwrap(), 2);
    assert_eq!(reopened.albums().unwrap()[0].name, max);
}

#[test]
fn reopen_and_unlock_roundtrip() {
    let (s, v) = setup();
    let mut expect = Contents::new();
    fill(&v, "a", 5, &mut expect);
    let album = v.create_album("Holiday", 1).unwrap();
    let tag = v.create_tag("family").unwrap();
    let first = v.list_items().unwrap()[0].id;
    v.set_item_labels(first, &[album], &[tag]).unwrap();
    drop(v);

    let dev = Device::open(
        Box::new(s.storage.clone()),
        s.oracle.clone(),
        ContainerConfig::tiny(),
        &s.sealed,
    )
    .unwrap();
    assert_eq!(
        unlock_now(&dev, &s.oracle, &pat(1)).err(),
        Some(Error::WrongPattern)
    );
    assert_eq!(dev.failed_attempts().unwrap(), 1);
    let v = dev.unlock(&pat(0)).unwrap();
    // A success does not erase earlier failures; time does.
    assert_eq!(dev.failed_attempts().unwrap(), 1);
    s.oracle.advance_clock_for_tests(4 * 3600);
    assert_eq!(dev.failed_attempts().unwrap(), 0);
    assert_eq!(contents(&v), expect);
    assert_eq!(v.item(first).unwrap().albums, vec![album]);
    assert_eq!(v.albums().unwrap()[0].name, "Holiday");
    assert_eq!(v.tags().unwrap()[0].name, "family");

    // Delete, rename, delete label.
    let ids: Vec<u64> = v.list_items().unwrap().iter().map(|i| i.id).collect();
    v.delete_item(ids[1]).unwrap();
    v.rename_item(ids[2], "renamed.jpg").unwrap();
    v.delete_label(true, album).unwrap();
    drop(v);
    let v = dev.unlock(&pat(0)).unwrap();
    assert_eq!(v.item_count().unwrap(), 4);
    assert_eq!(v.item(ids[1]).err(), Some(Error::NotFound));
    assert_eq!(v.item(ids[2]).unwrap().name, "renamed.jpg");
    assert!(v.item(first).unwrap().albums.is_empty());
    assert!(v.albums().unwrap().is_empty());

    // A different hardware oracle (another device) cannot open the device secret.
    let other = Arc::new(MockOracle::new([2u8; 32]));
    assert!(
        Device::open(
            Box::new(s.storage.clone()),
            other,
            ContainerConfig::tiny(),
            &s.sealed
        )
        .is_err()
    );
}

#[test]
fn pattern_rules_at_creation() {
    let (s, v) = setup();
    assert_eq!(
        v.create_vault(&pat(0), false).err(),
        Some(Error::PatternInUse)
    );
    let z = Pattern::from_drawn(vec![vec![0, 4, 20, 24]]).unwrap();
    assert!(v.create_vault(&z, false).is_err());
    let weak = Pattern::new(vec![vec![0, 1, 2]]).unwrap();
    assert!(matches!(
        v.create_vault(&weak, false),
        Err(Error::Pattern(_))
    ));
    // Capacity: at most 16 − (1 + filler reservations) further vaults, then NoFreeSlot.
    let mut made = 0;
    let mut seed = 0u64;
    let err = loop {
        seed += 1;
        let nodes: Vec<u8> = payload(seed, 8).iter().map(|b| b % 25).collect();
        let Ok(p) = Pattern::from_drawn(vec![nodes]) else {
            continue;
        };
        match v.create_vault(&p, false) {
            Ok(_) => made += 1,
            Err(Error::NoFreeSlot) => break Error::NoFreeSlot,
            // Each check is a counted attempt: wait out the delay.
            Err(Error::RetryLater) => s.oracle.advance_clock_for_tests(3600),
            Err(_) => continue,
        }
    };
    assert_eq!(err, Error::NoFreeSlot);
    // 16 slots − vault A − 1..=8 filler reservations.
    assert!((7..=14).contains(&made), "made {made}");
    assert!((7..=14).contains(&made), "made {made}");
}

#[test]
fn streaming_import_and_random_access() {
    let (_s, v) = setup();
    let data = payload(5, 10_000);
    let mut w = v
        .begin_import(meta("video.mov"), data.len() as u64)
        .unwrap();
    for part in data.chunks(333) {
        w.write(part).unwrap();
    }
    let id = w.finish(None).unwrap();
    for (off, len) in [
        (0, 1),
        (995, 3),
        (996, 996),
        (5000, 7000),
        (9999, 10),
        (10_000, 5),
    ] {
        let end = (off + len).min(data.len());
        let want = if off >= data.len() {
            &[][..]
        } else {
            &data[off..end]
        };
        assert_eq!(v.read(id, off as u64, len as u64).unwrap(), want);
    }
    // Size mismatch is rejected.
    let mut w = v.begin_import(meta("x"), 10).unwrap();
    assert_eq!(w.write(&[0; 11]), Err(Error::InvalidArgument));
    w.write(&[0; 5]).unwrap();
    assert_eq!(w.finish(None), Err(Error::InvalidArgument));
    // Empty file.
    let e = v.import(meta("empty"), &[], None).unwrap();
    assert!(v.read(e, 0, 10).unwrap().is_empty());
}

#[test]
fn container_bytes_look_random() {
    let (s, v) = setup();
    let marker_name = "SECRET_FILENAME_MARKER_7f3a.jpg";
    let marker_body = b"PLAINTEXT_CONTENT_MARKER_19c2".repeat(100);
    v.import(meta(marker_name), &marker_body, Some(b"THUMBNAIL_MARKER_x"))
        .unwrap();
    let note = v
        .import(meta("n"), &b"ORIGINAL_NOTE_MARKER_c4".repeat(50), None)
        .unwrap();
    v.replace_content(note, &b"EDITED_NOTE_MARKER_8b".repeat(50), 2)
        .unwrap();
    v.create_album("ALBUM_MARKER_q1", 0).unwrap();
    v.create_tag("TAG_MARKER_z9").unwrap();
    v.set_name("VAULTNAME_MARKER_k2").unwrap();
    v.create_vault(&pat(1), false).unwrap();
    sync(&v, &s.cloud);
    let raw = s.storage.snapshot();
    let needles: [&[u8]; 9] = [
        marker_name.as_bytes(),
        b"PLAINTEXT_CONTENT_MARKER",
        b"THUMBNAIL_MARKER",
        b"ALBUM_MARKER",
        b"TAG_MARKER",
        b"image/heic",
        b"ORIGINAL_NOTE_MARKER",
        b"EDITED_NOTE_MARKER",
        b"VAULTNAME_MARKER",
    ];
    let blobs: Vec<Vec<u8>> = std::iter::once(raw.clone())
        .chain(s.cloud.snapshot().into_values())
        .collect();
    for blob in &blobs {
        for n in needles {
            assert!(
                !blob.windows(n.len()).any(|w| w == n),
                "plaintext marker leaked"
            );
        }
    }
    // Byte histogram of the whole container (superblock included) within 6 sigma, and
    // no run of 16 equal bytes anywhere.
    let mut hist = [0u64; 256];
    for &b in &raw {
        hist[b as usize] += 1;
    }
    let mean = raw.len() as f64 / 256.0;
    let sigma = mean.sqrt();
    for (b, &c) in hist.iter().enumerate() {
        assert!(
            (c as f64 - mean).abs() < 6.0 * sigma,
            "byte {b} count {c} vs mean {mean}"
        );
    }
    assert!(!raw.windows(16).any(|w| w.iter().all(|&x| x == w[0])));
    assert_eq!(raw.len() as u64, ContainerConfig::tiny().buckets[0]);
}

#[test]
fn container_grows_to_next_bucket() {
    let (s, v) = setup();
    let cfg = ContainerConfig::tiny();
    // ~90 chunks worth of data overflows the first 64-chunk bucket.
    let big = payload(9, 90 * 4096);
    v.import(meta("big.bin"), &big, None).unwrap();
    assert_eq!(s.storage.snapshot().len() as u64, cfg.buckets[1]);
    assert_eq!(
        v.read(v.list_items().unwrap()[0].id, 0, big.len() as u64)
            .unwrap(),
        big
    );
    drop(v);
    let dev = Device::open(
        Box::new(s.storage.clone()),
        s.oracle.clone(),
        cfg,
        &s.sealed,
    )
    .unwrap();
    let v = dev.unlock(&pat(0)).unwrap();
    assert_eq!(v.item_count().unwrap(), 1);
}

#[test]
fn wipe_after_failures_destroys_slots() {
    let (s, v) = setup();
    v.set_wipe_after(3).unwrap();
    drop(v);
    for _ in 0..2 {
        assert_eq!(
            unlock_now(&s.device, &s.oracle, &pat(4)).err(),
            Some(Error::WrongPattern)
        );
    }
    // The attempt that reaches the limit reports the wipe once.
    assert_eq!(
        unlock_now(&s.device, &s.oracle, &pat(4)).err(),
        Some(Error::Wiped)
    );
    assert_eq!(
        unlock_now(&s.device, &s.oracle, &pat(0)).err(),
        Some(Error::WrongPattern)
    );
}

#[test]
fn backup_restore_roundtrip_with_only_the_phrase() {
    let (s, a) = setup();
    let mut ea = Contents::new();
    fill(&a, "alpha", 6, &mut ea);
    a.create_album("Alpha album", 3).unwrap();
    a.set_name("Ålpha 🔒").unwrap();
    sync(&a, &s.cloud);
    // Later changes and deletions must also round-trip.
    let first = a.list_items().unwrap()[0].id;
    a.delete_item(first).unwrap();
    ea.remove("alpha-0.heic");
    fill(&a, "alpha2", 2, &mut ea);
    sync(&a, &s.cloud);
    // Converged: no further ops.
    assert!(a.sync_plan(&s.cloud.listing(), 3).unwrap().is_empty());

    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    let indices = backup::scan(&phrase, &s.cloud).unwrap();
    assert_eq!(indices.len(), 1);
    let storage = MemStorage::new();
    let (dev, _sealed) = Device::create_for_restore(
        Box::new(storage),
        Arc::new(MockOracle::new([9u8; 32])),
        ContainerConfig::tiny(),
        params(),
        &phrase,
        &indices,
    )
    .unwrap();
    // Wrong phrase is refused.
    let wrong = RecoveryPhrase::generate();
    assert_eq!(
        dev.restore_vault(&wrong, indices[0], &pat(3), &s.cloud.listing(), &s.cloud),
        Err(Error::InvalidPhrase)
    );
    dev.restore_vault(&phrase, indices[0], &pat(3), &s.cloud.listing(), &s.cloud)
        .unwrap();
    let r = dev.unlock(&pat(3)).unwrap();
    assert_eq!(contents(&r), ea);
    assert_eq!(r.albums().unwrap()[0].name, "Alpha album");
    assert_eq!(r.name().unwrap(), "Ålpha 🔒");
    // Restored vault is already in sync with the cloud.
    assert!(r.sync_plan(&s.cloud.listing(), 3).unwrap().is_empty());
    // And keeps working.
    r.import(meta("after-restore"), b"hello", None).unwrap();
    sync(&r, &s.cloud);
}

/// Headline: N vaults, duress, other vaults unrecoverable on device, decoy intact, all
/// vaults still restorable from cloud with the phrase.
#[test]
fn duress_wipes_device_but_phrase_restores_everything() {
    let (s, a) = setup();
    let b = a.create_vault(&pat(1), false).unwrap(); // hidden B
    let c = a.create_vault(&pat(2), true).unwrap(); // duress decoy C, filled at creation
    let d = a.create_vault(&pat(3), false).unwrap(); // D
    let mut expected: Vec<Contents> = Vec::new();
    for (v, tag) in [
        (&a, "vaultA"),
        (&b, "vaultB"),
        (&c, "decoyC"),
        (&d, "vaultD"),
    ] {
        let mut e = Contents::new();
        fill(v, tag, 3 + expected.len(), &mut e);
        sync(v, &s.cloud);
        expected.push(e);
    }
    drop((a, b, c, d));
    // Non-decoy vaults unlock normally with their own content.
    for i in [0, 1, 3] {
        assert_eq!(contents(&s.device.unlock(&pat(i)).unwrap()), expected[i]);
    }
    let cloud_before = s.cloud.snapshot();

    // Coercion: the duress pattern opens the decoy, intact.
    let c = s.device.unlock(&pat(2)).unwrap();
    assert_eq!(contents(&c), expected[2]);
    // Every other vault is gone from this device, also after reopening the container.
    for i in [0, 1, 3] {
        assert_eq!(
            unlock_now(&s.device, &s.oracle, &pat(i)).err(),
            Some(Error::WrongPattern)
        );
    }
    let reopened = Device::open(
        Box::new(s.storage.clone()),
        s.oracle.clone(),
        ContainerConfig::tiny(),
        &s.sealed,
    )
    .unwrap();
    for i in [0, 1, 3] {
        assert_eq!(
            unlock_now(&reopened, &s.oracle, &pat(i)).err(),
            Some(Error::WrongPattern)
        );
    }
    // The decoy keeps working and syncing; it never touches other vaults' cloud data.
    let c = unlock_now(&reopened, &s.oracle, &pat(2)).unwrap();
    assert_eq!(contents(&c), expected[2]);
    let mut more = expected[2].clone();
    fill(&c, "decoyC-after", 2, &mut more);
    // New vaults created after duress never take a hidden vault's manifest entry.
    c.create_vault(&pat(4), false).unwrap();
    sync(&c, &s.cloud);
    let new_v = unlock_now(&reopened, &s.oracle, &pat(4)).unwrap();
    // Created inside the decoy, it has no entry key until the owner enables backup.
    assert!(!new_v.backup_enabled().unwrap());
    let owner_phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    assert_eq!(
        new_v.enable_backup(&RecoveryPhrase::generate()),
        Err(Error::InvalidPhrase)
    );
    new_v.enable_backup(&owner_phrase).unwrap();
    assert!(new_v.backup_enabled().unwrap());
    new_v.import(meta("post-duress"), b"x", None).unwrap();
    sync(&new_v, &s.cloud);
    expected[2] = more;
    let cloud_after = s.cloud.snapshot();
    // Restore with only the phrase. Each vault on its own fresh phone first.
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    let indices = backup::scan(&phrase, &s.cloud).unwrap();
    assert_eq!(indices.len(), 5, "A, B, C, D and the post-duress vault");
    let mut want: Vec<Contents> = expected.clone();
    let mut post = Contents::new();
    post.insert("post-duress".into(), (b"x".to_vec(), None));
    want.push(post);
    let fresh = |seed: u8| {
        let oracle = Arc::new(MockOracle::new([seed; 32]));
        let dev = Device::create_for_restore(
            Box::new(MemStorage::new()),
            oracle.clone(),
            ContainerConfig::tiny(),
            params(),
            &phrase,
            &indices,
        )
        .unwrap()
        .0;
        (dev, oracle)
    };
    let mut by_index: BTreeMap<u8, Contents> = BTreeMap::new();
    for &idx in &indices {
        let (dev, _) = fresh(100 + idx);
        dev.restore_vault(&phrase, idx, &pat(5), &s.cloud.listing(), &s.cloud)
            .unwrap();
        let v = dev.unlock(&pat(5)).unwrap();
        by_index.insert(idx, contents(&v));
    }
    // Entries of the vaults wiped on the device were never touched in the cloud.
    for (idx, c) in &by_index {
        if [0, 1, 3].iter().any(|&i| *c == expected[i]) {
            let name = backup::entry_object_name(*idx);
            assert_eq!(cloud_before[&name], cloud_after[&name]);
        }
    }
    let mut got: Vec<Contents> = by_index.values().cloned().collect();
    got.sort();
    want.sort();
    assert_eq!(got, want, "every vault restored exactly");

    // All five on one new phone; the decoy keeps its duress role.
    let (dev, fresh_oracle) = fresh(42);
    let decoy_idx = *by_index.iter().find(|(_, c)| **c == expected[2]).unwrap().0;
    let assign: BTreeMap<u8, usize> = indices.iter().copied().zip([5, 0, 1, 3, 4]).collect();
    for (&idx, &p) in &assign {
        dev.restore_vault(&phrase, idx, &pat(p), &s.cloud.listing(), &s.cloud)
            .unwrap();
    }
    for (&idx, &p) in assign.iter().filter(|(i, _)| **i != decoy_idx) {
        assert_eq!(contents(&dev.unlock(&pat(p)).unwrap()), by_index[&idx]);
    }
    let decoy = dev.unlock(&pat(assign[&decoy_idx])).unwrap();
    assert_eq!(contents(&decoy), expected[2]);
    for (&idx, &p) in assign.iter().filter(|(i, _)| **i != decoy_idx) {
        let _ = idx;
        assert_eq!(
            unlock_now(&dev, &fresh_oracle, &pat(p)).err(),
            Some(Error::WrongPattern)
        );
    }
}

#[test]
fn managed_decoy_is_opened_without_wipe_and_survives_restore() {
    let (s, r) = setup();
    let b = r.create_vault(&pat(1), false).unwrap();
    let d = r.create_vault(&pat(2), true).unwrap();
    let (mut eb, mut ed) = (Contents::new(), Contents::new());
    fill(&b, "bee", 2, &mut eb);
    fill(&d, "decoy", 2, &mut ed);
    drop(d);
    assert_eq!(r.decoy_vaults().unwrap(), vec![1]);
    let d = r.open_managed_decoy(1).unwrap();
    assert_eq!(contents(&d), ed);
    fill(&d, "decoy-more", 1, &mut ed);
    // Renaming through the managed handle updates the owner's cached name.
    assert_eq!(r.decoys().unwrap()[0].name, "");
    d.set_name("Everyday").unwrap();
    assert_eq!(r.decoys().unwrap()[0].id, 1);
    assert_eq!(r.decoys().unwrap()[0].name, "Everyday");
    r.set_name("Main").unwrap();
    // No wipe happened: B still opens.
    let b = s.device.unlock(&pat(1)).unwrap();
    assert_eq!(contents(&b), eb);
    assert_eq!(r.open_managed_decoy(9).err(), Some(Error::NotFound));
    for v in [&r, &b, &d] {
        sync(v, &s.cloud);
    }
    drop((b, d));

    // Restore everything; the link survives (decoy anchor is re-located).
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    let indices = backup::scan(&phrase, &s.cloud).unwrap();
    assert_eq!(indices.len(), 3);
    let restored_oracle = Arc::new(MockOracle::new([77u8; 32]));
    let (dev, _) = Device::create_for_restore(
        Box::new(MemStorage::new()),
        restored_oracle.clone(),
        ContainerConfig::tiny(),
        params(),
        &phrase,
        &indices,
    )
    .unwrap();
    // Learn index → vault on throwaway devices (unlocking the decoy would wipe).
    let mut role = BTreeMap::new();
    for &i in &indices {
        let t = Device::create_for_restore(
            Box::new(MemStorage::new()),
            Arc::new(MockOracle::new([i; 32])),
            ContainerConfig::tiny(),
            params(),
            &phrase,
            &indices,
        )
        .unwrap()
        .0;
        t.restore_vault(&phrase, i, &pat(5), &s.cloud.listing(), &s.cloud)
            .unwrap();
        let v = t.unlock(&pat(5)).unwrap();
        let c = contents(&v);
        let r = if !v.decoy_vaults().unwrap().is_empty() {
            "owner"
        } else if c == eb {
            "b"
        } else {
            assert_eq!(c, ed);
            "decoy"
        };
        role.insert(r, i);
    }
    for (r, p) in [("owner", 3), ("b", 4), ("decoy", 5)] {
        dev.restore_vault(&phrase, role[r], &pat(p), &s.cloud.listing(), &s.cloud)
            .unwrap();
    }
    let owner = dev.unlock(&pat(3)).unwrap();
    assert_eq!(owner.name().unwrap(), "Main");
    assert_eq!(owner.decoys().unwrap()[0].name, "Everyday");
    let d = owner.open_managed_decoy(1).unwrap();
    assert_eq!(contents(&d), ed);
    assert_eq!(d.name().unwrap(), "Everyday");
    // No wipe: B opens; then the decoy's own pattern still acts as duress.
    assert_eq!(contents(&dev.unlock(&pat(4)).unwrap()), eb);
    drop((owner, d));
    assert_eq!(contents(&dev.unlock(&pat(5)).unwrap()), ed);
    assert_eq!(
        unlock_now(&dev, &restored_oracle, &pat(4)).err(),
        Some(Error::WrongPattern)
    );
    assert_eq!(
        unlock_now(&dev, &restored_oracle, &pat(3)).err(),
        Some(Error::WrongPattern)
    );
}

#[test]
fn change_pattern_is_atomic_and_checked() {
    let (s, a) = setup();
    let b = a.create_vault(&pat(1), false).unwrap();
    assert_eq!(a.change_pattern(&pat(1)), Err(Error::PatternInUse));
    assert_eq!(a.change_pattern(&pat(0)), Err(Error::PatternInUse));
    a.change_pattern(&pat(4)).unwrap();
    a.import(meta("still-works"), b"1", None).unwrap();
    assert_eq!(
        unlock_now(&s.device, &s.oracle, &pat(0)).err(),
        Some(Error::WrongPattern)
    );
    let a = unlock_now(&s.device, &s.oracle, &pat(4)).unwrap();
    assert_eq!(a.item_count().unwrap(), 1);
    // A managed decoy can change its pattern too; the link still works.
    let d = a.create_vault(&pat(2), true).unwrap();
    s.oracle.advance_clock_for_tests(3600);
    d.change_pattern(&pat(3)).unwrap();
    drop(d);
    assert!(a.open_managed_decoy(1).is_ok());
    assert_eq!(
        unlock_now(&s.device, &s.oracle, &pat(2)).err(),
        Some(Error::WrongPattern)
    );
    drop(b);
    assert!(unlock_now(&s.device, &s.oracle, &pat(1)).is_ok());
}

#[test]
fn delete_vault_locally_and_in_cloud() {
    let (s, a) = setup();
    let b = a.create_vault(&pat(1), false).unwrap();
    let mut ea = Contents::new();
    fill(&a, "keep", 2, &mut ea);
    fill(&b, "gone", 3, &mut Contents::new());
    sync(&a, &s.cloud);
    sync(&b, &s.cloud);
    let a_objects_before: Vec<String> = s.cloud.listing();
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    assert_eq!(backup::scan(&phrase, &s.cloud).unwrap().len(), 2);

    let plan = b.delete(&s.cloud.listing()).unwrap();
    assert!(matches!(plan.ops[0], SyncOp::PutEntry { .. }));
    s.cloud.apply(&plan);
    assert_eq!(b.item_count(), Err(Error::Locked));
    assert_eq!(
        unlock_now(&s.device, &s.oracle, &pat(1)).err(),
        Some(Error::WrongPattern)
    );
    assert_eq!(backup::scan(&phrase, &s.cloud).unwrap().len(), 1);
    // A's objects untouched; only B's were deleted.
    let after = s.cloud.listing();
    assert!(after.len() < a_objects_before.len());
    assert!(a.sync_plan(&after, 3).unwrap().is_empty());
    // The freed slot and pattern can be used again.
    let c = a.create_vault(&pat(1), false).unwrap();
    c.import(meta("new"), b"n", None).unwrap();
    assert_eq!(contents(&a), ea);
    // Deleting a managed decoy removes the owner's link.
    let d = a.create_vault(&pat(2), true).unwrap();
    assert_eq!(a.decoy_vaults().unwrap().len(), 1);
    d.delete(&[]).unwrap();
    assert!(a.decoy_vaults().unwrap().is_empty());
}

#[test]
fn new_pattern_checks_are_counted_attempts() {
    let (s, a) = setup();
    assert_eq!(s.device.failed_attempts().unwrap(), 0);
    // A wrong unlock and a successful create both count; create never resets.
    assert_eq!(s.device.unlock(&pat(5)).err(), Some(Error::WrongPattern));
    a.create_vault(&pat(1), false).unwrap();
    assert_eq!(s.device.failed_attempts().unwrap(), 2);
    // PatternInUse probing is throttled exactly like the unlock screen.
    for _ in 0..3 {
        assert_eq!(a.change_pattern(&pat(1)), Err(Error::PatternInUse));
    }
    assert_eq!(s.device.failed_attempts().unwrap(), 5);
    let steps = s.oracle.chain_steps_executed();
    assert_eq!(a.change_pattern(&pat(1)), Err(Error::RetryLater));
    assert_eq!(s.device.unlock(&pat(0)).err(), Some(Error::RetryLater));
    assert_eq!(
        s.oracle.chain_steps_executed(),
        steps,
        "no KDF while throttled"
    );
    assert!(s.device.retry_after_seconds().unwrap() > 0);
    // A successful unlock only undoes its own count; time decays failures.
    s.oracle.advance_clock_for_tests(31);
    let a = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(s.device.failed_attempts().unwrap(), 5);
    s.oracle.advance_clock_for_tests(4 * 3600);
    assert_eq!(s.device.failed_attempts().unwrap(), 4);
    // Wipe-after-N applies to checks too.
    a.set_wipe_after(6).unwrap();
    assert_eq!(a.wipe_after().unwrap(), 6);
    assert_eq!(a.change_pattern(&pat(1)), Err(Error::PatternInUse));
    s.oracle.advance_clock_for_tests(3600);
    assert_eq!(a.change_pattern(&pat(1)), Err(Error::Wiped));
    assert_eq!(
        unlock_now(&s.device, &s.oracle, &pat(0)).err(),
        Some(Error::WrongPattern)
    );
}

#[test]
fn unsized_import_and_item_extra() {
    let (s, v) = setup();
    let data = payload(11, 5_555);
    let mut m = meta("clip.mov");
    m.extra = b"live-photo:42".to_vec();
    let mut w = v.begin_import_unsized(m).unwrap();
    for part in data.chunks(700) {
        w.write(part).unwrap();
    }
    let id = w.finish(Some(b"thumb")).unwrap();
    let info = v.item(id).unwrap();
    assert_eq!(info.size, data.len() as u64);
    assert_eq!(info.extra, b"live-photo:42");
    assert_eq!(v.read(id, 1000, 3000).unwrap(), &data[1000..4000]);
    v.set_item_extra(id, b"other").unwrap();
    assert_eq!(
        v.set_item_extra(id, &[0; 4097]),
        Err(Error::InvalidArgument)
    );
    let empty = v
        .begin_import_unsized(meta("e"))
        .unwrap()
        .finish(None)
        .unwrap();
    drop(v);
    let v = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(v.item(id).unwrap().extra, b"other");
    assert_eq!(v.read(id, 0, data.len() as u64).unwrap(), data);
    assert_eq!(v.thumbnail(id).unwrap().unwrap(), b"thumb");
    assert_eq!(v.item(empty).unwrap().size, 0);
    // Streams survive backup/restore.
    sync(&v, &s.cloud);
}

#[test]
fn restore_never_overwrites_a_live_vault_and_works_in_existing_containers() {
    let (s, a) = setup();
    let b = a.create_vault(&pat(1), false).unwrap();
    let c = a.create_vault(&pat(2), true).unwrap();
    let (mut ea, mut eb, mut ec) = (Contents::new(), Contents::new(), Contents::new());
    fill(&a, "aa", 2, &mut ea);
    fill(&b, "bb", 2, &mut eb);
    fill(&c, "cc", 1, &mut ec);
    for v in [&a, &b, &c] {
        sync(v, &s.cloud);
    }
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    let indices = backup::scan(&phrase, &s.cloud).unwrap();
    assert_eq!(indices.len(), 3);
    // Every vault is live here: restore refuses without consuming an attempt.
    let attempts = s.device.failed_attempts().unwrap();
    for &i in &indices {
        assert_eq!(
            s.device
                .restore_vault(&phrase, i, &pat(4), &s.cloud.listing(), &s.cloud),
            Err(Error::VaultAlreadyPresent)
        );
    }
    assert_eq!(s.device.failed_attempts().unwrap(), attempts);
    drop((a, b, c));
    assert_eq!(contents(&s.device.unlock(&pat(0)).unwrap()), ea);
    assert_eq!(contents(&s.device.unlock(&pat(1)).unwrap()), eb);

    // Duress wipes A and B here; both restore into the SAME container.
    assert_eq!(contents(&s.device.unlock(&pat(2)).unwrap()), ec);
    let mut restored = Vec::new();
    for (&i, p) in indices.iter().zip([3, 4, 5]) {
        match s
            .device
            .restore_vault(&phrase, i, &pat(p), &s.cloud.listing(), &s.cloud)
        {
            Ok(()) => restored.push(p),
            Err(e) => assert_eq!(
                e,
                Error::VaultAlreadyPresent,
                "only the live decoy is refused"
            ),
        }
    }
    assert_eq!(restored.len(), 2);
    let mut got: Vec<Contents> = restored
        .iter()
        .map(|&p| contents(&s.device.unlock(&pat(p)).unwrap()))
        .collect();
    got.sort();
    let mut want = vec![ea.clone(), eb.clone()];
    want.sort();
    assert_eq!(got, want);
    // The decoy is untouched (and still the decoy).
    assert_eq!(
        contents(&unlock_now(&s.device, &s.oracle, &pat(2)).unwrap()),
        ec
    );
}

#[test]
fn undelete_and_restore_later_into_existing_container() {
    let (s, a) = setup();
    let b = a.create_vault(&pat(1), false).unwrap();
    let mut eb = Contents::new();
    fill(&b, "bb", 2, &mut eb);
    sync(&a, &s.cloud);
    sync(&b, &s.cloud);
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    let indices = backup::scan(&phrase, &s.cloud).unwrap();
    // Delete B locally without running the cloud plan: it is still restorable, into
    // the same container (its slot stays reserved until confirm_vault_deleted).
    let _plan = b.delete(&s.cloud.listing()).unwrap();
    assert_eq!(
        unlock_now(&s.device, &s.oracle, &pat(1)).err(),
        Some(Error::WrongPattern)
    );
    let mut undeleted = 0;
    for &i in &indices {
        if s.device
            .restore_vault(&phrase, i, &pat(3), &s.cloud.listing(), &s.cloud)
            .is_ok()
        {
            undeleted += 1;
        }
    }
    assert_eq!(undeleted, 1);
    assert_eq!(
        contents(&unlock_now(&s.device, &s.oracle, &pat(3)).unwrap()),
        eb
    );

    // A restore container that started with only some vaults can take the rest later.
    let (dev, _) = Device::create_for_restore(
        Box::new(MemStorage::new()),
        Arc::new(MockOracle::new([55u8; 32])),
        ContainerConfig::tiny(),
        params(),
        &phrase,
        &indices[..1],
    )
    .unwrap();
    dev.restore_vault(&phrase, indices[0], &pat(4), &s.cloud.listing(), &s.cloud)
        .unwrap();
    dev.restore_vault(&phrase, indices[1], &pat(5), &s.cloud.listing(), &s.cloud)
        .unwrap();
    let mut n = 0;
    for p in [4, 5] {
        n += dev.unlock(&pat(p)).unwrap().item_count().unwrap();
    }
    assert_eq!(n, 2);
}

/// Interleaving guesses with a known pattern does not reset the counter, so the
/// delay and wipe-after-N still apply.
#[test]
fn counter_reset_interleave_is_blocked() {
    let (s, a) = setup();
    a.set_wipe_after(6).unwrap();
    let hidden = a.create_vault(&pat(1), false).unwrap();
    hidden.import(meta("secret"), b"hidden data", None).unwrap();
    drop((hidden, a));
    let wrong = [2usize, 3, 4, 5];
    let mut stopped = None;
    'outer: for round in 0..20 {
        for _ in 0..2 {
            match s.device.unlock(&pat(wrong[round % 4])) {
                Err(Error::WrongPattern) => {}
                Err(e) => {
                    stopped = Some(e);
                    break 'outer;
                }
                Ok(_) => panic!("wrong pattern opened"),
            }
        }
        let _ = s.device.unlock(&pat(0));
    }
    assert!(
        matches!(stopped, Some(Error::RetryLater) | Some(Error::Wiped)),
        "interleaving must hit the delay or the wipe: {stopped:?}"
    );
}

#[test]
fn scan_refuses_incomplete_backup() {
    let (s, a) = setup();
    sync(&a, &s.cloud);
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    assert_eq!(backup::scan(&phrase, &s.cloud).unwrap().len(), 1);
    s.cloud
        .objects
        .lock()
        .unwrap()
        .remove(&backup::entry_object_name(7));
    assert_eq!(
        backup::scan(&phrase, &s.cloud),
        Err(Error::BackupIncomplete)
    );
}

#[test]
fn forgotten_pattern_is_reset_with_the_phrase_without_cloud() {
    let (s, a) = setup();
    let b = a.create_vault(&pat(1), false).unwrap();
    let d = a.create_vault(&pat(2), true).unwrap();
    let (mut ea, mut eb, mut ed) = (Contents::new(), Contents::new(), Contents::new());
    fill(&a, "aa", 2, &mut ea);
    fill(&b, "bb", 1, &mut eb);
    fill(&d, "dd", 1, &mut ed);
    drop((a, b, d));
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    assert_eq!(
        s.device
            .recover_with_phrase(&RecoveryPhrase::generate())
            .err(),
        Some(Error::InvalidPhrase)
    );
    let found = s.device.recover_with_phrase(&phrase).unwrap();
    assert_eq!(found.len(), 3);
    assert!(found.iter().all(|r| r.present_locally));
    assert_eq!(found.iter().filter(|r| r.is_duress).count(), 1);
    let attempts = s.device.failed_attempts().unwrap();
    // Reset every pattern (user forgot them all); the decoy keeps its role.
    let mut by_pattern = Vec::new();
    for (r, p) in found.iter().zip([3, 4, 5]) {
        s.device
            .reset_pattern_with_phrase(&phrase, r.index, &pat(p))
            .unwrap();
        by_pattern.push((p, r.is_duress));
    }
    assert!(
        s.device.failed_attempts().unwrap() <= attempts,
        "phrase ops are not attempts"
    );
    for old in [0, 1, 2] {
        assert_eq!(
            unlock_now(&s.device, &s.oracle, &pat(old)).err(),
            Some(Error::WrongPattern)
        );
    }
    let mut got = Vec::new();
    for &(p, duress) in by_pattern.iter().filter(|(_, d)| !d) {
        got.push(contents(
            &unlock_now(&s.device, &s.oracle, &pat(p)).unwrap(),
        ));
        let _ = duress;
    }
    got.sort();
    let mut want = vec![ea.clone(), eb.clone()];
    want.sort();
    assert_eq!(got, want);
    let decoy_p = by_pattern.iter().find(|(_, d)| *d).unwrap().0;
    assert_eq!(
        contents(&unlock_now(&s.device, &s.oracle, &pat(decoy_p)).unwrap()),
        ed
    );
    // Still a decoy: the others are now wiped from the device, but their local
    // entries remain for the phrase holder (data absent → restore from cloud).
    let after = s.device.recover_with_phrase(&phrase).unwrap();
    assert_eq!(after.iter().filter(|r| r.present_locally).count(), 1);
    let gone = after.iter().find(|r| !r.present_locally).unwrap();
    assert_eq!(
        s.device
            .reset_pattern_with_phrase(&phrase, gone.index, &pat(0)),
        Err(Error::NotFound)
    );
}

#[test]
fn erase_destroys_every_key_in_the_container() {
    let (s, a) = setup();
    a.import(meta("x"), b"y", None).unwrap();
    s.device.erase().unwrap();
    assert_eq!(a.item_count(), Err(Error::Locked));
    assert_eq!(s.device.unlock(&pat(0)).err(), Some(Error::Locked));
    // A forensic copy of the file opens nothing, not even with the device secret.
    assert!(
        Device::open(
            Box::new(s.storage.clone()),
            s.oracle.clone(),
            ContainerConfig::tiny(),
            &s.sealed
        )
        .is_err()
    );
}

#[test]
fn vaults_created_inside_a_decoy_are_not_backed_up() {
    let (s, a) = setup();
    let d = a.create_vault(&pat(2), true).unwrap();
    s.oracle.advance_clock_for_tests(3600);
    let c = d.create_vault(&pat(3), false).unwrap();
    c.import(meta("c"), b"c", None).unwrap();
    assert!(c.sync_plan(&s.cloud.listing(), 3).unwrap().is_empty());
    // The decoy itself is backed up (it holds its own entry key).
    sync(&d, &s.cloud);
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    assert_eq!(backup::scan(&phrase, &s.cloud).unwrap().len(), 1);
    let local = s.device.recover_with_phrase(&phrase).unwrap();
    assert_eq!(
        local.len(),
        2,
        "A and the decoy; the key-less vault has a filler entry"
    );
}

#[test]
fn verify_phrase_and_set_thumbnail() {
    let (s, v) = setup();
    let phrase = RecoveryPhrase::parse(&s.phrase_words.join(" ")).unwrap();
    let before = s.device.failed_attempts().unwrap();
    assert!(s.device.verify_phrase(&phrase).unwrap());
    assert!(!s.device.verify_phrase(&RecoveryPhrase::generate()).unwrap());
    assert_eq!(
        s.device.failed_attempts().unwrap(),
        before,
        "not an attempt"
    );

    let id = v.import(meta("doc.pdf"), &payload(3, 4000), None).unwrap();
    assert!(!v.item(id).unwrap().has_thumbnail);
    let thumb = payload(4, 2500);
    v.set_thumbnail(id, &thumb).unwrap();
    assert_eq!(v.thumbnail(id).unwrap().unwrap(), thumb);
    v.set_thumbnail(id, b"smaller").unwrap();
    assert_eq!(
        v.set_thumbnail(id, &vec![0u8; 4 * 1024 * 1024 + 1]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(v.set_thumbnail(999, b"x"), Err(Error::NotFound));
    drop(v);
    let v = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(v.thumbnail(id).unwrap().unwrap(), b"smaller");
    v.set_thumbnail(id, &[]).unwrap();
    assert!(v.thumbnail(id).unwrap().is_none());
    assert_eq!(v.read(id, 0, 4000).unwrap(), payload(3, 4000));
}

#[test]
fn replace_content_in_place() {
    let (s, v) = setup();
    let album = v.create_album("a", 0).unwrap();
    let tag = v.create_tag("t").unwrap();
    let mut m = meta("notes.txt");
    m.mime = "text/plain".into();
    m.albums = vec![album];
    m.tags = vec![tag];
    m.extra = b"x:1".to_vec();
    let id = v.import(m, b"draft", Some(b"thumb")).unwrap();
    let other_body = payload(5, 3000);
    let other = v.import(meta("other"), &other_body, None).unwrap();
    let other_info = v.item(other).unwrap();
    let before = v.item(id).unwrap();

    let text = payload(6, 5000);
    v.replace_content(id, &text, 1_800_000_000).unwrap();
    let after = v.item(id).unwrap();
    assert_eq!(v.read(id, 0, u64::MAX).unwrap(), text);
    assert_eq!(after.size, text.len() as u64);
    assert_eq!(after.modified, 1_800_000_000);
    let unchanged = |i: &hidewell_core::ItemInfo| {
        (
            i.id,
            i.name.clone(),
            i.mime.clone(),
            i.created,
            i.albums.clone(),
            i.tags.clone(),
            i.has_thumbnail,
            i.extra.clone(),
        )
    };
    assert_eq!(unchanged(&after), unchanged(&before));
    assert_eq!(v.thumbnail(id).unwrap().unwrap(), b"thumb");
    assert_eq!(v.item(other).unwrap(), other_info);
    assert_eq!(v.read(other, 0, u64::MAX).unwrap(), other_body);

    // Shrink to empty and back; bounds; missing id. Rejections leave the handle usable.
    v.replace_content(id, &[], 1_800_000_001).unwrap();
    assert!(v.read(id, 0, 10).unwrap().is_empty());
    assert_eq!(v.item(id).unwrap().size, 0);
    assert_eq!(
        v.replace_content(id, &vec![0u8; 16 * 1024 * 1024 + 1], 0),
        Err(Error::InvalidArgument)
    );
    assert_eq!(v.replace_content(999, b"x", 0), Err(Error::NotFound));
    v.replace_content(id, b"final", 1_800_000_002).unwrap();
    assert_eq!(v.item_count().unwrap(), 2);

    // Persisted.
    drop(v);
    let v = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(v.read(id, 0, u64::MAX).unwrap(), b"final");
    assert_eq!(v.item(id).unwrap().modified, 1_800_000_002);
    assert_eq!(unchanged(&v.item(id).unwrap()), unchanged(&before));
    assert_eq!(v.read(other, 0, u64::MAX).unwrap(), other_body);
}

#[test]
fn vault_names() {
    let (s, v) = setup();
    assert_eq!(v.name().unwrap(), "");
    v.set_name("  Holiday  ").unwrap();
    assert_eq!(v.name().unwrap(), "Holiday");
    // 64 Unicode scalar values of any width are accepted, 65 are not.
    for c in ["a", "é", "日", "🔒"] {
        v.set_name(&c.repeat(64)).unwrap();
        assert_eq!(v.name().unwrap(), c.repeat(64));
        assert_eq!(v.set_name(&c.repeat(65)), Err(Error::InvalidArgument));
    }
    // Rejection leaves the handle and the old name intact.
    assert_eq!(v.name().unwrap(), "🔒".repeat(64));
    v.set_name("Fotos — Ünïcode").unwrap();
    v.lock();
    assert_eq!(v.name(), Err(Error::Locked));
    let v = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(v.name().unwrap(), "Fotos — Ünïcode");
    // Names are per vault.
    let b = v.create_vault(&pat(1), false).unwrap();
    assert_eq!(b.name().unwrap(), "");
    b.set_name("Other").unwrap();
    assert_eq!(v.name().unwrap(), "Fotos — Ünïcode");
    v.set_name("   ").unwrap();
    assert_eq!(v.name().unwrap(), "");
}

#[test]
fn decoy_name_cache_refreshes_on_open() {
    let (s, r) = setup();
    let d = r.create_vault(&pat(2), true).unwrap();
    assert_eq!(r.decoys().unwrap()[0].name, "");
    // The creating handle is linked like a managed one.
    d.set_name("First").unwrap();
    assert_eq!(r.decoys().unwrap()[0].name, "First");
    // Owner locked while the decoy is renamed: the cache goes stale ...
    r.lock();
    d.set_name("Second").unwrap();
    drop(d);
    let r = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(r.decoys().unwrap()[0].name, "First");
    // ... and is refreshed (and persisted) when the owner opens the decoy.
    let d = r.open_managed_decoy(1).unwrap();
    assert_eq!(d.name().unwrap(), "Second");
    assert_eq!(r.decoys().unwrap()[0].name, "Second");
    drop((r, d));
    let r = s.device.unlock(&pat(0)).unwrap();
    assert_eq!(r.decoys().unwrap()[0].name, "Second");
}

#[test]
fn protection_info_reports_stored_parameters() {
    let (s, v) = setup();
    drop(v);
    // A freshly opened device, no vault unlocked.
    let dev = Device::open(
        Box::new(s.storage.clone()),
        s.oracle.clone(),
        ContainerConfig::tiny(),
        &s.sealed,
    )
    .unwrap();
    let p = params();
    let info = dev.protection_info().unwrap();
    assert_eq!(
        info,
        hidewell_core::ProtectionInfo {
            security_level: hidewell_core::SecurityLevel::SoftwareMock,
            chain_steps: p.chain_steps,
            argon2_memory_kib: p.argon_m_kib,
            argon2_passes: p.argon_t,
            argon2_lanes: p.argon_p,
            estimated_attempt_millis: None,
        }
    );
    // Reading it is not an attempt.
    assert_eq!(dev.failed_attempts().unwrap(), 0);
}

#[test]
fn sub_policy_unlock_attempts_are_not_counted() {
    use hidewell_core::PatternError;
    let (s, v) = setup();
    v.set_wipe_after(2).unwrap();
    drop(v);
    let before = s.storage.snapshot();
    let short: [(&[u8], PatternError); 4] = [
        (&[12], PatternError::TooFewNodes),
        (&[0, 1, 2], PatternError::TooFewNodes),
        (&[0, 1, 2, 3, 4], PatternError::TooFewNodes),
        // Seven nodes, one turn.
        (
            &[0, 1, 2, 3, 4, 9, 14],
            PatternError::TooFewDirectionChanges,
        ),
    ];
    for _ in 0..3 {
        for (strokes, err) in &short {
            let p = Pattern::new(vec![strokes.to_vec()]).unwrap();
            assert_eq!(s.device.unlock(&p).err(), Some(Error::Pattern(*err)));
        }
    }
    // Nothing written, counted, delayed or wiped (checked before the timing queries,
    // which may checkpoint by design).
    assert!(s.storage.snapshot() == before, "state written");
    assert_eq!(s.device.failed_attempts().unwrap(), 0);
    assert_eq!(s.device.retry_after_seconds().unwrap(), 0);
    // A policy-valid wrong pattern still counts.
    assert_eq!(s.device.unlock(&pat(4)).err(), Some(Error::WrongPattern));
    assert_eq!(s.device.failed_attempts().unwrap(), 1);
    assert!(s.device.unlock(&pat(0)).is_ok());
}
