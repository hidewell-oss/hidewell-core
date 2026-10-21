//! Deterministic timing and persistence tests; no sleeping or OS clock changes.

use super::*;
use crate::mock::MockOracle;
use crate::{MemStorage, NewItem, OracleError};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

fn pattern(wrong: bool) -> Pattern {
    Pattern::new(vec![if wrong {
        vec![12, 1, 10, 23, 14, 3, 6, 19]
    } else {
        vec![7, 0, 11, 22, 13, 4, 8, 15, 21]
    }])
    .unwrap()
}

struct Rig {
    storage: MemStorage,
    oracle: Arc<MockOracle>,
    device: Device,
    sealed: Vec<u8>,
}

impl Rig {
    fn new() -> Self {
        let storage = MemStorage::new();
        let oracle = Arc::new(MockOracle::new([42; 32]));
        let created = Device::create(
            Box::new(storage.clone()),
            oracle.clone(),
            ContainerConfig::tiny(),
            KdfParams::insecure_test_params(),
            &RecoveryPhrase::generate(),
            &pattern(false),
        )
        .unwrap();
        Self {
            storage,
            oracle,
            device: created.device,
            sealed: created.sealed_device_secret,
        }
    }

    fn fail(&self, n: usize) {
        for _ in 0..n {
            assert_eq!(
                self.device.unlock(&pattern(true)).err(),
                Some(Error::WrongPattern)
            );
        }
    }

    fn set_clock(&self, epoch: u8, elapsed_millis: u64) {
        self.oracle.set_clock_sample(Ok(ClockSample {
            epoch: [epoch; 16],
            elapsed_millis,
        }));
    }

    fn reopen(&mut self) {
        // A separate snapshot models process death without overlapping owners of
        // the same storage. Later reopen cycles use this new owner's latest bytes.
        let storage = MemStorage::from_bytes(self.storage.snapshot());
        self.device = Device::open(
            Box::new(storage.clone()),
            self.oracle.clone(),
            ContainerConfig::tiny(),
            &self.sealed,
        )
        .unwrap();
        self.storage = storage;
    }
}

#[test]
fn file_timestamp_metadata_cannot_pay_retry_or_decay_debt() {
    // Wall-clock metadata may move arbitrarily in either direction. Only the
    // separately injected continuous clock can affect the attempt policy.
    let rig = Rig::new();
    let vault = rig.device.unlock(&pattern(false)).unwrap();
    rig.fail(5);
    for timestamp in [1_700_000_000, i64::MAX, 0, i64::MIN] {
        vault
            .import(
                NewItem {
                    name: "clock".into(),
                    created: timestamp,
                    modified: timestamp,
                    ..Default::default()
                },
                b"data",
                None,
            )
            .unwrap();
        assert_eq!(rig.device.retry_after_seconds().unwrap(), 30);
        assert_eq!(rig.device.failed_attempts().unwrap(), 5);
    }
    rig.oracle.advance_clock_for_tests(4 * 3600);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 0);
    assert_eq!(rig.device.failed_attempts().unwrap(), 4);
}

#[test]
fn same_epoch_reopen_credits_each_interval_once_and_rounds_up() {
    let mut rig = Rig::new();
    rig.fail(5);
    rig.oracle.advance_clock_millis(10_001);
    for _ in 0..3 {
        assert_eq!(rig.device.retry_after_seconds().unwrap(), 20);
        rig.reopen();
    }
    rig.oracle.advance_clock_millis(19_998);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 1);
    rig.reopen();
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 1);
    rig.oracle.advance_clock_millis(1);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 0);
    rig.reopen();
    assert_eq!(rig.device.failed_attempts().unwrap(), 5);
    assert!(rig.device.unlock(&pattern(false)).is_ok());
    assert_eq!(rig.device.failed_attempts().unwrap(), 5);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 0);
}

#[test]
fn changed_epochs_with_larger_ticks_preserve_debt_and_cannot_replay_intervals() {
    let mut rig = Rig::new();
    rig.fail(5);
    rig.oracle.advance_clock_millis(12_000);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 18);
    for (epoch, tick) in [
        (90, 1_000_000_000),
        (42, 12_000),
        (90, 2_000_000_000),
        (42, 1),
    ] {
        rig.set_clock(epoch, tick);
        assert_eq!(rig.device.retry_after_seconds().unwrap(), 18);
        rig.reopen();
        assert_eq!(rig.device.retry_after_seconds().unwrap(), 18);
        assert_eq!(rig.device.failed_attempts().unwrap(), 5);
    }
    rig.oracle.advance_clock_millis(17_999);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 1);
    rig.oracle.advance_clock_millis(1);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 0);
}

#[test]
fn regression_retains_high_water_and_rebound_is_not_credited_twice() {
    let mut rig = Rig::new();
    rig.fail(5);
    rig.oracle.advance_clock_for_tests(30);
    rig.fail(1); // sixth failure: 60 seconds
    rig.oracle.advance_clock_for_tests(30); // checkpoint at tick 60,000
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 30);
    for tick in [59_000, 0, 60_000, 59_999, 60_000] {
        rig.set_clock(42, tick);
        assert_eq!(rig.device.retry_after_seconds().unwrap(), 30);
        rig.reopen();
        assert_eq!(rig.device.retry_after_seconds().unwrap(), 30);
    }
    rig.set_clock(42, 61_000);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 29);
}

#[test]
fn sleep_elapsed_and_partial_decay_survive_reopen_and_epoch_change() {
    let mut rig = Rig::new();
    rig.fail(5);
    // Continuous clocks include sleep. One large elapsed interval is equivalent to
    // many foreground polls, and partial decay survives a later epoch transition.
    rig.oracle.advance_clock_for_tests(90 * 60);
    assert_eq!(rig.device.failed_attempts().unwrap(), 5);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 0);
    rig.set_clock(77, 999_999_999);
    rig.reopen();
    assert_eq!(rig.device.failed_attempts().unwrap(), 5);
    rig.oracle.advance_clock_for_tests(150 * 60);
    assert_eq!(rig.device.failed_attempts().unwrap(), 4);
    rig.oracle.advance_clock_for_tests(2 * 3600);
    assert_eq!(rig.device.failed_attempts().unwrap(), 4);
    rig.reopen();
    assert!(rig.device.unlock(&pattern(false)).is_ok());
    // Success retains the previous 2 hours of decay progress.
    rig.oracle.advance_clock_for_tests(2 * 3600);
    assert_eq!(rig.device.failed_attempts().unwrap(), 3);
    rig.fail(1);
    rig.oracle.advance_clock_for_tests(4 * 3600 - 1);
    assert_eq!(rig.device.failed_attempts().unwrap(), 4);
    rig.oracle.advance_clock_for_tests(1);
    assert_eq!(rig.device.failed_attempts().unwrap(), 3);
}

#[test]
fn checkpointed_progress_is_kept_when_the_process_epoch_is_lost() {
    let mut rig = Rig::new();
    rig.fail(5);
    rig.oracle.advance_clock_for_tests(30);
    rig.fail(1); // 60-second retry
    rig.oracle.advance_clock_for_tests(30);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 30);
    rig.set_clock(77, 10_000_000);
    rig.reopen();
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 30);
    rig.oracle.advance_clock_for_tests(30);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 0);
    // Partial decay (including the retry minute) is also retained.
    rig.oracle.advance_clock_for_tests(4 * 3600 - 60);
    assert_eq!(rig.device.failed_attempts().unwrap(), 5);
}

#[test]
fn clock_errors_preserve_state_and_stop_queries_open_and_kdf() {
    let rig = Rig::new();
    rig.fail(5);
    let bytes = rig.storage.snapshot();
    let steps = rig.oracle.chain_steps_executed();
    for error in [
        OracleError::Failed,
        OracleError::BadOutput,
        OracleError::DeviceLocked,
        OracleError::KeyUnavailable,
    ] {
        rig.oracle.set_clock_sample(Err(error));
        assert_eq!(rig.device.failed_attempts(), Err(Error::Oracle(error)));
        assert_eq!(rig.device.retry_after_seconds(), Err(Error::Oracle(error)));
        assert_eq!(
            rig.device.unlock(&pattern(false)).err(),
            Some(Error::Oracle(error))
        );
        assert_eq!(
            Device::open(
                Box::new(MemStorage::from_bytes(bytes.clone())),
                rig.oracle.clone(),
                ContainerConfig::tiny(),
                &rig.sealed,
            )
            .err()
            .map(|e| e == Error::Oracle(error)),
            Some(true)
        );
        assert_eq!(rig.oracle.chain_steps_executed(), steps);
        assert_eq!(rig.storage.snapshot(), bytes);
    }
    rig.set_clock(42, 0);
    assert_eq!(rig.device.failed_attempts().unwrap(), 5);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 30);

    let empty = MemStorage::new();
    rig.oracle.set_clock_sample(Err(OracleError::Failed));
    assert!(
        Device::create_for_restore(
            Box::new(empty.clone()),
            rig.oracle.clone(),
            ContainerConfig::tiny(),
            KdfParams::insecure_test_params(),
            &RecoveryPhrase::generate(),
            &[],
        )
        .is_err()
    );
    assert!(empty.snapshot().is_empty());
}

#[test]
fn huge_same_epoch_interval_cannot_overflow_decay_arithmetic() {
    let rig = Rig::new();
    rig.fail(5);
    rig.set_clock(42, u64::MAX);
    assert_eq!(rig.device.failed_attempts().unwrap(), 0);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 0);
}

/// Disk with a volatile write cache and explicit fsync. Losing the cache models a
/// crash, including a write that completed but whose following sync failed.
struct CrashDisk {
    volatile: MemStorage,
    durable: Mutex<Vec<u8>>,
    fail_write: AtomicBool,
    fail_sync: AtomicBool,
    persist_torn_write: AtomicBool,
    persist_failed_sync: AtomicBool,
    writes: AtomicU64,
}

impl CrashDisk {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            volatile: MemStorage::new(),
            durable: Mutex::new(Vec::new()),
            fail_write: false.into(),
            fail_sync: false.into(),
            persist_torn_write: false.into(),
            persist_failed_sync: false.into(),
            writes: 0.into(),
        })
    }
    fn after_crash(&self) -> MemStorage {
        MemStorage::from_bytes(self.durable.lock().unwrap().clone())
    }
}

struct CrashStorage(Arc<CrashDisk>);

impl Storage for CrashStorage {
    fn len(&self) -> Result<u64> {
        self.0.volatile.len()
    }
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        self.0.volatile.read_at(offset, bytes)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        self.0.writes.fetch_add(1, Ordering::SeqCst);
        if self.0.fail_write.load(Ordering::SeqCst) {
            self.0
                .volatile
                .clone()
                .write_at(offset, &bytes[..bytes.len() / 2])?;
            if self.0.persist_torn_write.load(Ordering::SeqCst) {
                // Only this partial write reaches disk; unrelated cached writes
                // may still be lost (including a preceding failed fsync).
                let mut durable = self.0.durable.lock().unwrap();
                let start = offset as usize;
                let half = bytes.len() / 2;
                durable[start..start + half].copy_from_slice(&bytes[..half]);
            }
            return Err(Error::Io(std::io::ErrorKind::StorageFull));
        }
        self.0.volatile.clone().write_at(offset, bytes)
    }
    fn sync(&mut self) -> Result<()> {
        if self.0.fail_sync.load(Ordering::SeqCst) {
            if self.0.persist_failed_sync.load(Ordering::SeqCst) {
                *self.0.durable.lock().unwrap() = self.0.volatile.snapshot();
            }
            return Err(Error::Io(std::io::ErrorKind::Other));
        }
        *self.0.durable.lock().unwrap() = self.0.volatile.snapshot();
        Ok(())
    }
}

fn crash_device() -> (Arc<CrashDisk>, Arc<MockOracle>, Created) {
    let disk = CrashDisk::new();
    let oracle = Arc::new(MockOracle::new([42; 32]));
    let created = Device::create(
        Box::new(CrashStorage(disk.clone())),
        oracle.clone(),
        ContainerConfig::tiny(),
        KdfParams::insecure_test_params(),
        &RecoveryPhrase::generate(),
        &pattern(false),
    )
    .unwrap();
    (disk, oracle, created)
}

#[test]
fn failed_checkpoint_write_or_sync_never_loses_debt_or_runs_kdf() {
    for sync_fault in [false, true] {
        for new_epoch in [false, true] {
            let (disk, oracle, created) = crash_device();
            for _ in 0..5 {
                assert_eq!(
                    created.device.unlock(&pattern(true)).err(),
                    Some(Error::WrongPattern)
                );
            }
            oracle.advance_clock_for_tests(30);
            assert_eq!(
                created.device.unlock(&pattern(true)).err(),
                Some(Error::WrongPattern)
            );
            let steps = oracle.chain_steps_executed();
            if sync_fault {
                disk.fail_sync.store(true, Ordering::SeqCst);
            } else {
                disk.fail_write.store(true, Ordering::SeqCst);
            }
            oracle.advance_clock_for_tests(30);
            assert!(matches!(
                created.device.retry_after_seconds(),
                Err(Error::Io(_))
            ));
            assert!(matches!(
                created.device.unlock(&pattern(false)),
                Err(Error::Io(_))
            ));
            assert_eq!(oracle.chain_steps_executed(), steps);
            let crash = disk.after_crash();
            if new_epoch {
                oracle.set_clock_sample(Ok(ClockSample {
                    epoch: [77; 16],
                    elapsed_millis: 9_000_000,
                }));
            }
            let reopened = Device::open(
                Box::new(crash),
                oracle.clone(),
                ContainerConfig::tiny(),
                &created.sealed_device_secret,
            )
            .unwrap();
            assert_eq!(reopened.failed_attempts().unwrap(), 6);
            assert_eq!(
                reopened.retry_after_seconds().unwrap(),
                if new_epoch { 60 } else { 30 }
            );
        }
    }
}

#[test]
fn repeated_durable_torn_checkpoints_preserve_one_valid_state_copy() {
    // No preceding sync error, or one that left the complete new copy either
    // undurable or durable. All three must preserve the previous synced copy.
    for failed_sync in [None, Some(false), Some(true)] {
        let (disk, oracle, created) = crash_device();
        for _ in 0..5 {
            assert_eq!(
                created.device.unlock(&pattern(true)).err(),
                Some(Error::WrongPattern)
            );
        }
        oracle.advance_clock_for_tests(30);
        if let Some(durable) = failed_sync {
            disk.fail_sync.store(true, Ordering::SeqCst);
            disk.persist_failed_sync.store(durable, Ordering::SeqCst);
            assert!(matches!(
                created.device.retry_after_seconds(),
                Err(Error::Io(_))
            ));
            disk.fail_sync.store(false, Ordering::SeqCst);
        }
        disk.fail_write.store(true, Ordering::SeqCst);
        disk.persist_torn_write.store(true, Ordering::SeqCst);
        for _ in 0..3 {
            assert!(matches!(
                created.device.retry_after_seconds(),
                Err(Error::Io(_))
            ));
        }
        // Writes can reach disk even when write_at/fsync reports failure. Repeated
        // failures must keep targeting the same older copy, retaining its predecessor.
        let reopened = Device::open(
            Box::new(disk.after_crash()),
            oracle,
            ContainerConfig::tiny(),
            &created.sealed_device_secret,
        )
        .unwrap();
        assert_eq!(reopened.failed_attempts().unwrap(), 5);
        assert_eq!(reopened.retry_after_seconds().unwrap(), 0);
    }
}

#[test]
fn failed_epoch_checkpoint_is_retried_without_double_credit() {
    for sync_fault in [false, true] {
        let (disk, oracle, created) = crash_device();
        for _ in 0..5 {
            assert_eq!(
                created.device.unlock(&pattern(true)).err(),
                Some(Error::WrongPattern)
            );
        }
        oracle.advance_clock_for_tests(12);
        assert_eq!(created.device.retry_after_seconds().unwrap(), 18);
        oracle.set_clock_sample(Ok(ClockSample {
            epoch: [77; 16],
            elapsed_millis: 1_000_000,
        }));
        disk.fail_write.store(!sync_fault, Ordering::SeqCst);
        disk.fail_sync.store(sync_fault, Ordering::SeqCst);
        assert!(matches!(
            created.device.failed_attempts(),
            Err(Error::Io(_))
        ));
        disk.fail_write.store(false, Ordering::SeqCst);
        disk.fail_sync.store(false, Ordering::SeqCst);
        assert_eq!(created.device.retry_after_seconds().unwrap(), 18);
        let reopened = Device::open(
            Box::new(disk.after_crash()),
            oracle,
            ContainerConfig::tiny(),
            &created.sealed_device_secret,
        )
        .unwrap();
        assert_eq!(reopened.retry_after_seconds().unwrap(), 18);
        assert_eq!(reopened.failed_attempts().unwrap(), 5);
    }
}

#[test]
fn attempt_write_and_fsync_precede_kdf_even_when_timing_changes() {
    for sync_fault in [false, true] {
        let (disk, oracle, created) = crash_device();
        // Prime the post-setup clock checkpoint before injecting the attempt fault.
        assert_eq!(created.device.failed_attempts().unwrap(), 0);
        let steps = oracle.chain_steps_executed();
        disk.fail_write.store(!sync_fault, Ordering::SeqCst);
        disk.fail_sync.store(sync_fault, Ordering::SeqCst);
        assert!(matches!(
            created.device.unlock(&pattern(true)),
            Err(Error::Io(_))
        ));
        assert_eq!(oracle.chain_steps_executed(), steps);
        let reopened = Device::open(
            Box::new(disk.after_crash()),
            oracle,
            ContainerConfig::tiny(),
            &created.sealed_device_secret,
        )
        .unwrap();
        assert_eq!(reopened.failed_attempts().unwrap(), 0);
    }
}

#[test]
fn polling_checkpoints_are_bounded_and_idle_queries_do_not_write() {
    let (disk, oracle, created) = crash_device();
    assert_eq!(created.device.failed_attempts().unwrap(), 0);
    let before = disk.writes.load(Ordering::SeqCst);
    for _ in 0..100 {
        oracle.advance_clock_for_tests(3600);
        assert_eq!(created.device.retry_after_seconds().unwrap(), 0);
    }
    assert_eq!(disk.writes.load(Ordering::SeqCst), before);
    for _ in 0..5 {
        assert_eq!(
            created.device.unlock(&pattern(true)).err(),
            Some(Error::WrongPattern)
        );
    }
    oracle.advance_clock_for_tests(30);
    assert_eq!(
        created.device.unlock(&pattern(true)).err(),
        Some(Error::WrongPattern)
    );
    let before = disk.writes.load(Ordering::SeqCst);
    for i in 1..=60 {
        oracle.advance_clock_for_tests(1);
        assert_eq!(created.device.retry_after_seconds().unwrap(), 60 - i);
    }
    assert_eq!(disk.writes.load(Ordering::SeqCst) - before, 2);
}

#[test]
fn epoch_change_and_clock_errors_cannot_skip_the_wipe_policy() {
    let mut rig = Rig::new();
    let vault = rig.device.unlock(&pattern(false)).unwrap();
    vault.set_wipe_after(6).unwrap();
    rig.fail(5);
    rig.set_clock(77, u64::MAX - 30_000);
    assert_eq!(
        rig.device.unlock(&pattern(true)).err(),
        Some(Error::RetryLater)
    );
    rig.oracle.set_clock_sample(Err(OracleError::Failed));
    assert_eq!(
        rig.device.unlock(&pattern(true)).err(),
        Some(Error::Oracle(OracleError::Failed))
    );
    rig.set_clock(77, u64::MAX);
    assert_eq!(rig.device.unlock(&pattern(true)).err(), Some(Error::Wiped));
    assert_eq!(rig.device.failed_attempts().unwrap(), 0);
    assert_eq!(rig.device.retry_after_seconds().unwrap(), 0);
    assert_eq!(vault.item_count(), Err(Error::Locked));
    rig.reopen();
    assert_eq!(rig.device.failed_attempts().unwrap(), 0);
    assert_eq!(
        rig.device.unlock(&pattern(false)).err(),
        Some(Error::WrongPattern)
    );
}

#[test]
fn wall_clock_device_states_are_rejected() {
    #[derive(Serialize)]
    struct WallClockState {
        version: u8,
        generation: u64,
        salt: [u8; SALT_LEN],
        kdf: KdfParams,
        total_chunks: u32,
        bitmap: Vec<u8>,
        reserved_slots: u16,
        backup_pk: [u8; 32],
        failed_attempts: u32,
        wipe_after: u32,
        active_table: u8,
        last_failure_unix: i64,
        decay_from_unix: i64,
    }
    let rig = Rig::new();
    {
        let d = lock(&rig.device.inner).unwrap();
        for copy in 0..2 {
            let state = WallClockState {
                version: 3,
                generation: 100 + copy,
                salt: d.state.salt,
                kdf: d.state.kdf,
                total_chunks: d.state.total_chunks,
                bitmap: d.state.bitmap.clone(),
                reserved_slots: d.state.reserved_slots,
                backup_pk: d.state.backup_pk,
                failed_attempts: 5,
                wipe_after: 10,
                active_table: d.state.active_table,
                last_failure_unix: 1_700_000_000,
                decay_from_unix: 1_700_000_000,
            };
            let pt = crate::index::to_padded(&state, d.cfg.device_state_plain_len()).unwrap();
            let sealed = crypto::seal(&d.device_key, &DeviceInner::state_aad(copy), &pt);
            rig.storage.poke(d.state_offset(copy) as usize, &sealed);
        }
    }
    let before = rig.storage.snapshot();
    assert_eq!(
        Device::open(
            Box::new(rig.storage.clone()),
            rig.oracle,
            ContainerConfig::tiny(),
            &rig.sealed,
        )
        .err(),
        Some(Error::Corrupt)
    );
    assert_eq!(rig.storage.snapshot(), before);
}
