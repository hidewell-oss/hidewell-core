//! The device container: superblock (key-slot table + device state), global chunk
//! allocation, unlock, duress, vault creation and restore.
//!
//! Superblock (first `superblock_chunks` chunks; everything else in them is random):
//! `slot table A || slot table B || device state copy 0 || device state copy 1`.
//! The device state names the active slot table; the inactive one is random bytes except
//! transiently during an atomic table replacement (pattern change).
//! A device state copy is `nonce || AES-256-GCM(device_key, padded state,
//! aad = "hidewell/devstate/v1" || u8(copy))`; the copy with the highest valid generation
//! wins, and writes alternate copies (crash-safe).
//!
//! `device_key = HKDF(device_secret, "hidewell/device-state/v1")`, where `device_secret`
//! is 32 random bytes sealed by the hardware oracle (not pattern-gated). The sealed
//! blob is returned to the platform, which stores it outside the container.

use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::backup::{self, ObjectSource};
use crate::config::ContainerConfig;
use crate::crypto;
use crate::error::{Error, Result};
use crate::index::EntryKey;
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::oracle::{ClockSample, HardwareOracle, SecurityLevel};
use crate::pattern::Pattern;
use crate::phrase::RecoveryPhrase;
use crate::rng;
use crate::secret::{SecretKey, SecretVec};
use crate::slots::{self, SLOT_COUNT, SLOT_LEN, SlotPayload, TABLE_LEN};
use crate::storage::Storage;
use crate::strength;
use crate::vault::{Vault, VaultState, child_entry_keys};

#[cfg(test)]
#[path = "device_clock_tests.rs"]
mod clock_tests;

const STATE_VERSION: u8 = 4;
/// One counted failure is forgiven per this many seconds since the last failure.
pub const FAILURE_DECAY_SECS: i64 = 4 * 3600;
const FAILURE_DECAY_MILLIS: u64 = FAILURE_DECAY_SECS as u64 * 1000;
/// Checkpoint ongoing waits at most once per this interval. Epoch changes, forgiven
/// failures and completed retry delays are checkpointed immediately.
const CLOCK_CHECKPOINT_MILLIS: u64 = 30_000;

/// Timing debt and the last sample whose elapsed interval has already been applied.
/// These fields are authenticated and committed together with `failed_attempts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AttemptTiming {
    epoch: [u8; 16],
    elapsed_millis: u64,
    retry_remaining_millis: u64,
    decay_progress_millis: u64,
}

impl AttemptTiming {
    fn new(sample: ClockSample) -> Self {
        Self {
            epoch: sample.epoch,
            elapsed_millis: sample.elapsed_millis,
            retry_remaining_millis: 0,
            decay_progress_millis: 0,
        }
    }
}

/// Non-vault-identifying device state, encrypted under the device key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DeviceState {
    version: u8,
    generation: u64,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) kdf: KdfParams,
    pub(crate) total_chunks: u32,
    /// Global allocation bitmap, sized for the largest bucket. Allocation, cover traffic
    /// and the duress wipe need a device-wide view of used chunks; it is not
    /// pattern-gated, and its leakage is mitigated by filler chunks.
    bitmap: Vec<u8>,
    /// Reserved key slots: real vaults ∪ filler reservations.
    pub(crate) reserved_slots: u16,
    pub(crate) backup_pk: [u8; 32],
    pub(crate) failed_attempts: u32,
    /// Wipe the slot table after this many consecutive failures (0 = off).
    pub(crate) wipe_after: u32,
    /// Active slot table (0 = A, 1 = B).
    active_table: u8,
    timing: AttemptTiming,
}

/// Counter values before an attempt, restored when the attempt unlocks.
#[derive(Clone, Copy)]
pub(crate) struct AttemptUndo {
    failed: u32,
    timing: AttemptTiming,
}

pub(crate) fn decode_state(pt: &[u8]) -> Result<DeviceState> {
    let s: DeviceState = crate::index::from_padded(pt)?;
    if s.version != STATE_VERSION
        || s.timing.decay_progress_millis >= FAILURE_DECAY_MILLIS
        || s.timing.retry_remaining_millis > kdf::retry_delay(s.failed_attempts).as_millis() as u64
        || (s.failed_attempts == 0 && s.timing.decay_progress_millis != 0)
    {
        return Err(Error::Corrupt);
    }
    Ok(s)
}

/// Device-wide unlock protection parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtectionInfo {
    /// Hardware security level of the oracle.
    pub security_level: SecurityLevel,
    /// Hardware chain length k.
    pub chain_steps: u32,
    /// Argon2id memory in KiB.
    pub argon2_memory_kib: u32,
    /// Argon2id passes (t).
    pub argon2_passes: u32,
    /// Argon2id lanes (p).
    pub argon2_lanes: u32,
    /// Measured duration of one attempt, if calibration stored one. The device state
    /// does not store one, so this is always `None`.
    pub estimated_attempt_millis: Option<u64>,
}

/// Mutable device internals, shared by the [`Device`] and open [`Vault`] handles.
pub(crate) struct DeviceInner {
    pub(crate) storage: Box<dyn Storage>,
    pub(crate) cfg: ContainerConfig,
    pub(crate) oracle: Arc<dyn HardwareOracle>,
    device_key: SecretKey,
    pub(crate) state: DeviceState,
    /// Last timing checkpoint known to have completed a clock-specific fsync.
    /// Other state commits can also save timing; retaining this older checkpoint
    /// only causes an occasional redundant write.
    clock_checkpoint: AttemptUndo,
    /// Bumped by duress and failure wipes; vault handles from an older epoch are dead.
    pub(crate) epoch: u64,
    /// One current mutable snapshot per slot. Opening another handle invalidates the
    /// previous handle and its writers, even when both use this same device mutex.
    pub(crate) vault_handle_generations: [u64; SLOT_COUNT],
    /// Set by `Device::erase`; every later call fails with `Locked`.
    erased: bool,
}

impl DeviceInner {
    pub(crate) fn claim_vault_handle(&mut self, slot: u8) -> u64 {
        let generation = &mut self.vault_handle_generations[slot as usize];
        *generation += 1;
        *generation
    }

    fn chunk_offset(&self, chunk: u32) -> u64 {
        u64::from(chunk) * u64::from(self.cfg.chunk_size)
    }

    pub(crate) fn is_allocated(&self, chunk: u32) -> bool {
        self.state.bitmap[(chunk / 8) as usize] & (1 << (chunk % 8)) != 0
    }

    fn set_allocated(&mut self, chunk: u32, on: bool) {
        let (i, b) = ((chunk / 8) as usize, 1u8 << (chunk % 8));
        if on {
            self.state.bitmap[i] |= b;
        } else {
            self.state.bitmap[i] &= !b;
        }
    }

    fn free_chunks(&self) -> Vec<u32> {
        (self.cfg.superblock_chunks()..self.state.total_chunks)
            .filter(|&c| !self.is_allocated(c))
            .collect()
    }

    /// Allocate a uniformly random free chunk, growing the container if needed.
    /// Only the in-memory bitmap changes; callers persist before their commit point.
    pub(crate) fn alloc_chunk(&mut self) -> Result<u32> {
        let mut free = self.free_chunks();
        if free.is_empty() {
            self.grow()?;
            free = self.free_chunks();
        }
        if free.is_empty() {
            return Err(Error::NoSpace);
        }
        let c = free[rng::below(free.len() as u64) as usize];
        // Fresh random content: no stale data (e.g. anchors of vaults destroyed by
        // duress, freed lazily) survives into a reused chunk.
        self.randomize_chunk(c)?;
        self.set_allocated(c, true);
        Ok(c)
    }

    /// Return a chunk to the free pool and overwrite it with fresh random bytes.
    pub(crate) fn release_chunk(&mut self, chunk: u32) -> Result<()> {
        assert!(chunk >= self.cfg.superblock_chunks() && chunk < self.state.total_chunks);
        self.set_allocated(chunk, false);
        self.randomize_chunk(chunk)
    }

    pub(crate) fn randomize_chunk(&mut self, chunk: u32) -> Result<()> {
        let mut buf = vec![0u8; self.cfg.chunk_size as usize];
        rng::fill_bulk(&mut buf);
        let off = self.chunk_offset(chunk);
        self.storage.write_at(off, &buf)
    }

    /// Cover traffic: rewrite a few random free chunks with fresh random bytes.
    pub(crate) fn cover_traffic(&mut self) -> Result<()> {
        let mut free = self.free_chunks();
        rng::shuffle(&mut free);
        for &c in free.iter().take(self.cfg.cover_chunks_per_commit as usize) {
            self.randomize_chunk(c)?;
        }
        Ok(())
    }

    /// Mark a random `permille` fraction (drawn from the configured range) of the free
    /// chunks in `candidates` as allocated filler. Filler identity is not recorded.
    fn add_filler(&mut self, mut candidates: Vec<u32>, total: u32) -> Vec<u32> {
        let (lo, hi) = self.cfg.filler_permille;
        let permille = rng::range_inclusive(u64::from(lo), u64::from(hi));
        let n = (u64::from(total) * permille / 1000) as usize;
        rng::shuffle(&mut candidates);
        candidates.truncate(n);
        for &c in &candidates {
            self.set_allocated(c, true);
        }
        candidates
    }

    /// Overwrite the two anchor-record regions of `chunk` with random bytes, so a stale
    /// anchor of a destroyed vault cannot be found by an anchor scan.
    fn scrub_anchor_regions(&mut self, chunk: u32) -> Result<()> {
        let mut junk = vec![0u8; self.cfg.anchor_plain_len() + crate::crypto::AEAD_OVERHEAD];
        for half in 0..2u64 {
            rng::fill_bulk(&mut junk);
            let off = self.chunk_offset(chunk) + half * u64::from(self.cfg.chunk_size / 2);
            self.storage.write_at(off, &junk)?;
        }
        Ok(())
    }

    /// Grow to the next bucket: append random chunks and add filler among them.
    fn grow(&mut self) -> Result<()> {
        let cur = u64::from(self.state.total_chunks) * u64::from(self.cfg.chunk_size);
        let next = self
            .cfg
            .buckets
            .iter()
            .copied()
            .find(|&b| b > cur)
            .ok_or(Error::NoSpace)?;
        let new_total = (next / u64::from(self.cfg.chunk_size)) as u32;
        let old_total = self.state.total_chunks;
        for c in old_total..new_total {
            self.randomize_chunk(c)?;
        }
        self.state.total_chunks = new_total;
        self.add_filler((old_total..new_total).collect(), new_total - old_total);
        // The grown size must be durable before any chunk in it is referenced.
        self.persist()?;
        self.storage.sync()
    }

    fn state_offset(&self, copy: u64) -> u64 {
        (2 * TABLE_LEN + copy as usize * self.cfg.device_state_len()) as u64
    }

    fn state_aad(copy: u64) -> Vec<u8> {
        crypto::label(b"hidewell/devstate/v1", &[&[copy as u8]])
    }

    /// Write the device state to the older copy (generation + 1). Caller syncs.
    pub(crate) fn persist(&mut self) -> Result<()> {
        self.state.generation += 1;
        let copy = self.state.generation % 2;
        let pt = crate::index::to_padded(&self.state, self.cfg.device_state_plain_len())?;
        let mut out = vec![0u8; self.cfg.device_state_len()];
        crypto::seal_into(&self.device_key, &Self::state_aad(copy), &pt, &mut out);
        let off = self.state_offset(copy);
        self.storage.write_at(off, &out)
    }

    fn load_state(
        storage: &dyn Storage,
        cfg: &ContainerConfig,
        device_key: &SecretKey,
    ) -> Result<DeviceState> {
        let mut best: Option<DeviceState> = None;
        for copy in 0..2u64 {
            let mut buf = vec![0u8; cfg.device_state_len()];
            storage.read_at((2 * TABLE_LEN + copy as usize * buf.len()) as u64, &mut buf)?;
            let Ok(pt) = crypto::open(device_key, &Self::state_aad(copy), &buf) else {
                continue;
            };
            let s = decode_state(&pt)?;
            if s.generation % 2 != copy {
                return Err(Error::Corrupt);
            }
            if best.as_ref().is_none_or(|b| s.generation > b.generation) {
                best = Some(s);
            }
        }
        best.ok_or(Error::Corrupt)
    }

    fn table_offset(table: u8) -> u64 {
        u64::from(table) * TABLE_LEN as u64
    }

    pub(crate) fn read_table(&self) -> Result<Vec<u8>> {
        let mut t = vec![0u8; TABLE_LEN];
        self.storage
            .read_at(Self::table_offset(self.state.active_table), &mut t)?;
        Ok(t)
    }

    /// In-place write of one slot of the active table. Only used where a torn write is
    /// harmless (slot was unused, or is being destroyed).
    pub(crate) fn write_slot(&mut self, slot: u8, bytes: &[u8; SLOT_LEN]) -> Result<()> {
        let off = Self::table_offset(self.state.active_table) + u64::from(slot) * SLOT_LEN as u64;
        self.storage.write_at(off, bytes)
    }

    pub(crate) fn randomize_inactive_table(&mut self) -> Result<()> {
        let mut junk = vec![0u8; TABLE_LEN];
        rng::fill_bulk(&mut junk);
        self.storage
            .write_at(Self::table_offset(1 - self.state.active_table), &junk)
    }

    /// Atomically replace one slot: write the whole new table to the inactive copy,
    /// switch the active copy in the (A/B, crash-safe) device state, then overwrite the
    /// old table with random bytes so the superseded slot cannot be opened any more.
    pub(crate) fn replace_slot_atomic(&mut self, slot: u8, bytes: &[u8; SLOT_LEN]) -> Result<()> {
        let mut table = self.read_table()?;
        let i = slot as usize * SLOT_LEN;
        table[i..i + SLOT_LEN].copy_from_slice(bytes);
        let inactive = 1 - self.state.active_table;
        self.storage
            .write_at(Self::table_offset(inactive), &table)?;
        self.storage.sync()?;
        self.state.active_table = inactive;
        self.persist()?;
        self.storage.sync()?;
        self.randomize_inactive_table()?;
        self.storage.sync()
    }

    fn is_reserved(&self, slot: u8) -> bool {
        self.state.reserved_slots & (1 << slot) != 0
    }

    fn reserve(&mut self, slot: u8) {
        self.state.reserved_slots |= 1 << slot;
    }

    /// Drop a deleted vault's reservation.
    pub(crate) fn unreserve(&mut self, slot: u8) {
        self.state.reserved_slots &= !(1 << slot);
    }

    /// Mark a chunk free without overwriting it (lazy, like duress).
    pub(crate) fn free_chunk_lazy(&mut self, chunk: u32) {
        assert!(chunk >= self.cfg.superblock_chunks() && chunk < self.state.total_chunks);
        self.set_allocated(chunk, false);
    }

    /// Reserve a random number (configured range) of extra filler slots.
    fn reserve_filler_slots(&mut self) {
        let (lo, hi) = self.cfg.filler_slots;
        let n = rng::range_inclusive(u64::from(lo), u64::from(hi)) as usize;
        let mut free: Vec<u8> = (0..SLOT_COUNT as u8)
            .filter(|&s| !self.is_reserved(s))
            .collect();
        rng::shuffle(&mut free);
        for s in free.into_iter().take(n) {
            self.reserve(s);
        }
    }

    fn derive_unlock_key(&self, pattern: &Pattern) -> Result<SecretKey> {
        kdf::derive_unlock_key(
            self.oracle.as_ref(),
            pattern,
            &self.state.salt,
            &self.state.kdf,
        )
    }

    fn attempt_snapshot(&self) -> AttemptUndo {
        AttemptUndo {
            failed: self.state.failed_attempts,
            timing: self.state.timing,
        }
    }

    /// Apply each interval once. A different epoch establishes a new baseline with
    /// zero credit; a regressing tick retains the high-water mark so its rebound
    /// cannot count the same interval twice. Clock errors leave all debt untouched.
    fn refresh_clock(&mut self) -> Result<()> {
        let sample = self.oracle.clock_sample()?;
        let st = &mut self.state;
        let timing = &mut st.timing;
        if sample.epoch != timing.epoch {
            timing.epoch = sample.epoch;
            timing.elapsed_millis = sample.elapsed_millis;
        } else if sample.elapsed_millis >= timing.elapsed_millis {
            let elapsed = sample.elapsed_millis - timing.elapsed_millis;
            timing.elapsed_millis = sample.elapsed_millis;
            timing.retry_remaining_millis = timing.retry_remaining_millis.saturating_sub(elapsed);
            // Bounding elapsed avoids overflow even for a u64::MAX sample. Once all
            // failures are forgiven, any additional time has no policy effect.
            let decay_elapsed = elapsed.min(u64::from(st.failed_attempts) * FAILURE_DECAY_MILLIS);
            let progress = timing.decay_progress_millis + decay_elapsed;
            let forgiven = (progress / FAILURE_DECAY_MILLIS).min(u64::from(st.failed_attempts));
            st.failed_attempts -= forgiven as u32;
            timing.decay_progress_millis = if st.failed_attempts == 0 {
                0
            } else {
                progress % FAILURE_DECAY_MILLIS
            };
        }
        self.checkpoint_clock()
    }

    /// Timing getters may write: save epoch transitions and policy boundaries
    /// immediately, and partial waiting/decay progress every 30 seconds while polled.
    /// An old durable checkpoint remains safe: same-epoch reopen recomputes from it;
    /// a new epoch preserves its debt, losing at most uncheckpointed waiting credit.
    fn checkpoint_clock(&mut self) -> Result<()> {
        let now = self.attempt_snapshot();
        let old = self.clock_checkpoint;
        let has_debt = now.failed != 0 || old.failed != 0;
        let due = now.failed != old.failed
            || now.timing.epoch != old.timing.epoch
            || (old.timing.retry_remaining_millis != 0 && now.timing.retry_remaining_millis == 0)
            || now
                .timing
                .elapsed_millis
                .saturating_sub(old.timing.elapsed_millis)
                >= CLOCK_CHECKPOINT_MILLIS;
        if has_debt && due {
            self.persist_attempt_state()?;
        }
        Ok(())
    }

    /// Keep retrying the same state copy after a write/fsync error. Failed writes
    /// may still reach disk: advancing to the other copy before a successful sync
    /// could tear both copies and destroy the last durable checkpoint.
    fn persist_attempt_state(&mut self) -> Result<()> {
        let generation = self.state.generation;
        let result = self.persist().and_then(|()| self.storage.sync());
        if result.is_err() {
            self.state.generation = generation;
        } else {
            self.clock_checkpoint = self.attempt_snapshot();
        }
        result
    }

    /// Round up: a remaining fraction of a second still gates the next attempt.
    fn retry_after(&self) -> u64 {
        self.state.timing.retry_remaining_millis.div_ceil(1000)
    }

    /// Count an attempt durably BEFORE the KDF runs: enforce the retry delay,
    /// apply decay, increment the counter and fsync. Killing the process mid-attempt
    /// leaves it counted. A successful unlock only undoes its own increment
    /// ([`Self::undo_attempt`]); nothing resets the counter except setup, a
    /// phrase-authorised operation, or the wipe.
    fn begin_attempt(&mut self) -> Result<AttemptUndo> {
        self.refresh_clock()?;
        if self.retry_after() > 0 {
            return Err(Error::RetryLater);
        }
        let undo = self.attempt_snapshot();
        self.state.failed_attempts = undo.failed.saturating_add(1);
        self.state.timing.retry_remaining_millis =
            kdf::retry_delay(self.state.failed_attempts).as_millis() as u64;
        self.state.timing.decay_progress_millis = 0;
        self.persist_attempt_state()?;
        Ok(undo)
    }

    fn undo_attempt(&mut self, u: AttemptUndo) {
        self.state.failed_attempts = u.failed;
        self.state.timing = u.timing;
    }

    /// Phrase holders and setup clear the counter (full authority).
    fn clear_failures(&mut self) {
        self.state.failed_attempts = 0;
        self.state.timing.retry_remaining_millis = 0;
        self.state.timing.decay_progress_millis = 0;
    }

    /// After a counted attempt that did not unlock: apply the optional wipe.
    /// Returns true if the slot table was wiped.
    fn after_counted_attempt(&mut self) -> Result<bool> {
        if self.state.wipe_after == 0 || self.state.failed_attempts < self.state.wipe_after {
            return Ok(false);
        }
        self.wipe_slots()?;
        self.clear_failures();
        self.persist()?;
        self.storage.sync()?;
        Ok(true)
    }

    /// Check a new pattern, derive its unlock key once, and refuse patterns that already
    /// open a slot. Because `PatternInUse` reveals whether a pattern opens some vault,
    /// for pattern-gated callers this is a counted attempt exactly like a failed unlock
    /// (it would otherwise be a free oracle for probing hidden vaults' patterns).
    /// Phrase-authorised callers pass `counted = false`: the phrase is full authority.
    pub(crate) fn new_pattern_key(
        &mut self,
        pattern: &Pattern,
        counted: bool,
    ) -> Result<SecretKey> {
        pattern.check_policy()?;
        if strength::is_blocklisted(pattern) {
            return Err(Error::PatternBlocklisted);
        }
        if counted {
            self.begin_attempt()?;
        }
        let key = self.derive_unlock_key(pattern)?;
        let in_use = slots::trial_open(&key, &self.read_table()?)?.is_some();
        if counted && self.after_counted_attempt()? {
            return Err(Error::Wiped);
        }
        if in_use {
            return Err(Error::PatternInUse);
        }
        Ok(key)
    }

    fn local_entry_offset(&self, i: u8) -> u64 {
        (2 * TABLE_LEN + 2 * self.cfg.device_state_len()) as u64
            + u64::from(i) * backup::LOCAL_ENTRY_LEN as u64
    }

    fn local_entry_aad(i: u8) -> Vec<u8> {
        crypto::label(b"hidewell/local-entry/v1", &[&[i]])
    }

    /// Store manifest entry `i` locally, wrapped under the device key so the region is
    /// uniformly random.
    pub(crate) fn write_local_entry(&mut self, i: u8, hpke_entry: &[u8]) -> Result<()> {
        if hpke_entry.len() != backup::ENTRY_SEALED_LEN {
            return Err(Error::Corrupt);
        }
        let mut out = vec![0u8; backup::LOCAL_ENTRY_LEN];
        crypto::seal_into(
            &self.device_key,
            &Self::local_entry_aad(i),
            hpke_entry,
            &mut out,
        );
        let off = self.local_entry_offset(i);
        self.storage.write_at(off, &out)
    }

    pub(crate) fn write_local_filler(&mut self, i: u8) -> Result<()> {
        let f = backup::filler_entry(&self.state.backup_pk, i)?;
        self.write_local_entry(i, &f)
    }

    fn read_local_entry(&self, i: u8) -> Result<SecretVec> {
        let mut buf = vec![0u8; backup::LOCAL_ENTRY_LEN];
        self.storage.read_at(self.local_entry_offset(i), &mut buf)?;
        crypto::open(&self.device_key, &Self::local_entry_aad(i), &buf)
    }

    /// Create a vault in a random unreserved slot. Returns the open vault state.
    pub(crate) fn create_vault(
        &mut self,
        pattern: &Pattern,
        flags: u8,
        parent_keys: &[EntryKey],
    ) -> Result<VaultState> {
        let key = self.new_pattern_key(pattern, true)?;
        let free: Vec<u8> = (0..SLOT_COUNT as u8)
            .filter(|&s| !self.is_reserved(s))
            .collect();
        if free.is_empty() {
            return Err(Error::NoFreeSlot);
        }
        let slot = free[rng::below(free.len() as u64) as usize];
        let payload = SlotPayload {
            flags,
            anchor_chunk: self.alloc_chunk()?,
            master_key: SecretKey::random(),
        };
        // Data first (anchor + empty root; commit persists the bitmap), then the
        // reservation, then the slot: a crash leaves only unreferenced allocations.
        let keys = child_entry_keys(parent_keys, slot, flags & slots::FLAG_DURESS != 0);
        let state = VaultState::create(self, slot, &payload, keys)?;
        self.reserve(slot);
        self.persist()?;
        self.storage.sync()?;
        self.write_slot(slot, &slots::seal_slot(&key, slot, &payload))?;
        let entry = backup::vault_entry(
            &self.state.backup_pk,
            &state,
            state.root_ptr().ok_or(Error::Corrupt)?,
        )?;
        self.write_local_entry(slot, &entry)?;
        self.storage.sync()?;
        Ok(state)
    }

    /// Duress: destroy every other slot, rebuild the bitmap as decoy chunks ∪ fresh
    /// filler. Freed chunks keep their (undecryptable) bytes until reused or covered.
    /// Slot reservations are kept so later vaults never take a hidden vault's backup
    /// manifest index.
    fn duress(&mut self, keep_slot: u8, keep_chunks: &[u32]) -> Result<()> {
        for s in 0..SLOT_COUNT as u8 {
            if s != keep_slot {
                self.write_slot(s, &slots::random_slot())?;
            }
        }
        self.randomize_inactive_table()?;
        self.storage.sync()?;
        let sb = self.cfg.superblock_chunks();
        self.state.bitmap.iter_mut().for_each(|b| *b = 0);
        for c in 0..sb {
            self.set_allocated(c, true);
        }
        for &c in keep_chunks {
            self.set_allocated(c, true);
        }
        let total = self.state.total_chunks;
        let cand = self.free_chunks();
        for c in self.add_filler(cand, total - sb) {
            self.scrub_anchor_regions(c)?;
        }
        self.epoch += 1;
        self.persist()?;
        self.storage.sync()
    }

    fn wipe_slots(&mut self) -> Result<()> {
        for s in 0..SLOT_COUNT as u8 {
            self.write_slot(s, &slots::random_slot())?;
        }
        self.randomize_inactive_table()?;
        self.epoch += 1;
        self.storage.sync()
    }
}

/// Result of first-time setup.
pub struct Created {
    /// The device handle.
    pub device: Device,
    /// Hardware-sealed device secret; the platform must persist it outside the
    /// container (e.g. Keychain ThisDeviceOnly / app-private file) and pass it to
    /// [`Device::open`].
    pub sealed_device_secret: Vec<u8>,
    /// The first vault, unlocked.
    pub vault: Vault,
    /// Initial backup manifest: one filler entry per slot. Upload each only if no
    /// object with that name exists yet (never overwrite existing entries).
    pub initial_entries: Vec<(String, Vec<u8>)>,
}

/// An opened (not unlocked) device container. Cheap to clone.
#[derive(Clone)]
pub struct Device {
    pub(crate) inner: Arc<Mutex<DeviceInner>>,
}

pub(crate) fn lock(inner: &Mutex<DeviceInner>) -> Result<MutexGuard<'_, DeviceInner>> {
    let g = inner.lock().map_err(|_| Error::Locked)?;
    if g.erased {
        return Err(Error::Locked);
    }
    Ok(g)
}

impl Device {
    fn init(
        mut storage: Box<dyn Storage>,
        oracle: Arc<dyn HardwareOracle>,
        cfg: ContainerConfig,
        params: KdfParams,
        backup_pk: [u8; 32],
    ) -> Result<(DeviceInner, Vec<u8>)> {
        cfg.validate()?;
        params.validate()?;
        if !storage.is_empty()? {
            return Err(Error::InvalidArgument);
        }
        let timing = AttemptTiming::new(oracle.clock_sample()?);
        let secret = SecretKey::random();
        let sealed = oracle.seal_device_secret(secret.expose().to_vec())?;
        let device_key = crypto::hkdf32(secret.expose(), &[b"hidewell/device-state/v1"]);
        let total = (cfg.buckets[0] / u64::from(cfg.chunk_size)) as u32;
        // Uniform random fill of the whole container (superblock included).
        let mut buf = vec![0u8; cfg.chunk_size as usize];
        for c in 0..total {
            rng::fill_bulk(&mut buf);
            storage.write_at(u64::from(c) * u64::from(cfg.chunk_size), &buf)?;
        }
        let state = DeviceState {
            version: STATE_VERSION,
            generation: 0,
            salt: rng::array(),
            kdf: params,
            total_chunks: total,
            bitmap: vec![0u8; cfg.bitmap_len()],
            reserved_slots: 0,
            backup_pk,
            failed_attempts: 0,
            wipe_after: 0,
            active_table: 0,
            timing,
        };
        let mut d = DeviceInner {
            storage,
            cfg,
            oracle,
            device_key,
            state,
            clock_checkpoint: AttemptUndo { failed: 0, timing },
            epoch: 0,
            vault_handle_generations: [0; SLOT_COUNT],
            erased: false,
        };
        let sb = d.cfg.superblock_chunks();
        for c in 0..sb {
            d.set_allocated(c, true);
        }
        let cand = d.free_chunks();
        d.add_filler(cand, total - sb);
        d.persist()?;
        for i in 0..SLOT_COUNT as u8 {
            d.write_local_filler(i)?;
        }
        d.storage.sync()?;
        Ok((d, sealed))
    }

    /// First-time setup: new container, device secret, first vault and filler manifest.
    /// `storage` must be empty. `params` come from [`crate::kdf::calibrate`].
    pub fn create(
        storage: Box<dyn Storage>,
        oracle: Arc<dyn HardwareOracle>,
        cfg: ContainerConfig,
        params: KdfParams,
        phrase: &RecoveryPhrase,
        pattern: &Pattern,
    ) -> Result<Created> {
        let pk = phrase.backup_keypair().pk;
        let (mut d, sealed) = Self::init(storage, oracle, cfg, params, pk)?;
        let all_keys: Vec<EntryKey> = (0..SLOT_COUNT as u8)
            .map(|i| EntryKey {
                index: i,
                key: *phrase.entry_auth_key(i).expose(),
            })
            .collect();
        let state = d.create_vault(pattern, 0, &all_keys)?;
        // Setup: no vault existed to probe, so the counted check above is cleared.
        d.clear_failures();
        d.reserve_filler_slots();
        d.persist()?;
        d.storage.sync()?;
        let initial_entries = (0..SLOT_COUNT as u8)
            .map(|i| Ok((backup::entry_object_name(i), backup::filler_entry(&pk, i)?)))
            .collect::<Result<_>>()?;
        let device = Device {
            inner: Arc::new(Mutex::new(d)),
        };
        let vault = Vault::new(device.inner.clone(), state);
        Ok(Created {
            device,
            sealed_device_secret: sealed,
            vault,
            initial_entries,
        })
    }

    /// Set up a fresh container for restore from the phrase. Reserves the slots of every
    /// real manifest entry (`real_indices` from [`crate::backup::scan`]) plus filler,
    /// so vaults not restored yet keep their manifest index. Restore each vault with
    /// [`Device::restore_vault`]. Returns the device and the sealed device secret.
    pub fn create_for_restore(
        storage: Box<dyn Storage>,
        oracle: Arc<dyn HardwareOracle>,
        cfg: ContainerConfig,
        params: KdfParams,
        phrase: &RecoveryPhrase,
        real_indices: &[u8],
    ) -> Result<(Device, Vec<u8>)> {
        if real_indices.iter().any(|&i| i as usize >= SLOT_COUNT) {
            return Err(Error::InvalidArgument);
        }
        let pk = phrase.backup_keypair().pk;
        let (mut d, sealed) = Self::init(storage, oracle, cfg, params, pk)?;
        for &i in real_indices {
            d.reserve(i);
        }
        d.reserve_filler_slots();
        d.persist()?;
        d.storage.sync()?;
        Ok((
            Device {
                inner: Arc::new(Mutex::new(d)),
            },
            sealed,
        ))
    }

    /// Open an existing container with the platform-stored sealed device secret.
    /// The caller must hold exclusive ownership of this storage for this device's
    /// lifetime (including its vaults and writers). Clone this handle to share it;
    /// do not independently open the same storage in another device.
    pub fn open(
        storage: Box<dyn Storage>,
        oracle: Arc<dyn HardwareOracle>,
        cfg: ContainerConfig,
        sealed_device_secret: &[u8],
    ) -> Result<Device> {
        cfg.validate()?;
        let secret = SecretVec::new(oracle.open_device_secret(sealed_device_secret.to_vec())?);
        let secret = SecretKey::from_slice(&secret).ok_or(Error::Corrupt)?;
        let device_key = crypto::hkdf32(secret.expose(), &[b"hidewell/device-state/v1"]);
        let state = DeviceInner::load_state(storage.as_ref(), &cfg, &device_key)?;
        state.kdf.validate()?;
        let len = storage.len()?;
        let committed_len = u64::from(state.total_chunks) * u64::from(cfg.chunk_size);
        // Growth writes the appended chunks before publishing the new total. A torn
        // write or disk-full error may leave any length up to the next bucket. The
        // authenticated committed size remains authoritative; grow() rewrites the
        // entire uncommitted tail before making any of it available for allocation.
        let growth_limit = cfg
            .buckets
            .iter()
            .copied()
            .find(|&bucket| bucket > committed_len)
            .unwrap_or(committed_len);
        let ok = state.version == STATE_VERSION
            && state.active_table <= 1
            && state.bitmap.len() == cfg.bitmap_len()
            && cfg.buckets.contains(&committed_len)
            && (committed_len..=growth_limit).contains(&len);
        if !ok {
            return Err(Error::Corrupt);
        }
        let clock_checkpoint = AttemptUndo {
            failed: state.failed_attempts,
            timing: state.timing,
        };
        let mut inner = DeviceInner {
            storage,
            cfg,
            oracle,
            device_key,
            state,
            clock_checkpoint,
            epoch: 0,
            vault_handle_generations: [0; SLOT_COUNT],
            erased: false,
        };
        inner.refresh_clock()?;
        Ok(Device {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Try a pattern. Runs the hardware chain and Argon2id exactly once and trial-decrypts
    /// all 16 slots. A duress pattern opens its decoy vault and destroys every other
    /// slot before returning. Wrong patterns count towards the optional wipe.
    /// Opening a vault invalidates any earlier handle to that same vault and its
    /// unfinished writers; those handles return [`Error::Locked`].
    ///
    /// A pattern failing the structural policy ([`Pattern::check_policy`]) is rejected
    /// with [`Error::Pattern`] before anything is counted or derived: every sealed slot
    /// passed that policy, so it cannot open a vault.
    pub fn unlock(&self, pattern: &Pattern) -> Result<Vault> {
        pattern.check_policy()?;
        let mut d = lock(&self.inner)?;
        let undo = d.begin_attempt()?;
        let key = d.derive_unlock_key(pattern)?;
        let table = d.read_table()?;
        let Some((slot, payload)) = slots::trial_open(&key, &table)? else {
            if d.after_counted_attempt()? {
                return Err(Error::Wiped);
            }
            return Err(Error::WrongPattern);
        };
        // A matching slot was not a guess: undo only this attempt's count, never
        // earlier failures, even if the vault's data then fails to load.
        d.undo_attempt(undo);
        let state = match VaultState::load(&d, slot, &payload) {
            Ok(state) => state,
            Err(e) => {
                d.persist_attempt_state()?;
                return Err(e);
            }
        };
        if payload.is_duress() {
            let chunks = state.physical_chunks();
            d.duress(slot, &chunks)?;
        }
        // Clear any stale inactive slot table left by an interrupted pattern change.
        d.randomize_inactive_table()?;
        d.persist()?;
        d.storage.sync()?;
        let mut state = state;
        state.epoch = d.epoch;
        state.claim_handle(&mut d);
        drop(d);
        Ok(Vault::new(self.inner.clone(), state))
    }

    /// Current counted failures after time decay (failed unlocks and new-pattern
    /// checks). May checkpoint monotonic timing progress to storage.
    pub fn failed_attempts(&self) -> Result<u32> {
        let mut d = lock(&self.inner)?;
        d.refresh_clock()?;
        Ok(d.state.failed_attempts)
    }

    /// Seconds until the next pattern attempt is accepted; attempts before that fail
    /// with [`Error::RetryLater`] without running the KDF. May checkpoint monotonic
    /// timing progress to storage; clock or checkpoint errors are returned to callers.
    pub fn retry_after_seconds(&self) -> Result<u64> {
        let mut d = lock(&self.inner)?;
        d.refresh_clock()?;
        Ok(d.retry_after())
    }

    /// Hardware security level of the oracle.
    pub fn security_level(&self) -> Result<SecurityLevel> {
        Ok(lock(&self.inner)?.oracle.security_level())
    }

    /// This device's unlock protection parameters, for display. Read from the
    /// loaded device state; device-wide, so it reveals nothing about any vault.
    pub fn protection_info(&self) -> Result<ProtectionInfo> {
        let d = lock(&self.inner)?;
        let k = d.state.kdf;
        Ok(ProtectionInfo {
            security_level: d.oracle.security_level(),
            chain_steps: k.chain_steps,
            argon2_memory_kib: k.argon_m_kib,
            argon2_passes: k.argon_t,
            argon2_lanes: k.argon_p,
            estimated_attempt_millis: None,
        })
    }

    /// Backup namespace (cloud folder name) for this device's phrase.
    pub fn backup_namespace(&self) -> Result<String> {
        Ok(backup::namespace(&lock(&self.inner)?.state.backup_pk))
    }

    /// After executing the cloud plan returned by `Vault::delete` (its filler entry
    /// written), release the deleted vault's slot reservation so a new vault may use it.
    /// Until then the slot stays reserved, so no new vault can take an index whose
    /// cloud entry is still real. Ignores non-deletion plans. Not calling it only
    /// costs a slot.
    pub fn confirm_vault_deleted(&self, plan: &backup::SyncPlan) -> Result<()> {
        let Some(slot) = plan.deleted_slot() else {
            return Ok(());
        };
        let mut d = lock(&self.inner)?;
        d.unreserve(slot);
        d.persist()?;
        d.storage.sync()
    }

    /// Restore vault `index` from the cloud with only the phrase, protecting it with a
    /// new pattern. `listing` is the set of object names in the backup namespace.
    /// Works on a fresh restore container and on an existing one where that vault is
    /// absent (e.g. after duress, or restoring later); refuses with
    /// `VaultAlreadyPresent` if the vault is live here.
    pub fn restore_vault(
        &self,
        phrase: &RecoveryPhrase,
        index: u8,
        pattern: &Pattern,
        listing: &[String],
        source: &dyn ObjectSource,
    ) -> Result<()> {
        if index as usize >= SLOT_COUNT {
            return Err(Error::InvalidArgument);
        }
        let kp = phrase.backup_keypair();
        let mut d = lock(&self.inner)?;
        if kp.pk != d.state.backup_pk {
            return Err(Error::InvalidPhrase);
        }
        let bytes = source.get(&backup::entry_object_name(index))?;
        let entry = backup::open_entry(phrase, &kp, index, &bytes)?.ok_or(Error::NotFound)?;
        // Never overwrite a live vault. The same vault is found by its anchor
        // (master-key trial, no new state); a different live vault cannot hold slot
        // `index` while entry `index` is real, because reservations are only released
        // after the entry has been replaced by filler (duress/wipe keep them; deletion
        // keeps them until `confirm_vault_deleted`).
        if VaultState::locate_anchor(&d, &entry.master_key).is_some() {
            return Err(Error::VaultAlreadyPresent);
        }
        // Phrase-authorised: not a counted attempt, and clears the counter.
        let key = d.new_pattern_key(pattern, false)?;
        let payload = SlotPayload {
            flags: entry.flags,
            anchor_chunk: d.alloc_chunk()?,
            master_key: entry.master_key,
        };
        VaultState::restore(&mut d, index, &payload, entry.root, listing, source)?;
        d.reserve(index);
        d.clear_failures();
        d.persist()?;
        d.storage.sync()?;
        d.write_slot(index, &slots::seal_slot(&key, index, &payload))?;
        let local = backup::seal_entry(
            &kp.pk,
            index,
            payload.flags,
            &payload.master_key,
            entry.root,
            &phrase.entry_auth_key(index),
        )?;
        d.write_local_entry(index, &local)?;
        d.storage.sync()
    }

    /// Check a recovery phrase against this device without storing or counting
    /// anything: derives the backup public key and compares it in constant time.
    pub fn verify_phrase(&self, phrase: &RecoveryPhrase) -> Result<bool> {
        use subtle::ConstantTimeEq;
        let pk = phrase.backup_keypair().pk;
        let d = lock(&self.inner)?;
        Ok(bool::from(pk.ct_eq(&d.state.backup_pk)))
    }

    /// Forgotten-pattern recovery, step 1: with the phrase, list the vaults whose
    /// local manifest entry (kept in the container, no cloud needed) is real and
    /// authentic, whether their data is present on this device, and whether each is a
    /// duress vault (the phrase holder is the owner and entitled to know).
    pub fn recover_with_phrase(&self, phrase: &RecoveryPhrase) -> Result<Vec<RecoverableVault>> {
        let kp = phrase.backup_keypair();
        let d = lock(&self.inner)?;
        if kp.pk != d.state.backup_pk {
            return Err(Error::InvalidPhrase);
        }
        let mut out = Vec::new();
        for i in 0..SLOT_COUNT as u8 {
            let local = d.read_local_entry(i)?;
            if let Some(e) = backup::open_entry(phrase, &kp, i, &local)? {
                out.push(RecoverableVault {
                    index: i,
                    present_locally: VaultState::locate_anchor(&d, &e.master_key).is_some(),
                    is_duress: e.flags & slots::FLAG_DURESS != 0,
                });
            }
        }
        Ok(out)
    }

    /// Forgotten-pattern recovery, step 2: give vault `index` (present locally)
    /// a new pattern using the phrase. Not a counted attempt; the vault keeps its role
    /// (a duress vault stays a duress vault). `NotFound` if its data is not on this
    /// device: use `restore_vault` from the cloud instead. Invalidates existing
    /// handles to that vault and their unfinished writers.
    pub fn reset_pattern_with_phrase(
        &self,
        phrase: &RecoveryPhrase,
        index: u8,
        pattern: &Pattern,
    ) -> Result<()> {
        if index as usize >= SLOT_COUNT {
            return Err(Error::InvalidArgument);
        }
        let kp = phrase.backup_keypair();
        let mut d = lock(&self.inner)?;
        if kp.pk != d.state.backup_pk {
            return Err(Error::InvalidPhrase);
        }
        let local = d.read_local_entry(index)?;
        let entry = backup::open_entry(phrase, &kp, index, &local)?.ok_or(Error::NotFound)?;
        let anchor = VaultState::locate_anchor(&d, &entry.master_key).ok_or(Error::NotFound)?;
        let key = d.new_pattern_key(pattern, false)?;
        let payload = SlotPayload {
            flags: entry.flags,
            anchor_chunk: anchor,
            master_key: entry.master_key,
        };
        // The data must load before the slot is rewritten.
        drop(VaultState::load(&d, index, &payload)?);
        d.replace_slot_atomic(index, &slots::seal_slot(&key, index, &payload))?;
        d.claim_vault_handle(index);
        d.reserve(index);
        d.clear_failures();
        d.persist()?;
        d.storage.sync()
    }

    /// Erase this container's keys: overwrite the whole superblock (both slot
    /// tables, both device-state copies, the local manifest entries) with random bytes
    /// and fsync. Afterwards nothing in the file can be opened, by pattern or phrase
    /// (cloud backups are untouched); this handle and its vaults return `Locked`. The
    /// platform should then delete the file, the sealed device secret and the hardware
    /// keys.
    pub fn erase(&self) -> Result<()> {
        let mut d = lock(&self.inner)?;
        for c in 0..d.cfg.superblock_chunks() {
            d.randomize_chunk(c)?;
        }
        d.storage.sync()?;
        d.epoch += 1;
        d.erased = true;
        Ok(())
    }
}

/// A vault found by [`Device::recover_with_phrase`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverableVault {
    /// Manifest / slot index.
    pub index: u8,
    /// Its data is on this device (reset its pattern with
    /// [`Device::reset_pattern_with_phrase`]); otherwise restore it from the cloud.
    pub present_locally: bool,
    /// It is a duress (decoy) vault.
    pub is_duress: bool,
}
