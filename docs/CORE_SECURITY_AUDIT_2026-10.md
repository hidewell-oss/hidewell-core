# Hidewell Rust Core: Security Review Report, October 2026

Date of review: 2026-10-20
Subject: `hidewell-core` and `hidewell-ffi` (this repository), as published in its initial release
Report version: 1.1

## 1. Executive summary

This report documents an independent, line-by-line security and correctness review of the Hidewell Rust core, the library that implements the encrypted container, the pattern-based unlock, the hidden key slots, attempt enforcement, and the phrase-keyed backup used by the iOS and Android apps. The review was conducted on 2026-10-20 by Claude Fable 5.1 (Anthropic), commissioned and scoped by the project maintainer. Provenance and the limits of the method are stated in section 3.

Overall assessment: the core's cryptographic construction (authenticated encryption with role-binding AAD, hardware-bound KDF chain, uniform-looking container) is consistent with its security documents (`SECURITY.md`, `THREAT_MODEL.md`). The review found one High-severity design defect (attempt throttling based on the device wall clock) and several Medium-severity correctness defects in crash recovery, handle lifecycle, metadata consistency and attempt accounting. Every defect with a code fix is fixed in the released code and covered by a test named under its finding. The remaining items are documented limitations that the maintainer accepted, plus one open item.

| Severity | Found | Fixed | Accepted risk | Open |
| --- | --- | --- | --- | --- |
| Critical | 0 | 0 | 0 | 0 |
| High | 1 | 1 | 0 | 0 |
| Medium | 6 | 5 | 1 | 0 |
| Low | 6 | 2 | 3 | 1 |
| Informational | 4 | 2 | 2 | 0 |
| Total | 17 | 10 | 6 | 1 |

## 2. Scope

In scope (modules and features):

- `hidewell-core` (library, about 10k lines including tests): `backup.rs`, `config.rs`, `crypto.rs`, `device.rs`, `device_clock_tests.rs`, `error.rs`, `index.rs`, `kdf.rs`, `lib.rs`, `mock.rs`, `oracle.rs`, `pattern.rs`, `phrase.rs`, `rng.rs`, `secret.rs`, `slots.rs`, `storage.rs`, `strength.rs`, `tests.rs`, `vault.rs`, `tests/container.rs`, `tests/bench_unlock.rs`. Features: container format and commit protocol, pattern KDF and key slots, attempt enforcement, duress and managed decoys, deletion and restore, backup manifest and sync plans, phrase recovery, secret hygiene and error redaction.
- `hidewell-ffi` (UniFFI bindings): `src/lib.rs`, plus the generated Kotlin and Swift sources under `bindings/`.
- `uniffi-bindgen` (two 5-line binary wrappers).
- Security documents: `docs/SECURITY.md`, `docs/THREAT_MODEL.md`.

Not covered by the review: the following features of the released code postdate the review and were verified only by their own tests, not by this reading: in-place content replacement (`Vault::replace_content`), vault display names (`Vault::name`/`set_name`, index v4), protection info for display (`Device::protection_info`), the uncounted rejection of sub-policy patterns at unlock, the fix for HW-C-10 (name and MIME length caps, FFI `limits()`), and the fuzzing harness (`fuzz/`, `fuzz_api.rs`).

Out of scope:

- The iOS and Android applications (Swift/Kotlin), including their `HardwareOracle` and clock implementations. They are tested privately and are not covered by this report.
- Cryptanalysis of the primitives or of the construction beyond checking that the primitives are standard, used through maintained RustCrypto/`hpke` crates, and bound correctly (AAD, domain separation, key derivation).
- Side-channel measurement (timing, power, cache). Constant-time comparisons were checked by inspection only.
- Fuzzing. The repository ships libFuzzer targets for the untrusted-input decoders (see recommendation 2 for the initial campaign); the review itself relied on reading and on the property-based tests (`proptest`) for pattern encoding/decoding, phrase word round trips, slot trial decryption, the strength meter, random-access reads, in-place content replacement and allocation invariants.
- Supply-chain review of dependencies (versions were recorded, not audited).
- Hardware oracle implementations (Secure Enclave, StrongBox/TEE): the core only sees a trait.

## 3. Methodology and provenance

About this review: the review was conducted entirely by Claude Fable 5.1, an AI model by Anthropic, on 2026-10-20. The project maintainer commissioned the review, set its priorities (encryption and file-vault threat model first, correctness second, cleanliness third) and decided which findings were accepted as risks; the reading, testing, fixing and reporting were done by the model. The model has no stake in the project. The core was not authored by this model, so author and reviewer are distinct. No other reviewer was engaged and no individual signs this report; as with any commissioned audit, the report carries no warranty or liability. Readers should weigh it on the disclosed method and the reproducible evidence (the tests named under each finding, the test runs in section 7) rather than on the reviewer's identity.

Method:

1. Full-file reads of all Rust source files in the workspace (no sampling), with the security documents open, checking each security-relevant operation against the documented invariants (AAD contents, commit ordering, fsync points, bounds checks, counter semantics).
2. Two passes: one focused on storage consistency, handle lifecycle and the attempt-throttling design, then a fresh correctness-first, cleanliness-second reading of the whole core, including an adversarial re-review of the security-relevant changes made for the earlier findings.
3. Test-driven confirmation: every defect that was fixed was first reproduced by a failing test against the defective code (for example, the zero-block-size test was observed to panic inside `ContainerConfig::validate()`; the attempt-counting test observed the counter rising from 1 to 4).
4. Tooling on every change: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked --features mock-oracle -- -D warnings` (and the CI invocation without the feature), `cargo test --workspace --locked`, and `scripts/check-log-scrub.sh` (grep-based check that no logging macro exists in shipped code). Toolchain: rustc 1.92.0.
5. Crash and fault injection through test storage implementations (`FaultStorage`, `GrowthFaultStorage`, `CrashDisk`) that tear writes, fail fsync, or model a volatile write cache; attempt timing through the deterministic `MockOracle` clock (no sleeping, no OS clock changes).

Limits of the method: a code read can miss defects, particularly in the cryptographic construction, in concurrency under real platform schedulers, and in the interaction with platform storage semantics (fsync behaviour of the actual file systems was not measured). Test coverage was extended but not measured with a coverage tool. Findings are reported as observed in the code; severity ratings are the reviewer's judgement.

## 4. System overview as reviewed

### 4.1 Container layout

One file per device (`FileStorage` on Unix; `MemStorage` in tests), uniformly random-looking:

- Superblock (first `superblock_chunks` chunks; 1 chunk in production): slot table A, slot table B (16 slots of 76 bytes each), two device-state copies, 16 local manifest entries. Everything not in use is random.
- Chunks of 4 MiB (production), sub-allocated in 64 KiB blocks; a global allocation bitmap sized for the largest bucket lives in the device state. Container size grows through fixed buckets (1, 4, 16, 64 GiB). At setup and on growth, 5 to 15 percent of free chunks are marked as filler; every commit rewrites two random free chunks with fresh random bytes (cover traffic).
- Per vault, inside vault-owned chunks: an anchor chunk holding two fixed-size A/B anchor records (generation, root pointer, last uploaded root, logical-to-physical chunk map); a root blob (counters, chunk versions, page table, albums, tags, decoy links, backup entry keys); page blobs of up to 128 items; content and thumbnail streams in 1 MiB segments (`segment_blocks * block_size`, minus 28 bytes of AEAD overhead).
- Commit protocol (write-new-then-switch): new blobs go to blocks free in both old and new state; device state (bitmap) persisted and fsynced; anchor written to the older A/B copy with generation + 1 and fsynced (the switch); then superseded blocks are scrubbed, emptied chunks released and randomised, cover traffic written, device state persisted again.
- Device state is also A/B: `nonce || AES-256-GCM(device_key, padded state, aad = "hidewell/devstate/v1" || copy)`; the copy with the higher valid generation wins; writes alternate copies.

### 4.2 Key hierarchy

- Hardware oracle (`HardwareOracle` trait, platform-implemented): `chain_step` (32 bytes in/out; iOS: Secure Enclave ECDH against `p256_hash_to_curve(input)`, RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` with DST `HIDEWELL-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_`; Android: HMAC-SHA256 under a StrongBox/TEE key), `seal_device_secret` / `open_device_secret` (not pattern-gated), `clock_sample`, `security_level`.
- Pattern KDF (`kdf.rs`): `s_0 = SHA-256("hidewell/chain/init/v1" || encode(pattern))`; `k` hardware chain steps with per-step SHA-256 domain separation; `unlock = Argon2id(s_k, 32-byte device salt, m, t, p)`; per-slot `KEK_i = HKDF-SHA256(unlock, "hidewell/kek/v1" || i)`. The chain and Argon2id run exactly once per attempt. Parameters are calibrated per device; release builds enforce m >= 64 MiB, 4 <= k <= 2048, m <= 1 GiB, t <= 64, 1 <= p <= 16. Test parameters are only accepted when compiled with `cfg(test)` or the `mock-oracle` feature, which `compile_error!`s in builds without debug assertions.
- Key slots (`slots.rs`): 16 slots of `nonce(12) || AES-256-GCM(KEK_i, 48-byte payload, aad = "hidewell/slot/v1" || i)`; payload = version, flags (duress), anchor chunk, 32-byte vault master key. Unused slots are random. Unlock trial-decrypts all 16 slots without early exit; more than one match is reported as corruption.
- Vault keys: `HKDF-SHA256(master_key, info)` for vault id (16 bytes), anchor key, index key, content key, object-name key.
- Device state key: `device_key = HKDF-SHA256(device_secret, "hidewell/device-state/v1")`, where `device_secret` is 32 random bytes sealed by the hardware oracle and stored by the platform outside the container.
- Recovery phrase (`phrase.rs`): 12 English BIP39 words (128-bit entropy); `recovery_key = HKDF(entropy, "hidewell/recovery/v1")`; backup X25519 key pair derived from it; per-index entry authentication keys `K_i = HKDF(recovery_key, "hidewell/entry-auth/v1" || i)`. The device stores only the backup public key.
- Backup manifest (`backup.rs`): 16 fixed entries, each `HPKE-Seal(backup_pk, info = "hidewell/manifest/v1" || i, 128-byte plaintext)` in base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM; real entries carry an HMAC-SHA256 tag under `K_i`, filler entries are random. Chunk objects are raw container chunks named by `AES-256-GCM(names_key, logical || version)` in hex. Local copies of the entries are stored in the superblock wrapped under the device key.

### 4.3 Primitives and crates (from `hidewell-core/Cargo.toml` and `hidewell-ffi/Cargo.toml`)

| Purpose | Crate (version) | Algorithm |
| --- | --- | --- |
| AEAD | `aes-gcm` 0.11.1 | AES-256-GCM, random 96-bit nonce, 128-bit tag |
| Password hashing | `argon2` 0.6.0 | Argon2id v0x13 |
| Key derivation | `hkdf` 0.13.0, `sha2` 0.11.1 | HKDF-SHA256, SHA-256 |
| MAC | `hmac` 0.13.0 | HMAC-SHA256 |
| Backup envelope | `hpke` 0.14.1 | DHKEM(X25519, HKDF-SHA256), AES-256-GCM |
| Hash-to-curve | `p256` 0.14.0 | RFC 9380 P-256 SSWU RO |
| Phrase | `bip39` 3.0.0 | BIP39 English, 12 words |
| Randomness | `getrandom` 0.4.3, `chacha20` 0.10.2, `rand_core` 0.10.1 | OS CSPRNG; ChaCha20 stream seeded per call for bulk fill; RNG failure panics (fail closed) |
| Serialisation | `postcard` 1.1.3, `serde` 1.0.229 | strict decoding, trailing bytes rejected |
| Secret hygiene | `zeroize` 1.9.1, `region` 4.0.1, `subtle` 2.6.1 | zeroize on drop, best-effort mlock, constant-time equality |
| FFI | `uniffi` 0.32.2 | Swift and Kotlin bindings |

`#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` are set on the core crate.

### 4.4 Attempt enforcement (device state v4)

Every pattern-gated trial (unlock, and the `PatternInUse` check in vault creation and pattern change) increments `failed_attempts`, sets `retry_remaining_millis = retry_delay(failed)`, resets partial decay progress, and persists and fsyncs the device state before the hardware chain and Argon2id run. Delay: none below 5 failures, then 30 s doubling, capped at 1 h. Optional wipe-after-N overwrites both slot tables with random bytes when the count reaches N and returns `Wiped` once. Failures decay by one per 4 h of trusted elapsed time.

Time comes only from `HardwareOracle::clock_sample` (16-byte epoch plus monotonic milliseconds). The authenticated device state stores the last applied epoch/tick, the remaining retry debt and the partial decay progress. Same-epoch, non-regressing samples earn credit once; regressions keep the high-water mark; a different epoch resets the baseline without credit; clock errors fail the operation (never treated as an expired wait). Timing queries checkpoint every 30 s while polled and immediately on epoch changes, forgiven failures and completed delays. A failed checkpoint write or fsync keeps the in-memory generation so the retry targets the same older copy. Decoded states are validated (`version == 4`, `decay_progress < 4 h`, `retry_remaining <= retry_delay(failed)`, no decay progress without failures); earlier formats are rejected.

### 4.5 Duress, decoys, deletion and ownership

A slot flagged duress opens its decoy vault and destroys every other slot, rebuilds the bitmap as decoy chunks plus fresh filler, scrubs anchor regions of filler chunks, and bumps an in-memory epoch so existing handles return `Locked`. The creating vault keeps a `DecoyLink` (slot, anchor, master key) in its encrypted root so the decoy can be managed without the wipe. Deleting a vault overwrites its slot and local entry, randomises its anchor chunk, frees its chunks lazily and keeps the slot reservation until the cloud entry has been replaced by filler.

Exclusive ownership: one `Device` (and its clones, which share one mutex) must own a container; independent `Device`s on the same storage are unsupported. Within one device, opening a vault invalidates earlier handles to the same slot and their writers (per-slot handle generations).

## 5. Findings

Status values: "Fixed before release" (the defect is absent from the released code and the named tests cover it), "Accepted risk" (documented limitation, decided by the maintainer), "Open".

### 5.1 Summary table

| ID | Severity | Status | Title |
| --- | --- | --- | --- |
| HW-C-01 | High | Fixed before release | Attempt throttling and decay used the device wall clock |
| HW-C-02 | Medium | Fixed before release | Re-unlocking a vault produced two live mutable snapshots |
| HW-C-03 | Medium | Fixed before release | Interrupted container growth made the container unopenable |
| HW-C-04 | Medium | Fixed before release | Root `BlobRef` block count taken from the size estimate |
| HW-C-05 | Medium | Fixed before release | Failed checkpoint write advanced to the other state copy |
| HW-C-06 | Low | Fixed before release | `ContainerConfig::validate()` divided before checking sizes |
| HW-C-07 | Medium | Fixed before release | Correct pattern on an unloadable vault counted as a failed attempt |
| HW-C-08 | Informational | Fixed before release | Redundant zeroize loops in `VaultState::drop` |
| HW-C-09 | Informational | Fixed before release | `ItemWriter` documented as sized-only |
| HW-C-10 | Low | Fixed before release | Unbounded item/album/tag names can poison a vault handle |
| HW-C-11 | Low | Accepted risk | Chunk allocations leak when restore or vault creation fails midway |
| HW-C-12 | Informational | Accepted risk | Crash between anchor switch and cleanup leaks chunks as filler |
| HW-C-13 | Medium | Accepted risk | Whole-container rollback restores older counters and timing |
| HW-C-14 | Low | Accepted risk | Exclusive-ownership contract is not enforced by the core |
| HW-C-15 | Low | Accepted risk | Failure decay permits about six wrong guesses per day indefinitely |
| HW-C-16 | Informational | Accepted risk | Unverified epochs extend waits after restarts |
| HW-C-17 | Low | Open | Transient secret copies at and beyond the FFI boundary |

### 5.2 Fixed findings

#### HW-C-01 Attempt throttling and decay used the device wall clock

- Severity: High. Status: Fixed before release.
- Location: `hidewell-core/src/device.rs` (`DeviceInner::now`, `decayed`, `retry_after`, `begin_attempt`; wall-clock timestamp fields in the device state).
- Description: retry delays and the 4 h failure decay were computed from `SystemTime::now()` (Unix seconds) stored in the device state. The core trusted the calendar clock.
- Impact: an attacker with the phone and the ability to change the system date (airplane mode plus manual date, or a compromised NTP source) could advance the clock to skip every retry delay and to decay accumulated failures, reducing the wipe-after-N and throttling guarantees to the cost of the KDF alone.
- Preconditions: physical possession, ability to change the device clock; no secret knowledge.
- Fix: required `HardwareOracle::clock_sample()` returning a 16-byte epoch and monotonic elapsed milliseconds; device state v4 stores the last applied sample, remaining retry debt and partial decay progress in the authenticated state; credit is granted only for non-regressing same-epoch intervals; epoch changes grant no credit and preserve debt; clock errors block attempts; states in the wall-clock format are rejected. Decoded states are range-checked.
- Tests: 15 deterministic tests in `device_clock_tests.rs`, including `file_timestamp_metadata_cannot_pay_retry_or_decay_debt`, `changed_epochs_with_larger_ticks_preserve_debt_and_cannot_replay_intervals`, `regression_retains_high_water_and_rebound_is_not_credited_twice`, `clock_errors_preserve_state_and_stop_queries_open_and_kdf`, `epoch_change_and_clock_errors_cannot_skip_the_wipe_policy`, `wall_clock_device_states_are_rejected`.
- Residual: trust in the platform clock callback and kernel; whole-container rollback (HW-C-13); waits lengthen across unverified epochs (HW-C-16).

#### HW-C-02 Re-unlocking a vault produced two live mutable snapshots

- Severity: Medium. Status: Fixed before release.
- Location: `vault.rs` (`VaultState::check_live`), `device.rs` (`Device::unlock`, `reset_pattern_with_phrase`), `Vault::open_managed_decoy`.
- Description: `check_live` only compared the duress/wipe epoch. Unlocking the same vault twice (or reopening a managed decoy) yielded two independent in-memory indexes over the same on-disk vault. Each could commit, and each tracked its own `pending_free`, so a stale handle or its unfinished `ItemWriter` could scrub blocks the current snapshot had since allocated.
- Impact: silent data corruption within a vault through ordinary app lifecycles (unlock, background, unlock again while a writer is still alive).
- Preconditions: none beyond normal use with overlapping handles.
- Fix: per-slot handle generations in `DeviceInner`; every open claims a new generation; `check_live` rejects older generations with `Locked`. Documented exclusive ownership of storage by one `Device`.
- Tests: `reopening_a_vault_invalidates_older_snapshots_and_writers`, `reopening_a_managed_decoy_invalidates_only_its_old_handle`, `phrase_pattern_reset_invalidates_existing_vault_handles`.

#### HW-C-03 Interrupted container growth made the container unopenable

- Severity: Medium. Status: Fixed before release.
- Location: `device.rs` (`Device::open`, `DeviceInner::grow`).
- Description: `grow()` appends random chunks before persisting the new `total_chunks`. `Device::open` required the file length to equal a bucket exactly, so a crash or disk-full error during the append left a file whose length matched no bucket and the container was rejected as `Corrupt` although every committed state was intact.
- Impact: denial of service / apparent data loss after an interrupted import near a bucket boundary.
- Preconditions: crash, kill or `ENOSPC` during growth.
- Fix: the authenticated `total_chunks` is authoritative; `open` accepts any length between the committed size and the next bucket; `grow()` rewrites the whole uncommitted tail before any of it can be allocated.
- Tests: `interrupted_growth_preserves_committed_vault_and_can_resume` (fails before any append, inside a chunk, after a complete chunk, one byte before the next bucket).

#### HW-C-04 Root `BlobRef` block count taken from the size estimate

- Severity: Medium. Status: Fixed before release.
- Location: `vault.rs` (`VaultState::commit`, root allocation loop).
- Description: the root blob was allocated from a size estimate; the committed `BlobRef` kept the estimate's `nblocks` while `len` was the real ciphertext length. `mark_loaded` (reopen and restore) requires `len > (nblocks - 1) * block_size`, so a root whose estimate crossed a block boundary that the real root did not cross was rejected.
- Impact: a vault became unopenable (`Corrupt`) after a commit whose root size fell in a specific window, for example after creating an album with a name of a particular length. Also wasted one block per such root.
- Preconditions: ordinary metadata growth; deterministic once the size is hit.
- Fix: `nblocks` recomputed from the ciphertext length, surplus blocks returned to the free mask.
- Tests: `roots_near_block_boundaries_reopen_and_restore`, `root_across_production_block_boundary_reopens` (production chunk/block sizes).

#### HW-C-05 Failed checkpoint write advanced to the other state copy

- Severity: Medium. Status: Fixed before release (`DeviceInner::persist_attempt_state`).
- Location: `device.rs`.
- Description: `persist()` increments the generation and therefore alternates the A/B copy. A timing checkpoint whose write or fsync failed left the generation advanced, so the retry targeted the other copy. A write that reported failure but partially reached disk, followed by a retry tearing the other copy, could destroy both copies.
- Impact: loss of the whole device state (container unopenable) after transient I/O errors during idle timing checkpoints.
- Preconditions: I/O error reporting failure for a write that was nevertheless partially durable; repeated polling.
- Fix: on failure the previous generation is restored so retries keep writing the same older copy; the last fsynced checkpoint is tracked separately.
- Tests: `failed_checkpoint_write_or_sync_never_loses_debt_or_runs_kdf`, `repeated_durable_torn_checkpoints_preserve_one_valid_state_copy`, `failed_epoch_checkpoint_is_retried_without_double_credit`.

#### HW-C-06 `ContainerConfig::validate()` divided before checking sizes

- Severity: Low. Status: Fixed before release.
- Location: `config.rs` (`validate`, `segment_plain_len`, `max_chunks`).
- Description: `blocks_per_chunk()` (`chunk_size / block_size`) ran before `block_size` was checked, so `block_size == 0` panicked; `chunk_size == 0` panicked in `max_chunks()`/`superblock_chunks()`; `segment_blocks * block_size` was a u32 multiplication; and `max_chunks()` truncates `bucket / chunk_size` to u32, so a bucket larger than 2^32 chunks passed the `<= 2^24` bound.
- Impact: process abort on a caller-supplied `Geometry` (reachable through `createDevice`/`Device.open` in the FFI); incorrect acceptance of absurd bucket sizes. Apps pass `productionGeometry()`, so no production exposure was identified.
- Fix: sizes validated first with early return; u64 arithmetic for the segment length and the bucket bound before any `max_chunks()` use.
- Test: `validate_rejects_degenerate_sizes_without_panicking` (15 degenerate configurations; confirmed to panic on the defective code).

#### HW-C-07 Correct pattern on an unloadable vault counted as a failed attempt

- Severity: Medium. Status: Fixed before release.
- Location: `device.rs` (`Device::unlock`).
- Description: the attempt increment was undone only after `VaultState::load` succeeded. If a vault's anchor or index was damaged, every unlock with its correct pattern (a slot match, not a guess) left `failed_attempts` incremented and persisted.
- Impact: escalating `RetryLater` for the correct pattern of a damaged vault and accumulation towards wipe-after-N, which would destroy the slots of the other, healthy vaults. No information leak (the `Corrupt` versus `WrongPattern` distinction already existed).
- Preconditions: storage damage to one vault's anchor/root/page blobs; repeated unlock by the owner.
- Fix: the increment is undone as soon as a slot opens; on load failure the undone state is persisted before the error is returned. Duress and success paths unchanged.
- Test: `matched_pattern_on_unloadable_vault_is_not_a_counted_attempt` (zeroed anchor chunk, three unlocks, count unchanged in memory and after reopen, sibling vault still opens; counter rose 1 to 4 on the defective code).

#### HW-C-08 Redundant zeroize loops in `VaultState::drop`

- Severity: Informational. Status: Fixed before release.
- `VaultState::drop` re-zeroized `root.albums`, `root.tags` and `root.decoys`, which `Root::drop` and the elements' `ZeroizeOnDrop` already cover. Reduced to zeroizing the items map (whose `Item` type is `Zeroize` but not `ZeroizeOnDrop`). No behavioural change.

#### HW-C-09 `ItemWriter` documented as sized-only

- Severity: Informational. Status: Fixed before release.
- The FFI doc comment described `ItemWriter` as "of known size" while it also backs `beginImportUnsized`. Doc comment only, in `hidewell-ffi/src/lib.rs` and the generated Kotlin and Swift sources.

#### HW-C-10 Unbounded item/album/tag names can poison a vault handle

- Severity: Low. Status: Fixed before release.
- Location: `vault.rs` (`commit`, `rename_item`, `create_album`, `rename_label`); FFI passed `String` unbounded.
- Description: a name or MIME type large enough that a page or the root cannot fit one chunk made `commit` return `NoSpace` after the in-memory state was mutated; `VaultShared::write` then poisoned the handle and the app had to re-unlock. `extra` was capped at 4096 bytes and thumbnails at 4 MiB, names were not.
- Fix: item, album and tag names are capped at 255 bytes (`MAX_NAME_LEN`, the common file-system `NAME_MAX`) and MIME types at 255 bytes (`MAX_MIME_LEN`; RFC 6838 allows 127 characters each for type and subtype), checked at the public API before any lock or state change, so an oversize value is a plain `InvalidArgument`. The FFI exposes all caps through `limits()`.
- Test: `name_limits_are_enforced_before_any_change` (values at the limit accepted on every path, one byte over and multi-byte overflows rejected, no id consumed, handle still usable, state unchanged after reopen); `root_across_production_block_boundary_reopens` also crosses the production block boundary with many capped names.

### 5.3 Accepted risks and open items

#### HW-C-11 Chunk allocations leak when restore or vault creation fails midway

- Severity: Low. Status: Accepted risk.
- `Device::restore_vault` and `create_vault` allocate chunks (`alloc_chunk`, which may call `grow()` and persist the bitmap) before their commit point. On failure the chunks stay marked in the bitmap. They hold random or vault ciphertext bytes and are indistinguishable from filler; only space is lost. A rollback mechanism was judged disproportionate.

#### HW-C-12 Crash between anchor switch and cleanup leaks chunks as filler

- Severity: Informational. Status: Accepted risk (documented in the `vault.rs` module header).
- A crash after the anchor switch but before step 4 of the commit skips scrubbing and chunk release; released chunks remain allocated and look like filler. Correctness is unaffected.

#### HW-C-13 Whole-container rollback restores older counters and timing

- Severity: Medium. Status: Accepted risk (documented in `SECURITY.md` and `THREAT_MODEL.md` item 8).
- An attacker who copies the entire container file and restores it later also restores older `failed_attempts`, retry debt and decay progress. The authenticated state has no external, rollback-resistant counter. Mitigation would need a hardware monotonic counter or a secure-element-held value, which neither platform exposes uniformly.

#### HW-C-14 Exclusive-ownership contract is not enforced by the core

- Severity: Low. Status: Accepted risk (documented on `Device::open` and `FileStorage::new`).
- Two independent `Device` instances over the same file (for example app and share extension without a lease) would hold divergent bitmaps and state generations. Platforms must enforce exclusive ownership (file locks or leases); the core cannot detect a violation.

#### HW-C-15 Failure decay permits about six wrong guesses per day indefinitely

- Severity: Low. Status: Accepted risk (documented in `SECURITY.md` and `THREAT_MODEL.md`).
- With one failure forgiven per 4 h, well-spaced guessing never reaches wipe-after-N. The retry delay and the KDF cost (about 0.75 s plus hardware chain latency per attempt, 16-slot trial) still bound the rate; the design is a rolling policy, not a lifetime budget.

#### HW-C-16 Unverified epochs extend waits after restarts

- Severity: Informational. Status: Accepted risk (documented).
- Time across an epoch change is not credited; a platform without a verified boot identity uses a random process epoch, so time while the process is absent earns nothing. Uncheckpointed progress (up to 30 s) is lost after a crash followed by a new epoch. This only lengthens waits; saved debt is never reduced.

#### HW-C-17 Transient secret copies at and beyond the FFI boundary

- Severity: Low. Status: Open.
- The core zeroizes `Secret<N>`, `SecretVec`, `Pattern`, `RecoveryPhrase`, index records and `ItemWriter` buffers, and `mlock`s key allocations best-effort. Values crossing UniFFI (phrase words as `Vec<String>`, pattern strokes, plaintext `Vec<u8>` returned by `read`/`thumbnail`, `ItemInfo` names) are plain allocations copied by the binding layer, and Swift/Kotlin strings cannot be reliably erased. The system must not be described as providing complete memory erasure.

## 6. Observations judged sound

The following were specifically checked and no defect was found. They are listed to record coverage, not as endorsements.

- AAD binding: anchors bind vault id and copy index; roots bind vault id and generation; pages bind vault id, `first_id` and generation; segments bind vault id, item id, kind, index, count and size (sentinels for unsized streams); slots bind their index; device-state copies bind their copy index; local and cloud manifest entries bind their index. Tests move blobs between positions and confirm rejection.
- Slot trial decryption examines all 16 slots without early exit; a double match is reported as `Corrupt`; slot payload structure (version, reserved zero bytes, flag mask) is validated.
- Constant-time comparisons via `subtle` for secrets (`Secret`, `SecretVec`), the entry HMAC tag and `verify_phrase`.
- Attempt counting is persisted and fsynced before the hardware chain runs; tests confirm no chain step executes when the write or fsync fails or when a retry delay is pending.
- A/B persistence for device state and anchors; the higher valid generation wins; parity between generation and copy index is checked.
- Write-new-then-switch commit order with fsync at each barrier; crash injection at every write of a commit and of a pattern change recovers to a consistent state (`crash_at_every_write_of_a_commit_is_recoverable`, `crash_during_pattern_change_leaves_exactly_one_pattern`).
- Bounds checks before allocation on restore: root pointer fields, logical chunk ids and chunk object lengths are validated against the geometry before any chunk is allocated; the restored index is fully loaded before the anchor is written.
- Load-time validation: anchor map entries must be allocated, in range and unique; page ids strictly increasing, within page bounds and below `next_item_id`; stream segment counts and lengths match the size; block runs must not overlap.
- Strict deserialisation (`postcard` with trailing-byte rejection; zero padding verified) and decoded device-state range checks.
- FFI boundary: epoch length (exactly 16 bytes), slot indices, KDF parameters and geometry validated in the core; patterns normalised identically at setup and unlock; errors flattened to data-free variants; `ItemWriter` consumed on `finish`.
- Error type carries no names, paths, sizes or counts (test enforces variant-name-only output); no logging in shipped code (`check-log-scrub.sh`); `Debug` is redacted on all secret-bearing types.
- The `mock-oracle` feature and the test KDF minimums cannot be compiled into a build without debug assertions (`compile_error!`; CI verifies the release build is refused).
- Lock ordering: vault state mutex, then device mutex; no path nests two vault state mutexes; mutex poisoning maps to `Locked` (fail closed).
- RFC and vendor test vectors: RFC 5869 (HKDF), RFC 9380 P-256 vectors, BIP39 official vectors; fixed chain/KDF vectors guard against unintended format changes.

## 7. Verification results

Recorded on the released code.

| Area | Result |
| --- | --- |
| Rust tests (`cargo test --workspace --locked`) | 66 core unit, 32 integration, 2 FFI passed; 1 benchmark ignored; 0 failures |
| Rust checks | `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets --locked --features mock-oracle -- -D warnings` clean (also without the feature, as in CI); `scripts/check-log-scrub.sh` OK |
| Platform integrations | The iOS and Android applications and their binding tests are run privately and are not covered by this report |

## 8. Recommendations

Prioritised; each is grounded in a finding or a stated scope gap.

1. Obtain a second review of the construction by a different reviewer. Its value is uncorrelated blind spots, not relative skill; this is standard practice for security-critical code whoever performed the first review.
2. Fuzz the untrusted-input decoders continuously: `Pattern::decode`, `index::from_padded`/`from_bytes` on `Root`, `AnchorRecord`, page item lists and `DeviceState` (`decode_state`), `backup::open_entry`, and `Device::open` over mutated container bytes. Property tests cover only the areas listed in section 2. The repository ships seven libFuzzer targets in `fuzz/`, run with `scripts/fuzz.sh` (not run by CI); the initial campaign, 60 s per target on one core (rustc nightly 1.101, cargo-fuzz 0.13.2), found no crashes or hangs: `anchor_decode` 3.04 M runs, `device_state_decode` 2.57 M, `page_decode` 1.74 M, `pattern_decode` 1.74 M, `root_decode` 1.51 M, `entry_open` 47.7 k, `device_open` 10.4 k (each run opens, unlocks and reads a container through the KDF). Longer and continuous runs are recommended.
3. Evaluate an external rollback-resistant attempt counter for HW-C-13 where the platform offers one (for example a Secure Enclave or StrongBox-held counter or key-rotation scheme), and record the decision in `THREAT_MODEL.md` item 8.
4. Consider a space-reclamation pass for HW-C-11/HW-C-12 only if container growth from leaked allocations is observed in practice; it is a capacity concern, not a security one.

## 9. Appendix

### 9.1 Files reviewed

`hidewell-core/src/`: `backup.rs`, `config.rs`, `crypto.rs`, `device.rs`, `device_clock_tests.rs`, `error.rs`, `index.rs`, `kdf.rs`, `lib.rs`, `mock.rs`, `oracle.rs`, `pattern.rs`, `phrase.rs`, `rng.rs`, `secret.rs`, `slots.rs`, `storage.rs`, `strength.rs`, `tests.rs`, `vault.rs`.
`hidewell-core/tests/`: `container.rs`, `bench_unlock.rs`.
`hidewell-ffi/src/lib.rs`; `uniffi-bindgen/src/main.rs`, `src/bin/uniffi-bindgen-swift.rs`.
`Cargo.toml`, `hidewell-core/Cargo.toml`, `hidewell-ffi/Cargo.toml`, `scripts/*.sh`, `.github/workflows/*.yml`, `docs/SECURITY.md`, `docs/THREAT_MODEL.md`.

Not reviewed (see section 2): `hidewell-core/src/fuzz_api.rs`, `fuzz/`, and the code for the features listed there as postdating the review.

### 9.2 Commands

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --features mock-oracle -- -D warnings
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
scripts/check-log-scrub.sh
scripts/fuzz.sh 60                      # nightly + cargo-fuzz; every libFuzzer target for 60 s
cargo build --locked -p hidewell-core --release --features mock-oracle   # must fail (CI check)
cargo test -p hidewell-core --profile perf --test bench_unlock -- --ignored --nocapture   # optional benchmark
```

### 9.3 Related documents

- `docs/SECURITY.md`, `docs/THREAT_MODEL.md`.

### 9.4 Revision history

- 1.0 (2026-10-20): initial report.
- 1.1 (2026-10-21): fact-check against the released code; source size, property-test list, crate table (`rand_core`, `serde` patch version, FFI manifest) and the note that fuzzing is not run by CI corrected. Finding statuses, counts and verification results re-run and unchanged; HW-C-17 remains open.
