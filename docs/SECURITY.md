# hidewell-core — security design

Scope: this repository (`hidewell-core`, `hidewell-ffi`; Rust, MIT OR Apache-2.0). Threats and residual leakage: [`THREAT_MODEL.md`](THREAT_MODEL.md).

Reporting a vulnerability: email contact@hidewell.app privately; do not open a public issue.

Audit status: independent security review by Claude Fable 5.1 (Anthropic), October 2026; see [`CORE_SECURITY_AUDIT_2026-10.md`](CORE_SECURITY_AUDIT_2026-10.md).

Primitives (RustCrypto + `hpke`, nothing home-rolled): AES-256-GCM (`aes-gcm`), HKDF-SHA256 (`hkdf`), SHA-256 (`sha2`), HMAC-SHA256 (`hmac`; manifest entry authentication and the test mock), Argon2id v1.3 (`argon2`), HPKE RFC 9180 DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/AES-256-GCM (`hpke`), RFC 9380 P-256 hash-to-curve (`p256`), BIP39 (`bip39`), ChaCha20 RNG seeded from `getrandom`. `#![forbid(unsafe_code)]` in `hidewell-core`. All domain-separation labels are `hidewell/...`.

## 1. Key hierarchy

```
pattern ──canonical encoding──► chain: k × oracle.chain_step  (platform hardware: e.g. SE ECDH on a hash-to-curve point / StrongBox HMAC)
                              │
                              ▼
                 Argon2id(chain_out, device salt, m ≥ 64 MiB, t, p)        once per attempt
                              │ unlock_key
              ┌───────────────┴───────────────┐
              ▼                               ▼
  KEK_i = HKDF(unlock, "hidewell/kek/v1"||i)  (i = 0..15, cheap)
              │ AES-GCM, aad "hidewell/slot/v1"||i
              ▼
  slot i payload: {flags(duress), anchor chunk, MASTER KEY}             (random master key per vault)
              │ HKDF(master, …)
     ┌────────┼──────────────┬───────────────┬──────────────┐
  vault_id  anchor key     index key      content key    object-name key
            (A/B records)  (root, pages)  (segments,     (cloud object
                                           thumbnails)    names)

recovery phrase (12 words, 128 bit) ─► recovery_key = HKDF(entropy, "hidewell/recovery/v1")
   ─► backup_sk = HKDF(recovery_key, "hidewell/backup-x25519/v1") ─► backup_pk (stored on device)
   manifest entry i = HPKE-Seal(backup_pk, {master key, root pointer, flags, HMAC tag})

hardware non-pattern key ─seal/open─► device_secret ─► device_key = HKDF(…, "hidewell/device-state/v1")
   device_key ─► device state {salt, KDF params, allocation bitmap, reserved slots,
                               backup_pk, failure counter, settings}
```

Two independent roots unlock the same master key: the pattern (device-bound: hardware chain + Argon2id + slot) and the phrase (restore/recovery: HPKE entry). Neither is stored. The master key never depends on the KEK, so restore re-wraps it under a new pattern.

## 2. Device-wide salt, fixed slot table, global bitmap

- **One device-wide Argon2 salt**, per-slot KEKs by HKDF. The vault is unknown at unlock, so a per-vault salt would need one Argon2 run per vault, break the time budget and leak the vault count through timing. Chain + Argon2id run exactly once per attempt regardless of the number of vaults (asserted with the mock oracle's step counter).
- **Fixed key-slot table**: 16 slots × 76 bytes, always full (unused = random). Unlock trial-decrypts all 16, no early exit. The slot count is constant and reveals nothing.
- **Global allocation bitmap**: allocation, cover traffic and the duress wipe need a global view of used chunks, so the bitmap lives in the device state under a hardware-wrapped device key that is not pattern-gated. Its leakage is mitigated by filler chunks (§4) and documented in THREAT_MODEL.md.

## 3. Unlock, slots and vault creation

- Patterns: 5 × 5 grid, 1 or 2 strokes, no node repeated within a stroke, skipped nodes inserted (the same normalisation at setup and unlock). Encoding is length-prefixed, injective and strictly decoded (property-tested). Setup rejects < 6 distinct nodes, < 2 direction changes, and blocklisted shapes (generated: lines, L, U/C, borders, Z/N, letters, spirals, snakes, X/+/T/=/||, all symmetries/reversals). Strength meter: documented guess-rank model in `strength.rs`.
- KDF: `s_0 = SHA-256("hidewell/chain/init/v1" ‖ encoding)`, `k` hardware chain steps with per-step SHA-256 domain separation, then Argon2id over the device salt. Minimums (m ≥ 64 MiB, 4 ≤ k ≤ 2048, t ≤ 64, p ≤ 16, m ≤ 1 GiB) are enforced on every use, including parameters read from storage, and relaxed only in test builds. Calibration targets 250 ms chain / 500 ms Argon2id.
- Hardware oracle trait (byte vectors in and out; `p256_hash_to_curve` exported for a Secure Enclave ECDH step). The software `MockOracle` compiles only under `cfg(test)` or the `mock-oracle` feature, and that feature is a `compile_error!` without `debug_assertions`. There is no unlock path other than the pattern: a biometric path would need a non-pattern-gated flag to disable it while a duress pattern exists, which would reveal the duress vault.
- Slot reservation: the device state holds a reserved-slot set = real vaults ∪ 1–8 filler reservations (drawn at setup, never recorded as filler). New vaults take a random unreserved slot. Reservations survive duress so hidden vaults' manifest entries are never overwritten by later vaults. A new pattern that already opens a slot is rejected (`PatternInUse`).
- Attempts: every pattern-gated trial (unlock, and the `PatternInUse` check in vault creation and pattern change) is counted in the device state and fsynced before the KDF runs; otherwise vault creation and pattern change would be an uncounted oracle for probing hidden vaults' patterns from inside an open vault. The core enforces the escalating delay (none < 5, then 30 s doubling, cap 1 h; `RetryLater`) and the optional wipe after N (overwrites all slots; data stays as random-looking ciphertext; the triggering attempt returns `Wiped`). A successful unlock undoes only its own increment, so interleaving guesses with a known pattern does not clear earlier failures; a matched pattern whose vault then fails to load is undone the same way (not a guess). Failures decay by one per 4 h of trusted continuous monotonic time. The authenticated state includes the epoch/tick checkpoint, remaining retry delay and partial decay progress; clock errors block pattern attempts, and a changed clock epoch grants no elapsed credit. Setup, successful phrase-authorised restore/pattern reset, and the wipe clear the counter. Phrase-authorised restore and pattern reset validate the new pattern without counting an attempt. A pattern that fails the structural setup policy (too few nodes or direction changes; not the blocklist) is rejected at unlock before the gate, uncounted: the rule is public, depends only on the input, and no sealed slot can match such a pattern.

## 4. Container

- One file, sizes 1/4/16/64 GiB, 4 MiB chunks, no header or magic; all bytes uniformly random or ciphertext (tested: no plaintext markers, byte histogram within 6σ, no 16-byte runs, in the container and in cloud objects). Free space is ChaCha20 output; new chunks are chosen uniformly at random among free chunks. At setup and on growth, a random 5–15 % of chunks are marked allocated and filled with random bytes ("filler"), so excess allocation is normal and non-evidentiary.
- Per-vault anchor (A/B records in a chunk named by the slot payload) → root → pages → item streams. Logical chunk ids keep the index position-independent; the logical→physical map lives only in the device-local anchor, so restore writes a fresh anchor and slot while everything else is addressed by logical ids and keyed from the master key.
- Files and thumbnails: segments of 1 MiB − 28 B plaintext, AES-256-GCM with a fresh random 96-bit nonce each, AAD = vault_id ‖ item id ‖ kind ‖ segment index ‖ segment count ‖ total size — reordering, cross-item substitution, truncation and extension fail authentication. Unsized streaming imports carry sentinel count/size in the AAD; their truncation/extension protection comes from the authenticated index (segment list, size and per-segment lengths checked on load and read). `read(item, offset, len)` decrypts only covering segments (streaming).
- Commit protocol: write-new-then-switch. New blobs go to blocks free in both old and new state; the bitmap is persisted and fsynced; the anchor record is written to the older A/B copy with generation + 1 and fsynced (the commit point); then superseded blocks are scrubbed, emptied chunks released and randomised, cover traffic written and the state persisted again. Fault injection tears every single write of a commit and of a pattern change in tests.
- Interrupted growth is recoverable: the authenticated committed size remains authoritative while an uncommitted tail up to the next bucket is overwritten on resumed growth. Root block counts reflect actual ciphertext length, including at allocation-estimate boundaries.
- Every commit scrubs superseded blocks, randomises released chunks and rewrites 2 random free chunks (cover traffic).
- Platforms exclusively own the container for the lifetime of a `Device` and its handles. Within that device, reopening a vault or resetting its pattern with the phrase invalidates its older handles and writers, preventing conflicting mutable snapshots.

## 5. Duress

Duress unlock opens the decoy normally, destroys the other 15 slots, rebuilds the bitmap as decoy chunks ∪ fresh filler and invalidates other open handles. Other vaults' data stays as undecryptable ciphertext until overwritten lazily. The decoy never deletes or overwrites other vaults' cloud entries or objects, so every vault remains restorable from the phrase (integration-tested). The decoy keeps its role (the flag also travels in its manifest entry), so every unlock of the decoy by its pattern re-runs the wipe. The real vault that created it can open it without the wipe through a link (slot, anchor, decoy master key) stored only in its own encrypted index; nothing outside the owner's index reveals the link and the decoy does not know its owner.

Pattern change is atomic via A/B slot tables: the new table is written to the inactive copy and fsynced, the active bit flips in the device state, then the old table is overwritten with random bytes (tested with a torn write at every write: exactly one of old/new pattern opens). Deletion computes the cloud cleanup plan first, then destroys the slot and randomises the anchor chunk; the slot reservation is released only once the platform confirms the plan ran (`confirm_vault_deleted`), so a real cloud entry with no live vault always means the slot is safe to restore into. Restore refuses to overwrite a vault that is live on the device (`VaultAlreadyPresent`, found by trial-decrypting anchor records with the entry's anchor key) and otherwise works in fresh and existing containers, including after duress.

## 6. Backup

The device holds no symmetric backup key: device-key-only storage would let a forensic examiner decrypt every master key, and storage inside vaults would hand the manifest to the duress vault. Instead the device stores only the phrase-derived backup public key and each vault seals its own manifest entry to it with HPKE. Platform-neutral: the core emits a sync plan (put object / put entry / delete own object); platforms only move bytes. Objects are immutable raw chunks with names only the owning vault can decrypt. Entries are authenticated with phrase-derived per-index keys, so the public key plus cloud write access cannot plant a vault or a duress flag. Restore needs only the phrase and the cloud folder: scan → create fresh container → restore each vault with a new pattern. The superblock also keeps device-key-wrapped local copies of all 16 entries, so a forgotten pattern can be reset with the phrase alone without the cloud.

## 7. Memory and logging

Keys in boxed `Secret<N>` (zeroize on drop, redacted `Debug`, constant-time `Eq`, best-effort `mlock`, never unlocked because `munlock` is not reference-counted); decrypted buffers in `SecretVec`; item/album/tag names, decoy links and entry keys zeroized when a vault handle drops; `ItemWriter` uses one fixed-capacity segment buffer so no stale plaintext is left in freed heap memory. Plaintext returned to the caller (`read`, `list_items`) is the caller's responsibility. No logging in the core (enforced by `scripts/check-log-scrub.sh`); `Error` variants carry no names, paths, sizes or counts (tested); `Debug` of metadata types prints ids only. `Device::erase` randomises the superblock (both slot tables, both state copies, all local entries). Argon2 memory is capped at 1 GiB.

## 8. Platform responsibilities

The core's guarantees hold only if the integrating application:

- implements `HardwareOracle` with a non-exportable, this-device-only hardware key (Secure Enclave, StrongBox or TEE), never silently recreates missing keys, reports `SoftwareMock` honestly, and never ships a software oracle in release builds;
- implements `clock_sample` with continuous monotonic time including sleep (never calendar time) and a 16-byte epoch that identifies a verified boot where available, or else a random process-wide value shared by all oracle instances and device reopens; queries `failed_attempts`/`retry_after_seconds` periodically during a wait and at lifecycle boundaries (that is when timing progress is checkpointed), and never treats a clock error as an expired delay;
- stores the sealed device secret outside the container in this-device-only storage and excludes the container from OS/cloud device backups;
- never writes plaintext (imports, thumbnails, previews, caches) outside the container, and never logs names, paths, sizes, counts or secrets;
- locks vault handles (`Vault.lock()`) and drops the `Device` when the app backgrounds; hides content from app-switcher snapshots and screen capture;
- runs sync plans as specified (ops in order, stop at the first failure; delete plans confirmed via `confirm_vault_deleted`), uploads setup filler entries only if absent;
- on `Wiped` or an erase request: `erase()`, then delete the container file, the sealed device secret and the hardware keys;
- treats secrets crossing the FFI as below.

**Secrets crossing the FFI** are plain platform objects that the core cannot zeroize: phrase words (`[String]` / `List<String>`), pattern strokes, the device secret (oracle `seal`/`open` arguments and results), chain-step inputs/outputs, and decrypted file/thumbnail bytes (`Data` / `ByteArray`). Keep them in local scope only; never log, persist or put them in UI state that outlives the screen; overwrite `ByteArray`s with zeros after use (Kotlin `fill(0)`); on iOS prefer `withUnsafeMutableBytes` to zero `Data` you own (Swift `String`s cannot be reliably zeroed — keep phrase words in a single short-lived array).

## 9. Known limits

- Whole-container rollback is undetectable (no hardware monotonic counter); it also resets the failure counter.
- Retry delay and decay depend on the platform's continuous monotonic clock and epoch contract. Calendar changes give no credit. Without a verified boot identity, a random process-wide epoch means time outside that process is not credited. Timing queries checkpoint progress at 30 s intervals while polled, and immediately on debt-bearing epoch/policy transitions; uncheckpointed credit can be lost on a crash followed by a new epoch. A compromised clock callback/kernel is outside this guarantee. Decay still permits roughly six well-spaced failures/day indefinitely; wipe-after-N is not a lifetime guess budget.
- Freed-chunk overwrite after duress is lazy.
- A coercer who gets the real vault opened learns its decoy links (by design: the real vault is then exposed anyway) and can forge manifest entries for other indices.

Formats: device state v4 (requires the monotonic clock callback) and vault index v4; earlier formats are rejected as `Corrupt`, whether read from the container or restored from a backup.
