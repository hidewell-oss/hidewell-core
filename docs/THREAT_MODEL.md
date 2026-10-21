# hidewell-core — threat model

Design: [`SECURITY.md`](SECURITY.md).

## Goal

Defend vault contents against anyone holding the device or a cloud copy without the pattern or the recovery phrase. Do not defend an unlocked device, malware, or a vault in use.

Assets: contents (files, thumbnails, metadata, file names, EXIF); existence and number of vaults; keys (master, vault, backup); usage metadata.

| Adversary | Has | Outcome | Mechanism |
|---|---|---|---|
| Casual snooper | Unlocked phone, minutes | No access | Pattern gate, no vault list; platform: auto-lock on background |
| Thief | Locked phone | No access | OS data protection + core encryption |
| Forensic examiner | Full FS extraction, code exec | Only on-device guessing at chip speed | Hardware secret in every key (chain), Argon2id per guess |
| Coercer | Phone + pressure | Sees only the vault opened | Duress pattern, hidden vault count |
| Cloud provider / account thief | Backup ciphertext | No access | Backup keyed from a 128-bit phrase, never the pattern |
| Software publisher | Whatever an operator could run | No access | No key escrow, no server copy; the core performs no network I/O |

Out of scope: malware, attacker-controlled jailbreak/root, shoulder-surfing, OS screenshots (a platform responsibility), a coercer who knows a duress vault exists, hardware/chip flaws.

Residual risks accepted: weak patterns on seized phones; losing the pattern AND the phrase loses data; the binary is a trust anchor; one phrase recovers all vaults (including after duress), so a coercer demanding the phrase gets everything.

The platform responsibilities the core relies on are listed in SECURITY.md §8.

## Residual leakage on the device

The device key is hardware-wrapped but not pattern-gated, so a forensic examiner with code execution can read the device state. What it reveals:

1. **Allocation bitmap.** The bitmap is global (allocation, cover traffic and the duress wipe need it) and lives under the device key rather than behind any pattern. Allocated chunks = Σ vault chunks (data + one anchor each) + filler + chunks leaked by crashed commits. Filler is 5–15 % of the container, drawn at setup, on growth and at duress, never recorded. Someone who has opened one vault (coerced) and can run code can compute the excess: if it exceeds what 15 % filler (plus rare crash leaks) explains, other data provably exists. Below that it is deniable. Total allocation also bounds total stored data.
2. **Reserved slot set.** The device state records which of the 16 slots are reserved (so a new vault never overwrites a hidden one) but not which reservations are filler. r = number of vaults + F, F uniform in 1..=8 drawn at setup and never re-drawn. With one vault opened, other vaults are deniable only while r − 1 ≤ 8. The distribution of r shifts with the vault count (Bayesian evidence, not proof, in the deniable range). Reservations survive duress (needed so later vaults never overwrite a hidden vault's cloud entry), so after duress r still reflects the pre-duress count: the post-duress state is as deniable as the pre-duress state, not "fresh".
3. **Container size bucket** (1/4/16/64 GiB) reveals coarse total volume.
4. **Settings**: failed-attempt counter and wipe-after setting (not vault-identifying).
5. **Filler mitigation residuals**: filler is uniform over chunk positions, while real vault chunks are written, scrubbed and partially rewritten over time. A single image cannot tell them apart (all bytes uniform). Several images over time can: chunks that change are live, and filler never changes except through cover traffic (which only targets free chunks). Cover traffic (2 random free chunks per commit) hides which free regions are written but not which allocated chunks change.
6. **Multi-snapshot attacker**: sees which chunks and which anchor halves change per commit, slot-table writes at vault creation and duress (15 slots rewritten at once), and device-state rewrites at every attempt.
7. **Duress** takes longer than a normal unlock (15 slot writes, bitmap rebuild) and changes the slot table. Only matters against a coercer who suspects duress (out of scope).
8. **Rollback**: restoring an older container image is undetectable and resets the failure counter / wipe-after progress.
9. **Managed decoy links** live only inside the creating vault's encrypted index; they reveal the decoy only to someone who has already opened that real vault.
10. **Deletion** keeps the slot reserved until the cloud cleanup is confirmed, then lowers the reserved-slot count by one; chunks are freed lazily. Multi-snapshot observers see both steps. If the cloud cleanup plan is not executed, the deleted vault remains restorable from the phrase.
11. **Restore liveness check**: `VaultAlreadyPresent` tells the caller that the entry's vault is live on this device. Only a phrase holder can ask, and the phrase already grants everything, so this adds no leakage beyond the reserved-slot set (item 2). The check scans anchor records of allocated chunks; its duration depends on container size only.

Not leaked on the device: file names, item counts, sizes or types (all inside AES-GCM under master-key-derived keys); which slot belongs to which vault; whether a vault is the decoy; vault creation order.

## Residual leakage in the cloud

The provider sees the backup folder (one per phrase, name = hash of the backup public key), 16 entry objects and immutable 4 MiB chunk objects with opaque 80-character names.

1. **Entry rewrite timing.** Entry i is rewritten only by the vault in slot i, so the provider learns how many entries are ever rewritten (lower bound on vault count, inherent to one fixed entry per slot) and per-vault activity times. Filler entries are never rewritten after setup.
2. **Upload volume per sync.** Chunk objects uploaded just before an entry rewrite are attributable to that entry: per-vault data volume and change rate (chunk granularity). Deletions after the rewrite reveal superseded volume.
3. **Totals**: object count ≈ total backed-up data / 4 MiB across all vaults.
4. **Linkability**: all vaults of one phrase live in one folder.
5. **Device + cloud together**: cloud objects are byte-identical to device chunks at upload time, so an adversary with both can map device chunks to vaults' upload sessions and refine points 1–2 of the device list.
6. **Duress and cloud**: the decoy never touches other entries or objects, so hidden vaults remain in the cloud and restorable with the phrase; this is also why the phrase is a total compromise if coerced (accepted).

Not leaked in the cloud: contents, names, item counts, which entries are filler (until rewritten), the pattern (never used for backup keys).

## Pattern guessing

A seized phone allows only on-device guessing: every guess needs k hardware chain steps on that chip plus Argon2id (≈ 0.75 s calibrated). Off-device guessing is impossible without extracting the hardware key (chip flaws are out of scope). Strength depends on the pattern: the blocklist and meter (guess-rank model, `strength.rs`) steer users away from the first few thousand guesses; at ~0.75 s/guess, 2^20 guesses ≈ 9 days, 2^24 ≈ 5 months. The optional wipe-after-N-failures limits accumulated failures after decay; it is not a lifetime guess budget and is defeated by container rollback (item 8).

Every pattern-gated trial costs the same: unlocking, and the `PatternInUse` check when creating a vault or changing a pattern. Each is counted durably before the KDF runs and is subject to the core-enforced escalating delay (`RetryLater`) and to wipe-after-N. A successful unlock undoes only its own increment, as does a matched pattern whose vault then fails to load (not a guess); failures decay by one per 4 h, so interleaving guesses with a known pattern does not clear earlier failures. Roughly 6 wrong guesses per day can be offset by decay; faster sustained guessing accumulates failures toward the optional wipe threshold. Phrase-authorised restore and pattern reset are not counted attempts and clear the counter on success, because the phrase already grants full authority. Residual: someone inside an open vault can probe for other vaults' patterns at exactly the unlock screen's rate. Both retry delay and decay use continuous monotonic time supplied by the platform, with an authenticated epoch/tick checkpoint, remaining retry debt, and partial decay progress. Calendar changes do not grant credit. Changed or unknown epochs grant no elapsed credit; regressing ticks keep their high-water mark. If a verified boot identity is unavailable, a random process epoch conservatively excludes time outside that process; unsaved waiting progress can also be lost after a crash/new epoch. Clock failures block pattern attempts. This depends on an honest platform clock callback/kernel; container rollback still restores older counter and timing state (item 8).

## Backup entries, local entries and erase

- Manifest entries are authenticated with phrase-derived per-index keys, so knowing the backup public key (readable via the device key) plus cloud write access does not allow planting vaults or duress flags. Residual: anyone who has opened a real (non-duress) vault holds all 16 entry keys and can forge entries for other indices. With cloud access they could already destroy those entries; forging lets them also plant false ones.
- A missing entry stops a restore (`BackupIncomplete`) instead of being treated as unused.
- Local entries: the container always holds 16 device-key-wrapped HPKE entries, which a forensic examiner can see but cannot open without the phrase; they reveal nothing about vault count. A phrase holder can use them to reset any locally present vault's pattern (by design: the phrase is full authority). After duress the wiped vaults' local entries remain, but their data is not present, so the device alone still yields nothing.
- `Device::erase` randomises every key-bearing byte of the container; a forensic copy taken afterwards opens nothing, even with the device secret.
- `Wiped` is reported once to whoever triggered it; the container keeps no record of a wipe.
