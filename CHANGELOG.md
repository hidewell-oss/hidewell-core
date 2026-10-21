# Changelog

## 1.0.0 (2026-10-21)

First public release.

- Container format with A/B anchors and device state, index v4, device state v4.
- Pattern unlock with hardware-bound KDF chain and 16 uniform key slots; duress and managed decoys.
- Attempt enforcement on authenticated monotonic time with retry delay, decay and wipe-after-N.
- Phrase-keyed HPKE backup manifest and sync plans; local and cloud restore.
- UniFFI bindings for Swift and Kotlin.
- Security review: `docs/CORE_SECURITY_AUDIT_2026-10.md` (report 1.2), 17 findings, 10 fixed, 6 accepted, 1 open.
- libFuzzer targets for every untrusted-input decoder, run nightly by the `fuzz` workflow.
