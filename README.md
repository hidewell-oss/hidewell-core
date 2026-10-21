# hidewell-core

Cryptographic core of the Hidewell encrypted photo/file vault for iOS and Android, written in Rust and exposed to Swift and Kotlin through [UniFFI](https://github.com/mozilla/uniffi-rs).

- **Pattern unlock bound to device hardware**: every attempt runs a non-parallelisable chain of hardware operations (Secure Enclave / StrongBox / TEE, provided by the platform through the `HardwareOracle` trait) followed by Argon2id, so guessing is only possible on the device, at chip speed.
- **Hidden vaults**: a fixed 16-slot key table and one padded, uniformly random-looking container file; the number of vaults is not stored anywhere.
- **Duress pattern**: opens a real decoy vault and destroys the keys of all other vaults on the device.
- **Phrase-keyed backup**: platform-neutral, end-to-end encrypted backup to any object store; restore with a 12-word BIP39 phrase only.
- `#![forbid(unsafe_code)]`, no logging, RustCrypto primitives only (nothing home-rolled).

Audit status: independent security review by Claude Fable 5.1 (Anthropic), October 2026 (17 findings, 10 fixed, 6 accepted, 1 open; see [`docs/CORE_SECURITY_AUDIT_2026-10.md`](docs/CORE_SECURITY_AUDIT_2026-10.md)).

## Documentation

- [`docs/SECURITY.md`](docs/SECURITY.md) — key hierarchy, container, duress, backup, platform responsibilities.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversaries and accepted residual leakage.
- [`docs/CORE_SECURITY_AUDIT_2026-10.md`](docs/CORE_SECURITY_AUDIT_2026-10.md) — October 2026 security review: scope, method, findings, accepted risks, recommendations.

## Layout

| Path | Contents |
|---|---|
| `hidewell-core/` | The core library (no FFI dependencies) |
| `hidewell-ffi/` | UniFFI bindings crate (`staticlib` / `cdylib`) |
| `uniffi-bindgen/` | Pinned local `uniffi-bindgen` CLI |
| `bindings/swift/HidewellCore/` | Swift package (generated Swift sources + XCFramework built locally) |
| `bindings/kotlin/hidewell-core/` | Android library (generated Kotlin sources + jniLibs built locally) |
| `scripts/` | Build and check scripts |

## Build and test

Requires Rust stable (edition 2024; `hidewell-ffi` needs ≥ 1.88).

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

### Fuzzing

`fuzz/` holds libFuzzer targets (a separate workspace; nightly only) for every decoder that
consumes untrusted bytes: `pattern_decode`, `root_decode`, `page_decode`, `anchor_decode`,
`device_state_decode`, `entry_open`, and `device_open` (mutations of a small valid container
through `Device::open`, unlock and reads). They assert only "no panic", plus re-encoding
round trips and that a forged manifest entry never authenticates.

```sh
rustup toolchain install nightly && cargo install cargo-fuzz
scripts/fuzz.sh 60                 # every target for 60 s; scripts/fuzz.sh 300 device_open for one
```

Seeds live in `fuzz/seeds/<target>/` (regenerate after a format change with
`cargo test -p hidewell-core --features fuzzing -- --ignored write_fuzz_seeds`); the growing
corpus and crash artifacts are git-ignored. The `fuzz` workflow runs every target nightly for
600 s (`workflow_dispatch` takes a duration), caching the corpus between runs and uploading
crash artifacts on failure. The targets reach crate-private decoders through
`hidewell_core::fuzz_api`, compiled only with the `fuzzing` feature (which implies
`mock-oracle`, so it cannot be built into a release).

Building with the test-only feature `mock-oracle` in a release profile fails at compile time by design.

Unlock benchmark (simulated hardware latency): `cargo test -p hidewell-core --profile perf --test bench_unlock -- --ignored --nocapture` (set `HIDEWELL_BENCH_STEP_MS`).

## Scripts

| Script | What it does | Requires |
|---|---|---|
| `scripts/build-ios.sh` | Builds `HidewellCoreFFI.xcframework` (device arm64, simulator arm64 + x86_64) and regenerates the Swift bindings in `bindings/swift/HidewellCore` | macOS, Xcode, rustup targets `aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios` |
| `scripts/test-ios.sh ["<simulator name>"]` | Runs the Swift package tests on an iOS simulator (after `build-ios.sh`) | macOS, Xcode |
| `scripts/build-android.sh` | Builds jniLibs (arm64-v8a, armeabi-v7a, x86_64; minSdk 28) with cargo-ndk, regenerates the Kotlin bindings, assembles the AAR and runs the host JVM binding test | cargo-ndk, rustup Android targets, Android NDK, JDK 21 (`ANDROID_HOME`, `ANDROID_NDK_HOME`, `JAVA_HOME`) |
| `scripts/check-log-scrub.sh` | Fails if shipped Rust sources contain any logging call | bash, grep |

Built binaries (XCFramework, jniLibs, AAR) are not committed.

Consuming the bindings: add `bindings/swift/HidewellCore` as a local Swift package; on Android use `includeBuild("<path>/bindings/kotlin/hidewell-core")` and `implementation("com.sentrybrain.hidewell:hidewell-core")`. The interface is documented in `hidewell-ffi/src/lib.rs` and in the generated sources.

## Security contact

Please report vulnerabilities privately to: contact@hidewell.app. Do not open public issues for security reports.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
