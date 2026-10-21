//! # hidewell-core
//!
//! Cryptographic core of the Hidewell encrypted vault: pattern-based unlock with a
//! hardware-bound KDF chain, hidden fixed-size key slots, a padded uniform-looking
//! container, and phrase-keyed backup.
//!
//! This crate performs no logging and its errors carry no file names, paths or counts.
//! See `docs/SECURITY.md` and `docs/THREAT_MODEL.md` in the repository.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// The deterministic software oracle must never ship: refuse to build it without
// debug assertions (i.e. in a release profile).
#[cfg(all(feature = "mock-oracle", not(debug_assertions), not(test)))]
compile_error!("feature `mock-oracle` is for tests only and cannot be used in release builds");

pub mod backup;
pub mod config;
pub mod crypto;
pub mod device;
pub mod error;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_api;
pub(crate) mod index;
pub mod kdf;
#[cfg(any(test, feature = "mock-oracle"))]
pub mod mock;
pub mod oracle;
pub mod pattern;
pub mod phrase;
pub mod rng;
pub mod secret;
pub mod slots;
pub mod storage;
pub mod strength;
#[cfg(test)]
mod tests;
pub mod vault;

pub use backup::{ObjectSource, SyncOp, SyncPlan};
pub use config::ContainerConfig;
pub use device::{Created, Device, ProtectionInfo, RecoverableVault};
pub use error::{Error, Result};
pub use index::{
    MAX_EXTRA, MAX_MIME_LEN, MAX_NAME_LEN, MAX_REPLACE_LEN, MAX_THUMBNAIL_LEN, MAX_VAULT_NAME_CHARS,
};
pub use kdf::{CalibrationTargets, KdfParams, calibrate, retry_delay};
pub use oracle::{ClockSample, HardwareOracle, OracleError, SecurityLevel, p256_hash_to_curve};
pub use pattern::{Pattern, PatternError};
pub use phrase::RecoveryPhrase;
#[cfg(unix)]
pub use storage::FileStorage;
pub use storage::{MemStorage, Storage};
pub use strength::{BlockedShape, Strength, StrengthReport};
pub use vault::{DecoyInfo, ItemInfo, ItemWriter, Label, NewItem, Vault};
