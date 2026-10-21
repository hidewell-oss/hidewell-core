//! UniFFI bindings for `hidewell-core` (Swift and Kotlin). This module and the
//! generated sources under `bindings/` are the interface contract.
//!
//! All calls are blocking and thread-safe: call them from a background thread/queue
//! (KDF + hardware chain take ~0.75 s; imports and sync do I/O). Patterns cross as
//! strokes of node ids (`Vec<Vec<u8>>`, node = row * 5 + column) and are normalised with
//! `Pattern::from_drawn` (skipped-over nodes inserted), identically at setup and unlock.

use std::fmt;
use std::fs::OpenOptions;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hidewell_core as hc;

uniffi::setup_scaffolding!("hidewell_core");

// ============================================================================ errors

/// Flat error. Carries no data (never names, paths or counts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Error)]
pub enum HidewellError {
    /// Pattern structurally invalid or below the setup policy.
    InvalidPattern,
    /// Pattern is a blocklisted common shape.
    PatternBlocklisted,
    /// Pattern already opens a vault.
    PatternInUse,
    /// No vault opens with this pattern.
    WrongPattern,
    /// Oracle: hardware key missing or invalidated.
    OracleKeyUnavailable,
    /// Oracle: device locked / authentication required.
    OracleDeviceLocked,
    /// Oracle: unexpected output.
    OracleBadOutput,
    /// Oracle: sealed device secret invalid (other device, tampered).
    OracleSealedBlobInvalid,
    /// Oracle: other failure.
    OracleFailed,
    /// Recovery phrase invalid.
    InvalidPhrase,
    /// KDF parameters invalid or below the minimum.
    InvalidParams,
    /// Authentication failed / corrupt data.
    Corrupt,
    /// Storage I/O error.
    Io,
    /// All key slots reserved.
    NoFreeSlot,
    /// Container full at the largest bucket.
    NoSpace,
    /// Not found (item, album, tag, decoy, backup object).
    NotFound,
    /// Handle locked or invalidated.
    Locked,
    /// Argument out of range.
    InvalidArgument,
    /// A foreign callback failed unexpectedly.
    CallbackFailed,
    /// Too many recent pattern attempts; wait `Device.retryAfterSeconds()`.
    RetryLater,
    /// Restore refused: that vault is already live on this device.
    VaultAlreadyPresent,
    /// A backup manifest entry is missing; refuse to restore from it.
    BackupIncomplete,
    /// This attempt hit the wipe-after-N limit; every key slot was destroyed. Returned
    /// once: call `Device.erase()` and route to setup/restore.
    Wiped,
}

impl fmt::Display for HidewellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for HidewellError {}

impl From<uniffi::UnexpectedUniFFICallbackError> for HidewellError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        HidewellError::CallbackFailed
    }
}

impl From<hc::OracleError> for HidewellError {
    fn from(e: hc::OracleError) -> Self {
        match e {
            hc::OracleError::KeyUnavailable => Self::OracleKeyUnavailable,
            hc::OracleError::DeviceLocked => Self::OracleDeviceLocked,
            hc::OracleError::BadOutput => Self::OracleBadOutput,
            hc::OracleError::SealedBlobInvalid => Self::OracleSealedBlobInvalid,
            hc::OracleError::Failed => Self::OracleFailed,
        }
    }
}

impl From<hc::Error> for HidewellError {
    fn from(e: hc::Error) -> Self {
        use hc::Error as E;
        match e {
            E::Pattern(_) => Self::InvalidPattern,
            E::PatternBlocklisted => Self::PatternBlocklisted,
            E::PatternInUse => Self::PatternInUse,
            E::WrongPattern => Self::WrongPattern,
            E::Oracle(o) => o.into(),
            E::InvalidPhrase => Self::InvalidPhrase,
            E::InvalidParams => Self::InvalidParams,
            E::Corrupt => Self::Corrupt,
            E::Io(_) => Self::Io,
            E::NoFreeSlot => Self::NoFreeSlot,
            E::NoSpace => Self::NoSpace,
            E::NotFound => Self::NotFound,
            E::Locked => Self::Locked,
            E::InvalidArgument => Self::InvalidArgument,
            E::RetryLater => Self::RetryLater,
            E::VaultAlreadyPresent => Self::VaultAlreadyPresent,
            E::BackupIncomplete => Self::BackupIncomplete,
            E::Wiped => Self::Wiped,
        }
    }
}

impl From<hc::PatternError> for HidewellError {
    fn from(_: hc::PatternError) -> Self {
        Self::InvalidPattern
    }
}

type Res<T> = Result<T, HidewellError>;

// ============================================================================ callbacks

/// Hardware security level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SecurityLevel {
    /// iOS Secure Enclave.
    SecureEnclave,
    /// Android StrongBox.
    StrongBox,
    /// Android TEE.
    Tee,
    /// Software (tests only).
    SoftwareMock,
}

/// Continuous monotonic time, including sleep; never a wall-clock timestamp.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ClockSample {
    /// Exactly 16 bytes. A verified boot identity, or a random process-wide singleton
    /// shared by every oracle instance and device reopen in that process.
    pub epoch: Vec<u8>,
    /// Monotonic milliseconds within `epoch`, including device sleep.
    pub elapsed_millis: u64,
}

/// Platform hardware oracle (implemented in Swift/Kotlin).
#[uniffi::export(with_foreign)]
pub trait HardwareOracle: Send + Sync {
    /// Backing hardware.
    fn security_level(&self) -> SecurityLevel;
    /// Sample continuous monotonic time. Throw on failure; never fall back to wall
    /// time or infer a shared boot from similar or increasing tick values.
    fn clock_sample(&self) -> Res<ClockSample>;
    /// 32 bytes in, 32 bytes out, deterministic per hardware key
    /// (iOS: SE ECDH x-coordinate with `p256HashToCurve(input)`; Android: StrongBox HMAC).
    fn chain_step(&self, input: Vec<u8>) -> Res<Vec<u8>>;
    /// Seal with a hardware key that is not pattern-gated.
    fn seal_device_secret(&self, secret: Vec<u8>) -> Res<Vec<u8>>;
    /// Open what `seal_device_secret` produced.
    fn open_device_secret(&self, sealed: Vec<u8>) -> Res<Vec<u8>>;
}

/// Backup object fetcher (implemented in Swift/Kotlin over iCloud Drive / Google Drive).
#[uniffi::export(with_foreign)]
pub trait ObjectSource: Send + Sync {
    /// Bytes of object `name` in the backup folder; throw `NotFound` if absent.
    fn get(&self, name: String) -> Res<Vec<u8>>;
}

struct OracleAdapter(Arc<dyn HardwareOracle>);

fn oracle_err(e: HidewellError) -> hc::OracleError {
    match e {
        HidewellError::OracleKeyUnavailable => hc::OracleError::KeyUnavailable,
        HidewellError::OracleDeviceLocked => hc::OracleError::DeviceLocked,
        HidewellError::OracleBadOutput => hc::OracleError::BadOutput,
        HidewellError::OracleSealedBlobInvalid => hc::OracleError::SealedBlobInvalid,
        _ => hc::OracleError::Failed,
    }
}

impl hc::HardwareOracle for OracleAdapter {
    fn security_level(&self) -> hc::SecurityLevel {
        match self.0.security_level() {
            SecurityLevel::SecureEnclave => hc::SecurityLevel::SecureEnclave,
            SecurityLevel::StrongBox => hc::SecurityLevel::StrongBox,
            SecurityLevel::Tee => hc::SecurityLevel::Tee,
            SecurityLevel::SoftwareMock => hc::SecurityLevel::SoftwareMock,
        }
    }
    fn clock_sample(&self) -> Result<hc::ClockSample, hc::OracleError> {
        let sample = self.0.clock_sample().map_err(oracle_err)?;
        Ok(hc::ClockSample {
            epoch: sample
                .epoch
                .try_into()
                .map_err(|_| hc::OracleError::BadOutput)?,
            elapsed_millis: sample.elapsed_millis,
        })
    }
    fn chain_step(&self, input: Vec<u8>) -> Result<Vec<u8>, hc::OracleError> {
        self.0.chain_step(input).map_err(oracle_err)
    }
    fn seal_device_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>, hc::OracleError> {
        self.0.seal_device_secret(secret).map_err(oracle_err)
    }
    fn open_device_secret(&self, sealed: Vec<u8>) -> Result<Vec<u8>, hc::OracleError> {
        self.0.open_device_secret(sealed).map_err(oracle_err)
    }
}

fn oracle(o: Arc<dyn HardwareOracle>) -> Arc<dyn hc::HardwareOracle> {
    Arc::new(OracleAdapter(o))
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    struct ClockOracle(Res<ClockSample>);

    impl HardwareOracle for ClockOracle {
        fn security_level(&self) -> SecurityLevel {
            SecurityLevel::SoftwareMock
        }
        fn clock_sample(&self) -> Res<ClockSample> {
            self.0.clone()
        }
        fn chain_step(&self, _: Vec<u8>) -> Res<Vec<u8>> {
            panic!("clock validation must not invoke the hardware chain")
        }
        fn seal_device_secret(&self, _: Vec<u8>) -> Res<Vec<u8>> {
            panic!("clock validation must not seal secrets")
        }
        fn open_device_secret(&self, _: Vec<u8>) -> Res<Vec<u8>> {
            panic!("clock validation must not open secrets")
        }
    }

    #[test]
    fn clock_adapter_requires_exactly_sixteen_epoch_bytes() {
        for len in [0, 1, 15, 17, 32] {
            let callback = ClockOracle(Ok(ClockSample {
                epoch: vec![7; len],
                elapsed_millis: u64::MAX,
            }));
            assert_eq!(
                oracle(Arc::new(callback)).clock_sample(),
                Err(hc::OracleError::BadOutput)
            );
        }
        let callback = ClockOracle(Ok(ClockSample {
            epoch: vec![7; 16],
            elapsed_millis: u64::MAX,
        }));
        assert_eq!(
            oracle(Arc::new(callback)).clock_sample(),
            Ok(hc::ClockSample {
                epoch: [7; 16],
                elapsed_millis: u64::MAX,
            })
        );
    }

    #[test]
    fn clock_callback_errors_fail_closed() {
        for (input, output) in [
            (HidewellError::OracleBadOutput, hc::OracleError::BadOutput),
            (
                HidewellError::OracleDeviceLocked,
                hc::OracleError::DeviceLocked,
            ),
            (
                HidewellError::OracleKeyUnavailable,
                hc::OracleError::KeyUnavailable,
            ),
            (
                HidewellError::OracleSealedBlobInvalid,
                hc::OracleError::SealedBlobInvalid,
            ),
            (HidewellError::OracleFailed, hc::OracleError::Failed),
            (HidewellError::CallbackFailed, hc::OracleError::Failed),
            (HidewellError::Io, hc::OracleError::Failed),
        ] {
            assert_eq!(
                oracle(Arc::new(ClockOracle(Err(input)))).clock_sample(),
                Err(output)
            );
        }
    }
}

struct SourceAdapter(Arc<dyn ObjectSource>);

impl hc::ObjectSource for SourceAdapter {
    fn get(&self, name: &str) -> hc::Result<Vec<u8>> {
        self.0.get(name.to_owned()).map_err(|e| match e {
            HidewellError::NotFound => hc::Error::NotFound,
            _ => hc::Error::Io(std::io::ErrorKind::Other),
        })
    }
}

// ============================================================================ records

/// KDF parameters (from `calibrate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct KdfParams {
    /// Hardware chain length.
    pub chain_steps: u32,
    /// Argon2id memory KiB (≥ 65536).
    pub argon_m_kib: u32,
    /// Argon2id passes.
    pub argon_t: u32,
    /// Argon2id lanes.
    pub argon_p: u32,
}

impl From<KdfParams> for hc::KdfParams {
    fn from(p: KdfParams) -> Self {
        hc::KdfParams {
            chain_steps: p.chain_steps,
            argon_m_kib: p.argon_m_kib,
            argon_t: p.argon_t,
            argon_p: p.argon_p,
        }
    }
}

fn level(l: hc::SecurityLevel) -> SecurityLevel {
    match l {
        hc::SecurityLevel::SecureEnclave => SecurityLevel::SecureEnclave,
        hc::SecurityLevel::StrongBox => SecurityLevel::StrongBox,
        hc::SecurityLevel::Tee => SecurityLevel::Tee,
        hc::SecurityLevel::SoftwareMock => SecurityLevel::SoftwareMock,
    }
}

/// Device-wide unlock protection parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ProtectionInfo {
    /// Hardware security level.
    pub security_level: SecurityLevel,
    /// Hardware chain length k.
    pub chain_steps: u32,
    /// Argon2id memory KiB.
    pub argon2_memory_kib: u32,
    /// Argon2id passes (t).
    pub argon2_passes: u32,
    /// Argon2id lanes (p).
    pub argon2_lanes: u32,
    /// Measured duration of one attempt; not stored, so always nil/null.
    pub estimated_attempt_millis: Option<u64>,
}

/// Container geometry. Apps use `productionGeometry()`; tests may use small values.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Geometry {
    /// Chunk size in bytes.
    pub chunk_size: u32,
    /// Block size in bytes.
    pub block_size: u32,
    /// Blocks per file segment.
    pub segment_blocks: u32,
    /// Container size buckets in bytes, ascending.
    pub buckets: Vec<u64>,
    /// Free chunks rewritten per commit.
    pub cover_chunks_per_commit: u32,
    /// Filler fraction range in permille.
    pub filler_permille_min: u32,
    /// Filler fraction range in permille.
    pub filler_permille_max: u32,
    /// Filler slot reservations range.
    pub filler_slots_min: u32,
    /// Filler slot reservations range.
    pub filler_slots_max: u32,
}

impl From<Geometry> for hc::ContainerConfig {
    fn from(g: Geometry) -> Self {
        hc::ContainerConfig {
            chunk_size: g.chunk_size,
            block_size: g.block_size,
            segment_blocks: g.segment_blocks,
            buckets: g.buckets,
            cover_chunks_per_commit: g.cover_chunks_per_commit,
            filler_permille: (g.filler_permille_min, g.filler_permille_max),
            filler_slots: (g.filler_slots_min, g.filler_slots_max),
        }
    }
}

/// Input limits enforced by the core; larger values throw `InvalidArgument` before
/// anything is changed, so apps can mirror them in their UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct Limits {
    /// Item, album and tag names: bytes of UTF-8.
    pub name_bytes: u64,
    /// Item MIME types: bytes.
    pub mime_bytes: u64,
    /// Opaque item metadata (`NewItem.extra`, `setItemExtra`): bytes.
    pub extra_bytes: u64,
    /// Thumbnails: bytes.
    pub thumbnail_bytes: u64,
    /// `replaceContent` payload: bytes.
    pub replace_content_bytes: u64,
    /// Vault display names (`setName`): Unicode scalar values after trimming.
    pub vault_name_chars: u64,
}

/// The core's input limits.
#[uniffi::export]
pub fn limits() -> Limits {
    Limits {
        name_bytes: hc::MAX_NAME_LEN as u64,
        mime_bytes: hc::MAX_MIME_LEN as u64,
        extra_bytes: hc::MAX_EXTRA as u64,
        thumbnail_bytes: hc::MAX_THUMBNAIL_LEN as u64,
        replace_content_bytes: hc::MAX_REPLACE_LEN as u64,
        vault_name_chars: hc::MAX_VAULT_NAME_CHARS as u64,
    }
}

/// Production geometry (4 MiB chunks, 1/4/16/64 GiB buckets).
#[uniffi::export]
pub fn production_geometry() -> Geometry {
    let c = hc::ContainerConfig::production();
    Geometry {
        chunk_size: c.chunk_size,
        block_size: c.block_size,
        segment_blocks: c.segment_blocks,
        buckets: c.buckets,
        cover_chunks_per_commit: c.cover_chunks_per_commit,
        filler_permille_min: c.filler_permille.0,
        filler_permille_max: c.filler_permille.1,
        filler_slots_min: c.filler_slots.0,
        filler_slots_max: c.filler_slots.1,
    }
}

/// Metadata of a new item.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewItem {
    /// File name, ≤ `limits().nameBytes` bytes of UTF-8.
    pub name: String,
    /// MIME type, ≤ `limits().mimeBytes` bytes.
    pub mime: String,
    /// Created (Unix seconds).
    pub created: i64,
    /// Modified (Unix seconds).
    pub modified: i64,
    /// Album ids.
    pub albums: Vec<u32>,
    /// Tag ids.
    pub tags: Vec<u32>,
    /// Opaque app metadata, ≤ 4096 bytes (e.g. Live Photo pairing).
    #[uniffi(default = None)]
    pub extra: Option<Vec<u8>>,
}

impl From<NewItem> for hc::NewItem {
    fn from(n: NewItem) -> Self {
        hc::NewItem {
            name: n.name,
            mime: n.mime,
            created: n.created,
            modified: n.modified,
            albums: n.albums,
            tags: n.tags,
            extra: n.extra.unwrap_or_default(),
        }
    }
}

/// Item metadata.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemInfo {
    /// Id.
    pub id: u64,
    /// File name.
    pub name: String,
    /// MIME type.
    pub mime: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// Created.
    pub created: i64,
    /// Modified.
    pub modified: i64,
    /// Album ids.
    pub albums: Vec<u32>,
    /// Tag ids.
    pub tags: Vec<u32>,
    /// Has a stored thumbnail.
    pub has_thumbnail: bool,
    /// Opaque app metadata (empty if none).
    #[uniffi(default)]
    pub extra: Vec<u8>,
}

impl From<hc::ItemInfo> for ItemInfo {
    fn from(i: hc::ItemInfo) -> Self {
        ItemInfo {
            id: i.id,
            name: i.name,
            mime: i.mime,
            size: i.size,
            created: i.created,
            modified: i.modified,
            albums: i.albums,
            tags: i.tags,
            has_thumbnail: i.has_thumbnail,
            extra: i.extra,
        }
    }
}

/// Album or tag.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultLabel {
    /// Id.
    pub id: u32,
    /// Name.
    pub name: String,
}

fn labels(v: Vec<hc::Label>) -> Vec<VaultLabel> {
    v.into_iter()
        .map(|l| VaultLabel {
            id: l.id,
            name: l.name,
        })
        .collect()
}

/// A duress vault linked to its owner, with its cached display name.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct DecoyInfo {
    /// Link id (for `openManagedDecoy`).
    pub id: u32,
    /// Display name; empty if unset.
    pub name: String,
}

/// A named blob (initial manifest entries).
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct NamedBlob {
    /// Object name.
    pub name: String,
    /// Bytes.
    pub data: Vec<u8>,
}

/// One backup operation; execute in order, stop at the first failure.
#[derive(Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SyncOp {
    /// Upload a new immutable object (fails if it exists).
    PutObject {
        /// Name.
        name: String,
        /// Bytes.
        data: Vec<u8>,
    },
    /// Overwrite (or create) a manifest entry.
    PutEntry {
        /// Name.
        name: String,
        /// Bytes.
        data: Vec<u8>,
    },
    /// Delete an object.
    DeleteObject {
        /// Name.
        name: String,
    },
}

/// Strength rating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Strength {
    /// Blocklisted or < 14 bits.
    Weak,
    /// 14..20 bits.
    Fair,
    /// 20..26 bits.
    Good,
    /// ≥ 26 bits.
    Strong,
}

/// Blocklisted shape family (stable identifier; apps map it to copy such as
/// "Too common: U shape"). `NShape`, `CShape` and `Digit2` are reserved: those shapes
/// are rotations/mirrors of Z, U and S and report as those.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BlockedShape {
    /// `Line` family.
    Line,
    /// `LShape` family.
    LShape,
    /// `UShape` family.
    UShape,
    /// `Square` family.
    Square,
    /// `ZShape` family.
    ZShape,
    /// `NShape` family.
    NShape,
    /// `CShape` family.
    CShape,
    /// `VShape` family.
    VShape,
    /// `MShape` family.
    MShape,
    /// `WShape` family.
    WShape,
    /// `SShape` family.
    SShape,
    /// `Digit2` family.
    Digit2,
    /// `Digit7` family.
    Digit7,
    /// `JShape` family.
    JShape,
    /// `GShape` family.
    GShape,
    /// `Spiral` family.
    Spiral,
    /// `Snake` family.
    Snake,
    /// `Cross` family.
    Cross,
    /// `Plus` family.
    Plus,
    /// `TShape` family.
    TShape,
    /// `Equals` family.
    Equals,
    /// `Bars` family.
    Bars,
}

impl From<hc::BlockedShape> for BlockedShape {
    fn from(s: hc::BlockedShape) -> Self {
        match s {
            hc::BlockedShape::Line => Self::Line,
            hc::BlockedShape::LShape => Self::LShape,
            hc::BlockedShape::UShape => Self::UShape,
            hc::BlockedShape::Square => Self::Square,
            hc::BlockedShape::ZShape => Self::ZShape,
            hc::BlockedShape::NShape => Self::NShape,
            hc::BlockedShape::CShape => Self::CShape,
            hc::BlockedShape::VShape => Self::VShape,
            hc::BlockedShape::MShape => Self::MShape,
            hc::BlockedShape::WShape => Self::WShape,
            hc::BlockedShape::SShape => Self::SShape,
            hc::BlockedShape::Digit2 => Self::Digit2,
            hc::BlockedShape::Digit7 => Self::Digit7,
            hc::BlockedShape::JShape => Self::JShape,
            hc::BlockedShape::GShape => Self::GShape,
            hc::BlockedShape::Spiral => Self::Spiral,
            hc::BlockedShape::Snake => Self::Snake,
            hc::BlockedShape::Cross => Self::Cross,
            hc::BlockedShape::Plus => Self::Plus,
            hc::BlockedShape::TShape => Self::TShape,
            hc::BlockedShape::Equals => Self::Equals,
            hc::BlockedShape::Bars => Self::Bars,
        }
    }
}

/// Strength report.
#[derive(Debug, Clone, Copy, PartialEq, uniffi::Record)]
pub struct StrengthReport {
    /// Matches a blocklisted shape (setup will refuse it).
    pub blocklisted: bool,
    /// log2 of the estimated guess rank.
    pub guess_rank_log2: f64,
    /// Rating.
    pub strength: Strength,
    /// Which common shape it matches, if blocklisted.
    #[uniffi(default = None)]
    pub blocked_shape: Option<BlockedShape>,
}

/// Result of first-time setup.
#[derive(uniffi::Record)]
pub struct Created {
    /// Device handle.
    pub device: Arc<Device>,
    /// Persist outside the container (Keychain ThisDeviceOnly / app-private storage).
    pub sealed_device_secret: Vec<u8>,
    /// The first vault, unlocked.
    pub vault: Arc<Vault>,
    /// Upload each to the backup folder only if no object with that name exists.
    pub initial_entries: Vec<NamedBlob>,
}

/// A vault found by `Device.recoverWithPhrase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct RecoverableVault {
    /// Manifest / slot index.
    pub index: u8,
    /// Data is on this device: `Device.resetPatternWithPhrase` works; otherwise use
    /// `Device.restoreVault` from the cloud.
    pub present_locally: bool,
    /// It is a duress (decoy) vault; it keeps that role.
    pub is_duress: bool,
}

/// Result of restore setup.
#[derive(uniffi::Record)]
pub struct RestoreCreated {
    /// Device handle (no vaults until `restoreVault`).
    pub device: Arc<Device>,
    /// Persist like `Created.sealedDeviceSecret`.
    pub sealed_device_secret: Vec<u8>,
}

// ============================================================================ helpers

fn pattern(strokes: Vec<Vec<u8>>) -> Res<hc::Pattern> {
    Ok(hc::Pattern::from_drawn(strokes)?)
}

fn phrase(words: Vec<String>) -> Res<hc::RecoveryPhrase> {
    Ok(hc::RecoveryPhrase::parse(&words.join(" "))?)
}

fn file(path: &str, create: bool) -> Res<Box<dyn hc::Storage>> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .open(path)
        .map_err(|_| HidewellError::Io)?;
    Ok(Box::new(hc::FileStorage::new(f)))
}

// ============================================================================ free functions

/// First-time setup: creates the container file at `path` (must not exist).
#[uniffi::export]
pub fn create_device(
    path: String,
    oracle_impl: Arc<dyn HardwareOracle>,
    geometry: Geometry,
    params: KdfParams,
    phrase_words: Vec<String>,
    first_pattern: Vec<Vec<u8>>,
) -> Res<Created> {
    let c = hc::Device::create(
        file(&path, true)?,
        oracle(oracle_impl),
        geometry.into(),
        params.into(),
        &phrase(phrase_words)?,
        &pattern(first_pattern)?,
    )?;
    Ok(Created {
        device: Arc::new(Device(c.device)),
        sealed_device_secret: c.sealed_device_secret,
        vault: Arc::new(Vault(c.vault)),
        initial_entries: c
            .initial_entries
            .into_iter()
            .map(|(name, data)| NamedBlob { name, data })
            .collect(),
    })
}

/// Restore setup on a new phone: creates a fresh container at `path`, reserving the
/// slots of all real manifest entries (`scanBackup`). Then call `Device.restoreVault`.
#[uniffi::export]
pub fn create_device_for_restore(
    path: String,
    oracle_impl: Arc<dyn HardwareOracle>,
    geometry: Geometry,
    params: KdfParams,
    phrase_words: Vec<String>,
    real_indices: Vec<u8>,
) -> Res<RestoreCreated> {
    let (d, sealed) = hc::Device::create_for_restore(
        file(&path, true)?,
        oracle(oracle_impl),
        geometry.into(),
        params.into(),
        &phrase(phrase_words)?,
        &real_indices,
    )?;
    Ok(RestoreCreated {
        device: Arc::new(Device(d)),
        sealed_device_secret: sealed,
    })
}

/// Indices of real (non-filler) manifest entries, using only the phrase.
#[uniffi::export]
pub fn scan_backup(phrase_words: Vec<String>, source: Arc<dyn ObjectSource>) -> Res<Vec<u8>> {
    Ok(hc::backup::scan(
        &phrase(phrase_words)?,
        &SourceAdapter(source),
    )?)
}

/// Backup folder name for a phrase (same as `Device.backupNamespace`).
#[uniffi::export]
pub fn backup_namespace_for_phrase(phrase_words: Vec<String>) -> Res<String> {
    Ok(hc::backup::namespace(
        &phrase(phrase_words)?.backup_keypair().pk,
    ))
}

/// New random 12-word recovery phrase.
#[uniffi::export]
pub fn generate_phrase() -> Vec<String> {
    hc::RecoveryPhrase::generate().words()
}

/// Whether `words` is a valid 12-word phrase (checksum included).
#[uniffi::export]
pub fn validate_phrase(words: Vec<String>) -> bool {
    phrase(words).is_ok()
}

/// Normalised strokes (skipped-over nodes inserted) for display.
#[uniffi::export]
pub fn normalize_pattern(strokes: Vec<Vec<u8>>) -> Res<Vec<Vec<u8>>> {
    Ok(pattern(strokes)?.strokes().to_vec())
}

/// Setup checks for a new pattern: structure, ≥ 6 nodes, ≥ 2 direction changes, not
/// blocklisted. (Vault creation enforces the same and `PatternInUse`.)
#[uniffi::export]
pub fn check_new_pattern(strokes: Vec<Vec<u8>>) -> Res<()> {
    let p = pattern(strokes)?;
    p.check_policy()?;
    if hc::strength::is_blocklisted(&p) {
        return Err(HidewellError::PatternBlocklisted);
    }
    Ok(())
}

/// Strength meter.
#[uniffi::export]
pub fn pattern_strength(strokes: Vec<Vec<u8>>) -> Res<StrengthReport> {
    let r = hc::strength::evaluate(&pattern(strokes)?);
    Ok(StrengthReport {
        blocklisted: r.blocklisted,
        guess_rank_log2: r.guess_rank_log2,
        strength: match r.strength {
            hc::Strength::Weak => Strength::Weak,
            hc::Strength::Fair => Strength::Fair,
            hc::Strength::Good => Strength::Good,
            hc::Strength::Strong => Strength::Strong,
        },
        blocked_shape: r.blocked_shape.map(Into::into),
    })
}

/// Measure this device and choose KDF parameters (run once at setup, ~1–2 s).
#[uniffi::export]
pub fn calibrate(
    oracle_impl: Arc<dyn HardwareOracle>,
    chain_target_ms: u32,
    argon_target_ms: u32,
    argon_m_kib: u32,
) -> Res<KdfParams> {
    let o = oracle(oracle_impl);
    let p = hc::calibrate(
        o.as_ref(),
        hc::CalibrationTargets {
            chain: Duration::from_millis(chain_target_ms.into()),
            argon: Duration::from_millis(argon_target_ms.into()),
            argon_m_kib,
            chain_samples: 8,
        },
    )?;
    Ok(KdfParams {
        chain_steps: p.chain_steps,
        argon_m_kib: p.argon_m_kib,
        argon_t: p.argon_t,
        argon_p: p.argon_p,
    })
}

/// UX delay before the next attempt after `failures` consecutive failures.
#[uniffi::export]
pub fn retry_delay_seconds(failures: u32) -> u64 {
    hc::retry_delay(failures).as_secs()
}

/// RFC 9380 P-256 hash-to-curve (65-byte SEC1 uncompressed) for the iOS chain step.
#[uniffi::export]
pub fn p256_hash_to_curve(input: Vec<u8>) -> Vec<u8> {
    hc::p256_hash_to_curve(&input)
}

/// Manifest entry object name for slot `index` (0..15).
#[uniffi::export]
pub fn entry_object_name(index: u8) -> String {
    hc::backup::entry_object_name(index)
}

// ============================================================================ objects

/// An opened container (not unlocked).
#[derive(uniffi::Object)]
pub struct Device(hc::Device);

#[uniffi::export]
impl Device {
    /// Open the container at `path` with the stored sealed device secret. The
    /// platform must hold exclusive container ownership until this device and all
    /// of its vault/writer handles are dropped.
    #[uniffi::constructor]
    pub fn open(
        path: String,
        oracle_impl: Arc<dyn HardwareOracle>,
        geometry: Geometry,
        sealed_device_secret: Vec<u8>,
    ) -> Res<Arc<Self>> {
        Ok(Arc::new(Device(hc::Device::open(
            file(&path, false)?,
            oracle(oracle_impl),
            geometry.into(),
            &sealed_device_secret,
        )?)))
    }

    /// Try a pattern (duress patterns open the decoy and wipe the rest). A successful
    /// unlock invalidates previous handles to this vault and their unfinished writers.
    /// Patterns failing the setup policy throw `InvalidPattern` without being counted.
    pub fn unlock(&self, strokes: Vec<Vec<u8>>) -> Res<Arc<Vault>> {
        Ok(Arc::new(Vault(self.0.unlock(&pattern(strokes)?)?)))
    }

    /// Consecutive failed attempts.
    pub fn failed_attempts(&self) -> Res<u32> {
        Ok(self.0.failed_attempts()?)
    }

    /// Oracle security level (settings screen).
    pub fn security_level(&self) -> Res<SecurityLevel> {
        Ok(level(self.0.security_level()?))
    }

    /// Unlock protection parameters for display; no pattern needed.
    pub fn protection_info(&self) -> Res<ProtectionInfo> {
        let p = self.0.protection_info()?;
        Ok(ProtectionInfo {
            security_level: level(p.security_level),
            chain_steps: p.chain_steps,
            argon2_memory_kib: p.argon2_memory_kib,
            argon2_passes: p.argon2_passes,
            argon2_lanes: p.argon2_lanes,
            estimated_attempt_millis: p.estimated_attempt_millis,
        })
    }

    /// Seconds until the next pattern attempt is accepted (0 = now). Attempts before
    /// that throw `RetryLater`.
    pub fn retry_after_seconds(&self) -> Res<u64> {
        Ok(self.0.retry_after_seconds()?)
    }

    /// Backup folder name.
    pub fn backup_namespace(&self) -> Res<String> {
        Ok(self.0.backup_namespace()?)
    }

    /// Whether `phrase_words` is this device's recovery phrase. Nothing is stored
    /// or counted; an unparsable phrase returns false.
    pub fn verify_phrase(&self, phrase_words: Vec<String>) -> Res<bool> {
        match phrase(phrase_words) {
            Ok(p) => Ok(self.0.verify_phrase(&p)?),
            Err(_) => Ok(false),
        }
    }

    /// Forgotten pattern, step 1: vaults recoverable with the phrase from the
    /// local entries in this container (no cloud needed). Not a pattern attempt.
    pub fn recover_with_phrase(&self, phrase_words: Vec<String>) -> Res<Vec<RecoverableVault>> {
        Ok(self
            .0
            .recover_with_phrase(&phrase(phrase_words)?)?
            .into_iter()
            .map(|r| RecoverableVault {
                index: r.index,
                present_locally: r.present_locally,
                is_duress: r.is_duress,
            })
            .collect())
    }

    /// Forgotten pattern, step 2: set a new pattern for a locally present vault.
    pub fn reset_pattern_with_phrase(
        &self,
        phrase_words: Vec<String>,
        index: u8,
        strokes: Vec<Vec<u8>>,
    ) -> Res<()> {
        Ok(self
            .0
            .reset_pattern_with_phrase(&phrase(phrase_words)?, index, &pattern(strokes)?)?)
    }

    /// Destroy every key in the container; then delete the file, the sealed device
    /// secret and the hardware keys.
    pub fn erase(&self) -> Res<()> {
        Ok(self.0.erase()?)
    }

    /// After executing a `Vault.delete` plan (its filler entry uploaded), release the
    /// deleted vault's slot for reuse. Skipping it only costs a slot.
    pub fn confirm_vault_deleted(&self, plan: Arc<SyncPlan>) -> Res<()> {
        Ok(self.0.confirm_vault_deleted(&plan.0)?)
    }

    /// Restore manifest entry `index` with a new pattern (objects via `source`). Works
    /// on a restore container or an existing one where that vault is absent; throws
    /// `VaultAlreadyPresent` if it is live here.
    pub fn restore_vault(
        &self,
        phrase_words: Vec<String>,
        index: u8,
        strokes: Vec<Vec<u8>>,
        listing: Vec<String>,
        source: Arc<dyn ObjectSource>,
    ) -> Res<()> {
        Ok(self.0.restore_vault(
            &phrase(phrase_words)?,
            index,
            &pattern(strokes)?,
            &listing,
            &SourceAdapter(source),
        )?)
    }
}

/// A backup plan: fetch `ops()`, execute in order, then `Vault.syncComplete(plan)`.
#[derive(uniffi::Object)]
pub struct SyncPlan(hc::SyncPlan);

#[uniffi::export]
impl SyncPlan {
    /// Operations in order.
    pub fn ops(&self) -> Vec<SyncOp> {
        self.0
            .ops
            .iter()
            .map(|op| match op {
                hc::SyncOp::PutObject { name, data } => SyncOp::PutObject {
                    name: name.clone(),
                    data: data.clone(),
                },
                hc::SyncOp::PutEntry { name, data } => SyncOp::PutEntry {
                    name: name.clone(),
                    data: data.clone(),
                },
                hc::SyncOp::DeleteObject { name } => SyncOp::DeleteObject { name: name.clone() },
            })
            .collect()
    }

    /// Nothing to do (sync converged).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Streaming import of one item, sized or unsized (no plaintext temp files needed).
#[derive(uniffi::Object)]
pub struct ItemWriter(Mutex<Option<hc::ItemWriter>>);

#[uniffi::export]
impl ItemWriter {
    /// Item id it will get.
    pub fn id(&self) -> Res<u64> {
        let g = self.0.lock().map_err(|_| HidewellError::Locked)?;
        Ok(g.as_ref().ok_or(HidewellError::Locked)?.id())
    }

    /// Append bytes (any chunking).
    pub fn write(&self, data: Vec<u8>) -> Res<()> {
        let mut g = self.0.lock().map_err(|_| HidewellError::Locked)?;
        Ok(g.as_mut().ok_or(HidewellError::Locked)?.write(&data)?)
    }

    /// Finish (exactly `size` bytes written, or any amount for unsized imports) and
    /// commit; returns the item id.
    pub fn finish(&self, thumbnail: Option<Vec<u8>>) -> Res<u64> {
        let w = self
            .0
            .lock()
            .map_err(|_| HidewellError::Locked)?
            .take()
            .ok_or(HidewellError::Locked)?;
        Ok(w.finish(thumbnail.as_deref())?)
    }

    /// Abandon the import (written segments are scrubbed at the next commit).
    pub fn cancel(&self) {
        if let Ok(mut g) = self.0.lock() {
            g.take();
        }
    }
}

/// An unlocked vault. Call `lock()` when the app backgrounds.
#[derive(uniffi::Object)]
pub struct Vault(hc::Vault);

#[uniffi::export]
impl Vault {
    /// Zeroize keys and in-memory index now; the handle is dead afterwards.
    pub fn lock(&self) {
        self.0.lock();
    }

    /// All items, by id.
    pub fn list_items(&self) -> Res<Vec<ItemInfo>> {
        Ok(self.0.list_items()?.into_iter().map(Into::into).collect())
    }

    /// Item count.
    pub fn item_count(&self) -> Res<u64> {
        Ok(self.0.item_count()?)
    }

    /// One item.
    pub fn item(&self, id: u64) -> Res<ItemInfo> {
        Ok(self.0.item(id)?.into())
    }

    /// Random-access read (streaming players): up to `length` bytes at `offset`;
    /// shorter only at end of file.
    pub fn read(&self, id: u64, offset: u64, length: u64) -> Res<Vec<u8>> {
        Ok(self.0.read(id, offset, length)?)
    }

    /// Thumbnail bytes, if stored.
    pub fn thumbnail(&self, id: u64) -> Res<Option<Vec<u8>>> {
        Ok(self.0.thumbnail(id)?)
    }

    /// Import a small file held in memory.
    pub fn import(&self, meta: NewItem, data: Vec<u8>, thumbnail: Option<Vec<u8>>) -> Res<u64> {
        Ok(self.0.import(meta.into(), &data, thumbnail.as_deref())?)
    }

    /// Start a streaming import of exactly `size` bytes.
    pub fn begin_import(&self, meta: NewItem, size: u64) -> Res<Arc<ItemWriter>> {
        let w = self.0.begin_import(meta.into(), size)?;
        Ok(Arc::new(ItemWriter(Mutex::new(Some(w)))))
    }

    /// Start a streaming import whose size is only known at `finish` (camera recording).
    pub fn begin_import_unsized(&self, meta: NewItem) -> Res<Arc<ItemWriter>> {
        let w = self.0.begin_import_unsized(meta.into())?;
        Ok(Arc::new(ItemWriter(Mutex::new(Some(w)))))
    }

    /// Store or replace a thumbnail after import (≤ 4 MiB; empty removes it).
    pub fn set_thumbnail(&self, id: u64, bytes: Vec<u8>) -> Res<()> {
        Ok(self.0.set_thumbnail(id, &bytes)?)
    }

    /// Replace an item's content in place, keeping its id and other metadata; sets size
    /// and `modified` (Unix seconds, caller-defined) (≤ 16 MiB).
    pub fn replace_content(&self, id: u64, bytes: Vec<u8>, modified: i64) -> Res<()> {
        let bytes = hc::secret::SecretVec::new(bytes);
        Ok(self.0.replace_content(id, &bytes, modified)?)
    }

    /// Replace an item's opaque metadata (≤ 4096 bytes).
    pub fn set_item_extra(&self, id: u64, extra: Vec<u8>) -> Res<()> {
        Ok(self.0.set_item_extra(id, &extra)?)
    }

    /// Whether this vault is backed up (holds its entry key).
    pub fn backup_enabled(&self) -> Res<bool> {
        Ok(self.0.backup_enabled()?)
    }

    /// Enable backup for a vault created inside a duress vault, using the phrase.
    pub fn enable_backup(&self, phrase_words: Vec<String>) -> Res<()> {
        Ok(self.0.enable_backup(&phrase(phrase_words)?)?)
    }

    /// Current wipe-after-N-failures setting (0 = off).
    pub fn wipe_after(&self) -> Res<u32> {
        Ok(self.0.wipe_after()?)
    }

    /// Rename an item (≤ `limits().nameBytes`, else `InvalidArgument`).
    pub fn rename_item(&self, id: u64, name: String) -> Res<()> {
        Ok(self.0.rename_item(id, &name)?)
    }

    /// Replace an item's albums and tags.
    pub fn set_item_labels(&self, id: u64, albums: Vec<u32>, tags: Vec<u32>) -> Res<()> {
        Ok(self.0.set_item_labels(id, &albums, &tags)?)
    }

    /// Delete an item.
    pub fn delete_item(&self, id: u64) -> Res<()> {
        Ok(self.0.delete_item(id)?)
    }

    /// Create an album (name ≤ `limits().nameBytes`, else `InvalidArgument`).
    pub fn create_album(&self, name: String, created: i64) -> Res<u32> {
        Ok(self.0.create_album(&name, created)?)
    }

    /// Rename an album (≤ `limits().nameBytes`, else `InvalidArgument`).
    pub fn rename_album(&self, id: u32, name: String) -> Res<()> {
        Ok(self.0.rename_label(true, id, &name)?)
    }

    /// Delete an album (removed from items).
    pub fn delete_album(&self, id: u32) -> Res<()> {
        Ok(self.0.delete_label(true, id)?)
    }

    /// Albums.
    pub fn albums(&self) -> Res<Vec<VaultLabel>> {
        Ok(labels(self.0.albums()?))
    }

    /// Create a tag (name ≤ `limits().nameBytes`, else `InvalidArgument`).
    pub fn create_tag(&self, name: String) -> Res<u32> {
        Ok(self.0.create_tag(&name)?)
    }

    /// Rename a tag (≤ `limits().nameBytes`, else `InvalidArgument`).
    pub fn rename_tag(&self, id: u32, name: String) -> Res<()> {
        Ok(self.0.rename_label(false, id, &name)?)
    }

    /// Delete a tag (removed from items).
    pub fn delete_tag(&self, id: u32) -> Res<()> {
        Ok(self.0.delete_label(false, id)?)
    }

    /// Tags.
    pub fn tags(&self) -> Res<Vec<VaultLabel>> {
        Ok(labels(self.0.tags()?))
    }

    /// Create another vault (returned open). `duress = true` makes it a decoy linked
    /// to this vault (manage it with `openManagedDecoy`).
    pub fn create_vault(&self, strokes: Vec<Vec<u8>>, duress: bool) -> Res<Arc<Vault>> {
        Ok(Arc::new(Vault(
            self.0.create_vault(&pattern(strokes)?, duress)?,
        )))
    }

    /// Ids of decoys created from this vault.
    pub fn decoy_vaults(&self) -> Res<Vec<u32>> {
        Ok(self.0.decoy_vaults()?)
    }

    /// Linked decoys with their cached display names.
    pub fn decoys(&self) -> Res<Vec<DecoyInfo>> {
        Ok(self
            .0
            .decoys()?
            .into_iter()
            .map(|d| DecoyInfo {
                id: d.id,
                name: d.name,
            })
            .collect())
    }

    /// This vault's display name; empty if unset.
    pub fn name(&self) -> Res<String> {
        Ok(self.0.name()?)
    }

    /// Set this vault's display name: trimmed, ≤ 64 characters, empty clears.
    pub fn set_name(&self, name: String) -> Res<()> {
        Ok(self.0.set_name(&name)?)
    }

    /// Open a linked decoy without the duress wipe.
    pub fn open_managed_decoy(&self, id: u32) -> Res<Arc<Vault>> {
        Ok(Arc::new(Vault(self.0.open_managed_decoy(id)?)))
    }

    /// Change this vault's pattern (atomic).
    pub fn change_pattern(&self, strokes: Vec<Vec<u8>>) -> Res<()> {
        Ok(self.0.change_pattern(&pattern(strokes)?)?)
    }

    /// Delete this vault; returns the cloud cleanup plan to execute right away (do not
    /// pass it to `syncComplete`).
    pub fn delete(&self, listing: Vec<String>) -> Res<Arc<SyncPlan>> {
        Ok(Arc::new(SyncPlan(self.0.delete(&listing)?)))
    }

    /// Wipe the slot table after `n` consecutive failures (0 = off).
    pub fn set_wipe_after(&self, n: u32) -> Res<()> {
        Ok(self.0.set_wipe_after(n)?)
    }

    /// Next backup plan from the current folder listing (≤ `max_puts` uploads).
    pub fn sync_plan(&self, listing: Vec<String>, max_puts: u32) -> Res<Arc<SyncPlan>> {
        Ok(Arc::new(SyncPlan(self.0.sync_plan(&listing, max_puts)?)))
    }

    /// Record that every op of `plan` succeeded.
    pub fn sync_complete(&self, plan: Arc<SyncPlan>) -> Res<()> {
        Ok(self.0.sync_complete(&plan.0)?)
    }
}
