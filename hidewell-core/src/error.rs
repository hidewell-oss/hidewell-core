//! Error type. Variants never carry secrets, file names, paths or counts.

use core::fmt;

use crate::oracle::OracleError;
use crate::pattern::PatternError;

/// All fallible core operations return this error.
///
/// Deliberately coarse: no variant carries user data (names, paths, sizes, counts),
/// so errors can be surfaced or logged by platform code without leaking vault metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Pattern is structurally invalid or violates the setup policy.
    Pattern(PatternError),
    /// Pattern matches a blocklisted common shape.
    PatternBlocklisted,
    /// Pattern unlocks an existing vault; choose another one.
    PatternInUse,
    /// No key slot matched (wrong pattern or no vault).
    WrongPattern,
    /// Hardware oracle failed.
    Oracle(OracleError),
    /// Recovery phrase invalid (unknown word, wrong length or checksum).
    InvalidPhrase,
    /// Stored KDF parameters below the security minimum, or otherwise invalid.
    InvalidParams,
    /// Authenticated decryption failed or structure invalid: tampering or corruption.
    Corrupt,
    /// Storage I/O failure (kind only; never a path).
    Io(std::io::ErrorKind),
    /// All key slots are reserved.
    NoFreeSlot,
    /// Container at its largest bucket and full.
    NoSpace,
    /// Item, album or tag not found.
    NotFound,
    /// Handle no longer valid (vault locked, or device state changed underneath it).
    Locked,
    /// Caller passed an argument outside the allowed range.
    InvalidArgument,
    /// Too many recent pattern attempts: wait `Device::retry_after_seconds`.
    RetryLater,
    /// The backup entry's vault is already live on this device; restoring it would
    /// overwrite it.
    VaultAlreadyPresent,
    /// A backup manifest entry is missing; the backup cannot be trusted to list every
    /// vault.
    BackupIncomplete,
    /// This attempt reached the wipe-after-N limit: every key slot was destroyed
    /// (returned once).
    Wiped,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.kind())
    }
}

impl From<OracleError> for Error {
    fn from(e: OracleError) -> Self {
        Error::Oracle(e)
    }
}

impl From<PatternError> for Error {
    fn from(e: PatternError) -> Self {
        Error::Pattern(e)
    }
}

/// Crate result alias.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    /// Every variant. The exhaustive match makes adding a variant a compile error here,
    /// so new variants are reviewed for user data.
    fn all() -> Vec<Error> {
        let sample = Error::Corrupt;
        match sample {
            Error::Pattern(_)
            | Error::PatternBlocklisted
            | Error::PatternInUse
            | Error::WrongPattern
            | Error::Oracle(_)
            | Error::InvalidPhrase
            | Error::InvalidParams
            | Error::Corrupt
            | Error::Io(_)
            | Error::NoFreeSlot
            | Error::NoSpace
            | Error::NotFound
            | Error::Locked
            | Error::InvalidArgument
            | Error::RetryLater
            | Error::VaultAlreadyPresent
            | Error::BackupIncomplete
            | Error::Wiped => {}
        }
        use crate::pattern::PatternError as P;
        let mut v = vec![
            Error::PatternBlocklisted,
            Error::PatternInUse,
            Error::WrongPattern,
            Error::InvalidPhrase,
            Error::InvalidParams,
            Error::Corrupt,
            Error::NoFreeSlot,
            Error::NoSpace,
            Error::NotFound,
            Error::Locked,
            Error::InvalidArgument,
            Error::RetryLater,
            Error::VaultAlreadyPresent,
            Error::BackupIncomplete,
            Error::Wiped,
        ];
        for p in [
            P::StrokeCount,
            P::EmptyStroke,
            P::NodeOutOfRange,
            P::RepeatedNode,
            P::SkipsNode,
            P::TooFewNodes,
            P::TooFewDirectionChanges,
            P::Malformed,
        ] {
            v.push(Error::Pattern(p));
        }
        for o in [
            OracleError::KeyUnavailable,
            OracleError::DeviceLocked,
            OracleError::BadOutput,
            OracleError::SealedBlobInvalid,
            OracleError::Failed,
        ] {
            v.push(Error::Oracle(o));
        }
        for k in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::Other,
        ] {
            v.push(Error::Io(k));
        }
        v
    }

    #[test]
    fn display_and_debug_never_carry_user_data() {
        // Errors built from real I/O failures on a path with a marker name.
        let marker = "SECRET_NAME_42.jpg";
        let io = std::fs::File::open(format!("/nonexistent-dir/{marker}")).unwrap_err();
        let mut errors = all();
        errors.push(Error::from(io));
        for e in errors {
            for s in [format!("{e}"), format!("{e:?}")] {
                assert!(
                    s.chars()
                        .all(|c| c.is_ascii_alphabetic() || "()".contains(c)),
                    "error text may only be variant names: {s}"
                );
                assert!(!s.contains("SECRET") && s.len() < 64);
            }
        }
    }
}
