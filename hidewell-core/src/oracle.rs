//! Hardware oracle: the device-bound, non-exportable key operations implemented by the
//! platform (iOS Secure Enclave, Android StrongBox/TEE) and called back from core.
//!
//! The trait is FFI-shaped: byte vectors in/out, a flat error enum, `Send + Sync`.

use p256::NistP256;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::hash2curve::{ExpandMsgXmd, hash_from_bytes};
use sha2::Sha256;

/// Strength of the hardware backing the oracle, shown in settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    /// iOS Secure Enclave.
    SecureEnclave,
    /// Android StrongBox secure element.
    StrongBox,
    /// Android TEE (StrongBox unavailable).
    Tee,
    /// Software mock (tests only; cannot be compiled into release builds).
    SoftwareMock,
}

/// Oracle failure. Carries no data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleError {
    /// The hardware key is missing or permanently invalidated.
    KeyUnavailable,
    /// The device is locked / user authentication required by the key policy.
    DeviceLocked,
    /// The oracle returned bytes of an unexpected length or format.
    BadOutput,
    /// Sealed blob failed to open (tampered, or from another device/key).
    SealedBlobInvalid,
    /// Any other platform failure.
    Failed,
}

/// A continuous monotonic clock reading, never a wall-clock timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockSample {
    /// Identity of this clock's epoch. Reuse only when the platform can verify that
    /// readings share the same boot. Otherwise use a random process-wide singleton,
    /// shared by every oracle instance and device reopen in that process.
    pub epoch: [u8; 16],
    /// Milliseconds since an arbitrary origin within `epoch`, including device sleep.
    /// Readings within one epoch must never go backwards or follow wall-clock changes.
    pub elapsed_millis: u64,
}

/// Device-bound hardware operations.
///
/// Implementations must use a non-exportable hardware key that is bound to this device
/// (iOS: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` Secure Enclave key; Android:
/// StrongBox, else TEE, Keystore key with `setUnlockedDeviceRequired(true)`).
pub trait HardwareOracle: Send + Sync {
    /// Backing hardware.
    fn security_level(&self) -> SecurityLevel;

    /// Sample the platform's continuous monotonic clock. Fail rather than substitute
    /// wall time, a guessed boot identity, or a stale sample when the clock fails.
    fn clock_sample(&self) -> Result<ClockSample, OracleError>;

    /// One step of the unlock chain. `input` is 32 bytes; output must be 32 bytes and a
    /// deterministic function of `input` and the hardware key.
    ///
    /// - iOS: `ECDH(se_key, p256_hash_to_curve(input))`, returning the shared x-coordinate.
    /// - Android: `HMAC-SHA256(strongbox_key, input)`.
    fn chain_step(&self, input: Vec<u8>) -> Result<Vec<u8>, OracleError>;

    /// Seal a small secret under a hardware key that is NOT gated by the pattern
    /// (it is used before unlock). Output is an opaque blob for [`Self::open_device_secret`].
    fn seal_device_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>, OracleError>;

    /// Open a blob produced by [`Self::seal_device_secret`] on this device.
    fn open_device_secret(&self, sealed: Vec<u8>) -> Result<Vec<u8>, OracleError>;
}

/// Domain separation tag for [`p256_hash_to_curve`] (RFC 9380 §3.1).
pub const HASH_TO_CURVE_DST: &[u8] = b"HIDEWELL-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_";

/// Map `input` to a P-256 point with RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` and return the
/// 65-byte SEC1 uncompressed encoding. For the iOS Secure Enclave chain step.
pub fn p256_hash_to_curve(input: &[u8]) -> Vec<u8> {
    hash_to_curve_with_dst(input, HASH_TO_CURVE_DST)
}

fn hash_to_curve_with_dst(input: &[u8], dst: &[u8]) -> Vec<u8> {
    let p = hash_from_bytes::<NistP256, ExpandMsgXmd<Sha256>>(&[input], &[dst])
        .expect("DST is non-empty and shorter than 256 bytes");
    p.to_affine().to_sec1_point(false).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9380_p256_vectors() {
        // RFC 9380 Appendix J.1.1, P256_XMD:SHA-256_SSWU_RO_.
        let dst = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
        let cases: [(&[u8], &str, &str); 2] = [
            (
                b"",
                "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
                "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
            ),
            (
                b"abc",
                "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
                "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
            ),
        ];
        for (msg, x, y) in cases {
            let p = hash_to_curve_with_dst(msg, dst);
            assert_eq!(p.len(), 65);
            assert_eq!(p[0], 0x04);
            assert_eq!(hex::encode(&p[1..33]), x);
            assert_eq!(hex::encode(&p[33..]), y);
        }
        assert_eq!(p256_hash_to_curve(b"x").len(), 65);
    }
}
