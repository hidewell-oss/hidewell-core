//! Unlock key derivation.
//!
//! ```text
//! s_0       = SHA-256("hidewell/chain/init/v1" || encode(pattern))
//! in_i      = SHA-256("hidewell/chain/step/v1" || s_i || u32be(i))        i = 0..k
//! s_{i+1}   = oracle.chain_step(in_i)                                  (hardware)
//! unlock    = Argon2id(password = s_k, salt = device salt (32 B), m, t, p, 32 B out)
//! KEK_slot  = HKDF-SHA256(ikm = unlock, salt = ∅, info = "hidewell/kek/v1" || u8(slot))
//! ```
//!
//! The chain and Argon2id run exactly once per attempt, independent of the number of
//! vaults; per-slot KEKs are cheap HKDF expansions. The Argon2 salt is device-wide: the
//! vault is unknown at unlock, and one Argon2 run per vault would break the time
//! budget and leak the vault count through timing.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto;
use crate::error::{Error, Result};
use crate::oracle::{HardwareOracle, OracleError};
use crate::pattern::Pattern;
use crate::secret::{SecretKey, SecretVec};

/// Device-wide Argon2 salt length.
pub const SALT_LEN: usize = 32;

/// Minimum Argon2 memory in KiB for production parameters (64 MiB).
pub const MIN_ARGON_M_KIB: u32 = 64 * 1024;
/// Minimum hardware chain length for production parameters.
pub const MIN_CHAIN_STEPS: u32 = 4;
/// Maximum hardware chain length (bounds calibration on very fast hardware).
pub const MAX_CHAIN_STEPS: u32 = 2048;
/// Maximum Argon2 memory in KiB (1 GiB) accepted from storage or callers.
pub const MAX_ARGON_M_KIB: u32 = 1 << 20;
/// Maximum Argon2 passes chosen by calibration.
pub const MAX_ARGON_T: u32 = 16;

/// KDF cost parameters, calibrated per device and stored in the device state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Hardware chain length k.
    pub chain_steps: u32,
    /// Argon2id memory in KiB.
    pub argon_m_kib: u32,
    /// Argon2id passes.
    pub argon_t: u32,
    /// Argon2id lanes.
    pub argon_p: u32,
}

impl KdfParams {
    /// Check parameters against the security minimums.
    ///
    /// The minimums are relaxed only when compiled for tests (`cfg(test)` or the
    /// `mock-oracle` feature, which cannot be enabled in release builds), so tests can
    /// use tiny parameters; release builds always enforce them, including for
    /// parameters read back from storage.
    pub fn validate(&self) -> Result<()> {
        let (min_m, min_k) = if cfg!(any(test, feature = "mock-oracle")) {
            (8, 1)
        } else {
            (MIN_ARGON_M_KIB, MIN_CHAIN_STEPS)
        };
        let ok = self.chain_steps >= min_k
            && self.chain_steps <= MAX_CHAIN_STEPS
            && self.argon_m_kib >= min_m
            && self.argon_m_kib <= MAX_ARGON_M_KIB
            && self.argon_t >= 1
            && self.argon_t <= 64
            && (1..=16).contains(&self.argon_p)
            && self.argon_m_kib >= 8 * self.argon_p;
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidParams)
        }
    }

    /// Tiny parameters for tests.
    #[cfg(any(test, feature = "mock-oracle"))]
    pub fn insecure_test_params() -> Self {
        KdfParams {
            chain_steps: 3,
            argon_m_kib: 8,
            argon_t: 1,
            argon_p: 1,
        }
    }

    fn argon(&self) -> Result<Argon2<'static>> {
        let params = Params::new(self.argon_m_kib, self.argon_t, self.argon_p, Some(32))
            .map_err(|_| Error::InvalidParams)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Run the hardware chain over the canonical pattern encoding.
pub fn hardware_chain(
    oracle: &dyn HardwareOracle,
    pattern: &Pattern,
    steps: u32,
) -> Result<SecretKey> {
    let enc = pattern.encode();
    let mut s = crypto::sha256(&[b"hidewell/chain/init/v1", &enc]);
    for i in 0..steps {
        let mut input = crypto::sha256(&[b"hidewell/chain/step/v1", &s, &i.to_be_bytes()]);
        let out = SecretVec::new(oracle.chain_step(input.to_vec())?);
        input.zeroize();
        if out.len() != 32 {
            return Err(OracleError::BadOutput.into());
        }
        s.copy_from_slice(&out);
    }
    Ok(SecretKey::from_array(&mut s))
}

/// Derive the per-attempt unlock key: hardware chain then Argon2id (runs once).
pub fn derive_unlock_key(
    oracle: &dyn HardwareOracle,
    pattern: &Pattern,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<SecretKey> {
    params.validate()?;
    let chain = hardware_chain(oracle, pattern, params.chain_steps)?;
    argon2id(&chain, salt, params)
}

fn argon2id(password: &SecretKey, salt: &[u8], params: &KdfParams) -> Result<SecretKey> {
    let mut out = [0u8; 32];
    params
        .argon()?
        .hash_password_into(password.expose(), salt, &mut out)
        .map_err(|_| Error::InvalidParams)?;
    Ok(SecretKey::from_array(&mut out))
}

/// Per-slot key-encryption key.
pub fn slot_kek(unlock_key: &SecretKey, slot: u8) -> SecretKey {
    crypto::hkdf32(unlock_key.expose(), &[b"hidewell/kek/v1", &[slot]])
}

/// Calibration targets.
#[derive(Clone, Copy, Debug)]
pub struct CalibrationTargets {
    /// Target wall time of the hardware chain (design target: 200–300 ms).
    pub chain: Duration,
    /// Target wall time of Argon2id (design target: ~0.5 s).
    pub argon: Duration,
    /// Argon2 memory in KiB (≥ [`MIN_ARGON_M_KIB`] in release builds).
    pub argon_m_kib: u32,
    /// Chain steps timed to estimate the per-step cost.
    pub chain_samples: u32,
}

impl Default for CalibrationTargets {
    fn default() -> Self {
        CalibrationTargets {
            chain: Duration::from_millis(250),
            argon: Duration::from_millis(500),
            argon_m_kib: MIN_ARGON_M_KIB,
            chain_samples: 8,
        }
    }
}

/// Measure this device and choose `k` and Argon2 passes for the targets.
///
/// k = clamp(round(target_chain / per_step), MIN_CHAIN_STEPS, MAX_CHAIN_STEPS).
/// Argon2 memory is fixed by `targets.argon_m_kib`, p = 1; passes t are chosen from a
/// single t = 1 measurement: t = clamp(round(target_argon / time(t=1)), 1, MAX_ARGON_T).
pub fn calibrate(oracle: &dyn HardwareOracle, targets: CalibrationTargets) -> Result<KdfParams> {
    if targets.chain_samples == 0 {
        return Err(Error::InvalidArgument);
    }
    let start = Instant::now();
    let mut s = [0u8; 32];
    for _ in 0..targets.chain_samples {
        let out = SecretVec::new(oracle.chain_step(s.to_vec())?);
        if out.len() != 32 {
            return Err(OracleError::BadOutput.into());
        }
        s.copy_from_slice(&out);
    }
    let per_step = start.elapsed().as_secs_f64() / f64::from(targets.chain_samples);
    let k = (targets.chain.as_secs_f64() / per_step.max(1e-9)).round();
    let k = (k.min(f64::from(MAX_CHAIN_STEPS)) as u32).max(MIN_CHAIN_STEPS);

    let mut probe = KdfParams {
        chain_steps: k,
        argon_m_kib: targets.argon_m_kib,
        argon_t: 1,
        argon_p: 1,
    };
    probe.validate()?;
    let pw = SecretKey::random();
    let start = Instant::now();
    argon2id(&pw, &[0u8; SALT_LEN], &probe)?;
    let one = start.elapsed().as_secs_f64();
    let t = (targets.argon.as_secs_f64() / one.max(1e-9)).round();
    probe.argon_t = (t.min(f64::from(MAX_ARGON_T)) as u32).max(1);
    probe.validate()?;
    Ok(probe)
}

/// Escalating delay, enforced by the core, before the next attempt after `failures`
/// consecutive failures: none for the first 5, then 30 s doubling, capped at 1 h.
pub fn retry_delay(failures: u32) -> Duration {
    if failures < 5 {
        return Duration::ZERO;
    }
    let exp = (failures - 5).min(7);
    Duration::from_secs((30u64 << exp).min(3600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockOracle;

    fn pattern() -> Pattern {
        Pattern::new(vec![vec![0, 1, 2, 7, 12, 13]]).unwrap()
    }

    #[test]
    fn chain_vector_with_mock_oracle() {
        let oracle = MockOracle::new([7u8; 32]);
        let params = KdfParams::insecure_test_params();
        let salt = [9u8; SALT_LEN];
        let chain = hardware_chain(&oracle, &pattern(), 3).unwrap();
        assert_eq!(oracle.chain_steps_executed(), 3);
        // Fixed vectors: regenerate only on a deliberate format change.
        assert_eq!(
            hex::encode(chain.expose()),
            "ad32ea2c7f5eafb835ec2a4e5172227869ee21bcb51ea2adcaf7380c46a90f5f"
        );
        let unlock = derive_unlock_key(&oracle, &pattern(), &salt, &params).unwrap();
        assert_eq!(
            hex::encode(unlock.expose()),
            "a611d92714cf1318baa13227d1b388dc33dbcd70960b5e6f940642720e7c9ad4"
        );
        assert_eq!(
            hex::encode(slot_kek(&unlock, 5).expose()),
            "45b1f9f55ce06c449bf0a2a0ec4cc5b650c5863ae0ccaa350e2585bef0b8a74a"
        );
    }

    #[test]
    fn chain_depends_on_everything() {
        let o1 = MockOracle::new([1u8; 32]);
        let o2 = MockOracle::new([2u8; 32]);
        let p2 = Pattern::new(vec![vec![0, 1, 2, 7, 12, 11]]).unwrap();
        let base = hardware_chain(&o1, &pattern(), 3).unwrap();
        assert_ne!(base, hardware_chain(&o2, &pattern(), 3).unwrap());
        assert_ne!(base, hardware_chain(&o1, &p2, 3).unwrap());
        assert_ne!(base, hardware_chain(&o1, &pattern(), 4).unwrap());
        let params = KdfParams::insecure_test_params();
        let a = derive_unlock_key(&o1, &pattern(), &[0; 32], &params).unwrap();
        let b = derive_unlock_key(&o1, &pattern(), &[1; 32], &params).unwrap();
        assert_ne!(a, b);
        assert_ne!(slot_kek(&a, 0), slot_kek(&a, 1));
    }

    #[test]
    fn params_validation() {
        let mut p = KdfParams::insecure_test_params();
        assert!(p.validate().is_ok());
        p.chain_steps = 0;
        assert_eq!(p.validate(), Err(Error::InvalidParams));
        p.chain_steps = MAX_CHAIN_STEPS + 1;
        assert_eq!(p.validate(), Err(Error::InvalidParams));
    }

    #[test]
    fn calibration_is_bounded() {
        let oracle = MockOracle::new([3u8; 32]);
        let p = calibrate(
            &oracle,
            CalibrationTargets {
                chain: Duration::from_millis(5),
                argon: Duration::from_millis(5),
                argon_m_kib: 64,
                chain_samples: 4,
            },
        )
        .unwrap();
        assert!((MIN_CHAIN_STEPS..=MAX_CHAIN_STEPS).contains(&p.chain_steps));
        assert!((1..=MAX_ARGON_T).contains(&p.argon_t));
        assert_eq!(p.argon_m_kib, 64);
    }

    #[test]
    fn retry_delays() {
        assert_eq!(retry_delay(4), Duration::ZERO);
        assert_eq!(retry_delay(5), Duration::from_secs(30));
        assert_eq!(retry_delay(6), Duration::from_secs(60));
        assert_eq!(retry_delay(100), Duration::from_secs(3600));
    }
}
