//! Deterministic software [`HardwareOracle`] for tests.
//!
//! Compiled only with `cfg(test)` or the `mock-oracle` feature, and the crate refuses to
//! compile with `mock-oracle` in a build without `debug_assertions` (see `lib.rs`), so it
//! can never ship in a release build.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::crypto;
use crate::oracle::{ClockSample, HardwareOracle, OracleError, SecurityLevel};
use crate::secret::SecretKey;

/// Software oracle: chain step = HMAC-SHA256(key, input); seal = AES-256-GCM under a
/// key derived from the same seed.
pub struct MockOracle {
    chain_key: SecretKey,
    seal_key: SecretKey,
    steps: AtomicU64,
    clock: Mutex<Result<ClockSample, OracleError>>,
}

impl MockOracle {
    /// Oracle whose behaviour is fully determined by `seed` (models one device).
    pub fn new(seed: [u8; 32]) -> Self {
        MockOracle {
            chain_key: crypto::hkdf32(&seed, &[b"mock/chain"]),
            seal_key: crypto::hkdf32(&seed, &[b"mock/seal"]),
            steps: AtomicU64::new(0),
            clock: Mutex::new(Ok(ClockSample {
                epoch: seed[..16].try_into().expect("16 bytes"),
                elapsed_millis: 0,
            })),
        }
    }

    /// Number of chain steps executed so far (for tests asserting "exactly once").
    pub fn chain_steps_executed(&self) -> u64 {
        self.steps.load(Ordering::SeqCst)
    }

    /// Set the exact deterministic clock result, including regressions and failures.
    pub fn set_clock_sample(&self, sample: Result<ClockSample, OracleError>) {
        *self.clock.lock().unwrap() = sample;
    }

    /// Advance monotonic test time, without changing the epoch or any wall clock.
    pub fn advance_clock_millis(&self, millis: u64) {
        let mut clock = self.clock.lock().unwrap();
        let sample = clock.as_mut().expect("clock must not be failing");
        sample.elapsed_millis = sample
            .elapsed_millis
            .checked_add(millis)
            .expect("clock overflow");
    }

    /// Advance monotonic test time by whole seconds.
    pub fn advance_clock_for_tests(&self, secs: u64) {
        self.advance_clock_millis(secs.checked_mul(1000).expect("clock overflow"));
    }
}

impl HardwareOracle for MockOracle {
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::SoftwareMock
    }

    fn clock_sample(&self) -> Result<ClockSample, OracleError> {
        *self.clock.lock().unwrap()
    }

    fn chain_step(&self, input: Vec<u8>) -> Result<Vec<u8>, OracleError> {
        if input.len() != 32 {
            return Err(OracleError::BadOutput);
        }
        self.steps.fetch_add(1, Ordering::SeqCst);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.chain_key.expose())
            .expect("any key length");
        mac.update(&input);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn seal_device_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>, OracleError> {
        Ok(crypto::seal(&self.seal_key, b"mock/device-secret", &secret))
    }

    fn open_device_secret(&self, sealed: Vec<u8>) -> Result<Vec<u8>, OracleError> {
        crypto::open(&self.seal_key, b"mock/device-secret", &sealed)
            .map(|v| v.to_vec())
            .map_err(|_| OracleError::SealedBlobInvalid)
    }
}
