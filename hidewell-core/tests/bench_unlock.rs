//! Unlock-time benchmark with production KDF parameters chosen by `calibrate`.
//!
//! The mock oracle sleeps `HIDEWELL_BENCH_STEP_MS` (default 20) per chain step to model
//! Secure Enclave / StrongBox latency. Run (optimised, mock allowed):
//! `cargo test -p hidewell-core --profile perf --test bench_unlock -- --ignored --nocapture`

use std::sync::Arc;
use std::time::{Duration, Instant};

use hidewell_core::mock::MockOracle;
use hidewell_core::{
    CalibrationTargets, ContainerConfig, Device, HardwareOracle, MemStorage, OracleError, Pattern,
    RecoveryPhrase, SecurityLevel, calibrate,
};

struct SlowOracle {
    inner: MockOracle,
    step: Duration,
}

impl HardwareOracle for SlowOracle {
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::SoftwareMock
    }
    fn clock_sample(&self) -> Result<hidewell_core::ClockSample, OracleError> {
        self.inner.clock_sample()
    }
    fn chain_step(&self, input: Vec<u8>) -> Result<Vec<u8>, OracleError> {
        std::thread::sleep(self.step);
        self.inner.chain_step(input)
    }
    fn seal_device_secret(&self, s: Vec<u8>) -> Result<Vec<u8>, OracleError> {
        self.inner.seal_device_secret(s)
    }
    fn open_device_secret(&self, s: Vec<u8>) -> Result<Vec<u8>, OracleError> {
        self.inner.open_device_secret(s)
    }
}

#[test]
#[ignore = "benchmark; run with --profile perf -- --ignored --nocapture"]
fn unlock_time_with_production_params() {
    let step_ms: u64 = std::env::var("HIDEWELL_BENCH_STEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let oracle = Arc::new(SlowOracle {
        inner: MockOracle::new([1u8; 32]),
        step: Duration::from_millis(step_ms),
    });
    let params = calibrate(oracle.as_ref(), CalibrationTargets::default()).unwrap();
    let pattern = Pattern::new(vec![vec![7, 0, 11, 22, 13, 4, 8, 15, 21]]).unwrap();
    // Small geometry: container size does not affect unlock (KDF + 16 slots + index).
    let c = Device::create(
        Box::new(MemStorage::new()),
        oracle.clone(),
        ContainerConfig::tiny(),
        params,
        &RecoveryPhrase::generate(),
        &pattern,
    )
    .unwrap();
    drop(c.vault);
    let mut times = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        drop(c.device.unlock(&pattern).unwrap());
        times.push(t.elapsed());
    }
    times.sort();
    println!(
        "step {step_ms} ms: k = {}, argon2id m = {} KiB t = {} p = {}; unlock min {:?} median {:?} max {:?}",
        params.chain_steps,
        params.argon_m_kib,
        params.argon_t,
        params.argon_p,
        times[0],
        times[2],
        times[4]
    );
    assert!(times[2] < Duration::from_secs(2));
}
