//! Randomness. All randomness comes from the OS CSPRNG (`getrandom`); bulk fill uses a
//! ChaCha20 stream freshly seeded from the OS per call.
//!
//! RNG failure panics: there is no safe way to continue without randomness (fail closed).

use chacha20::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use zeroize::Zeroize;

/// Fill from the OS CSPRNG directly. Used for keys, nonces and salts.
pub fn fill_os(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS CSPRNG unavailable");
}

/// Fill a (possibly large) buffer with uniformly random bytes.
pub fn fill_bulk(buf: &mut [u8]) {
    if buf.len() <= 256 {
        fill_os(buf);
        return;
    }
    let mut seed = [0u8; 32];
    fill_os(&mut seed);
    let mut rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    rng.fill_bytes(buf);
}

/// Random array.
pub fn array<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    fill_os(&mut a);
    a
}

/// Uniform integer in `0..n` (rejection sampling, no modulo bias). `n` must be > 0.
pub fn below(n: u64) -> u64 {
    assert!(n > 0, "below(0)");
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let v = u64::from_le_bytes(array::<8>());
        if v < zone {
            return v % n;
        }
    }
}

/// Uniform integer in the inclusive range `lo..=hi`.
pub fn range_inclusive(lo: u64, hi: u64) -> u64 {
    assert!(lo <= hi);
    lo + below(hi - lo + 1)
}

/// Fisher–Yates shuffle.
pub fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = below(i as u64 + 1) as usize;
        v.swap(i, j);
    }
}
