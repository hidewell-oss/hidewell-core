//! Secret byte containers: heap-allocated, zeroized on drop, best-effort `mlock`ed,
//! and never printed by `Debug`.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Best-effort: lock the pages backing `bytes` into RAM so they are not swapped.
///
/// Errors are ignored (mobile OSes may deny `mlock` or cap the budget). The pages are
/// intentionally never unlocked: `munlock` is not reference counted, so unlocking on
/// drop could unlock a page still holding another secret. Locked pages are small and
/// are reused by the allocator.
fn mlock_best_effort(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    if let Ok(guard) = region::lock(bytes.as_ptr(), bytes.len()) {
        core::mem::forget(guard);
    }
}

/// A fixed-size secret (key material). Zeroized on drop.
pub struct Secret<const N: usize>(Box<[u8; N]>);

/// 32-byte key.
pub type SecretKey = Secret<32>;

impl<const N: usize> Secret<N> {
    /// Takes ownership of `bytes` and zeroizes the source array.
    pub fn from_array(bytes: &mut [u8; N]) -> Self {
        let mut s = Self::zero();
        s.0.copy_from_slice(bytes);
        bytes.zeroize();
        s
    }

    /// Copies from a slice of exactly `N` bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != N {
            return None;
        }
        let mut s = Self::zero();
        s.0.copy_from_slice(bytes);
        Some(s)
    }

    /// Fresh random secret from the OS CSPRNG.
    pub fn random() -> Self {
        let mut s = Self::zero();
        crate::rng::fill_os(&mut s.0[..]);
        s
    }

    fn zero() -> Self {
        let b = Box::new([0u8; N]);
        mlock_best_effort(&b[..]);
        Secret(b)
    }

    /// Borrow the secret bytes.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Explicit copy (secrets are not `Clone` to make copies visible in review).
    pub fn duplicate(&self) -> Self {
        let mut s = Self::zero();
        s.0.copy_from_slice(&self.0[..]);
        s
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for Secret<N> {}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0[..].ct_eq(&other.0[..]).into()
    }
}

impl<const N: usize> Eq for Secret<N> {}

/// Variable-length secret buffer (decrypted plaintext etc.). Zeroized on drop,
/// redacted `Debug`.
#[derive(Default)]
pub struct SecretVec(Zeroizing<Vec<u8>>);

impl SecretVec {
    /// Wrap an owned buffer.
    pub fn new(v: Vec<u8>) -> Self {
        SecretVec(Zeroizing::new(v))
    }

    /// Copy out as a plain vector (caller takes responsibility for the copy).
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl core::ops::Deref for SecretVec {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl core::ops::DerefMut for SecretVec {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretVec([REDACTED])")
    }
}

impl PartialEq for SecretVec {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.len() == other.0.len() && bool::from(self.0[..].ct_eq(&other.0[..]))
    }
}

impl Eq for SecretVec {}
