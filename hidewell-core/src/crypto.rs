//! Thin wrappers over RustCrypto primitives: AES-256-GCM with random 96-bit nonces and
//! HKDF-SHA256. No primitives are implemented here.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::secret::{SecretKey, SecretVec};

/// AES-GCM nonce length.
pub const NONCE_LEN: usize = 12;
/// AES-GCM tag length.
pub const TAG_LEN: usize = 16;
/// Ciphertext expansion of [`seal`]: nonce || ciphertext || tag.
pub const AEAD_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// HKDF-SHA256 to a 32-byte key. `info` parts are concatenated.
pub fn hkdf32(ikm: &[u8], info: &[&[u8]]) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand_multi_info(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SecretKey::from_array(&mut out)
}

/// SHA-256 over concatenated parts.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn cipher(key: &SecretKey) -> Aes256Gcm {
    Aes256Gcm::new(key.expose().into())
}

/// Encrypt `plaintext` into `out` (len = plaintext.len() + AEAD_OVERHEAD) as
/// nonce || ciphertext || tag, with a fresh random nonce.
pub fn seal_into(key: &SecretKey, aad: &[u8], plaintext: &[u8], out: &mut [u8]) {
    assert_eq!(
        out.len(),
        plaintext.len() + AEAD_OVERHEAD,
        "seal_into length"
    );
    let (nonce_out, rest) = out.split_at_mut(NONCE_LEN);
    let (body, tag_out) = rest.split_at_mut(plaintext.len());
    crate::rng::fill_os(nonce_out);
    body.copy_from_slice(plaintext);
    let nonce = Nonce::try_from(&*nonce_out).expect("nonce length");
    let tag = cipher(key)
        .encrypt_inout_detached(&nonce, aad, body.into())
        .expect("AES-GCM encryption cannot fail for in-range lengths");
    tag_out.copy_from_slice(&tag);
}

/// Encrypt to a new vector.
pub fn seal(key: &SecretKey, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; plaintext.len() + AEAD_OVERHEAD];
    seal_into(key, aad, plaintext, &mut out);
    out
}

/// Decrypt nonce || ciphertext || tag. Returns [`Error::Corrupt`] on any failure.
pub fn open(key: &SecretKey, aad: &[u8], sealed: &[u8]) -> Result<SecretVec> {
    if sealed.len() < AEAD_OVERHEAD {
        return Err(Error::Corrupt);
    }
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let (body, tag) = rest.split_at(rest.len() - TAG_LEN);
    let nonce = Nonce::try_from(nonce).map_err(|_| Error::Corrupt)?;
    let tag = Tag::try_from(tag).map_err(|_| Error::Corrupt)?;
    let mut buf = SecretVec::new(body.to_vec());
    cipher(key)
        .decrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into(), &tag)
        .map_err(|_| Error::Corrupt)?;
    Ok(buf)
}

/// Build an AAD / info string from a domain label and fixed-width fields.
pub fn label(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + fields.iter().map(|f| f.len()).sum::<usize>());
    v.extend_from_slice(domain);
    for f in fields {
        v.extend_from_slice(f);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let k = SecretKey::random();
        let ct = seal(&k, b"aad", b"hello");
        assert_eq!(ct.len(), 5 + AEAD_OVERHEAD);
        assert_eq!(&open(&k, b"aad", &ct).unwrap()[..], b"hello");
        assert_eq!(open(&k, b"aaX", &ct), Err(Error::Corrupt));
        let mut bad = ct.clone();
        bad[13] ^= 1;
        assert_eq!(open(&k, b"aad", &bad), Err(Error::Corrupt));
        assert_eq!(open(&SecretKey::random(), b"aad", &ct), Err(Error::Corrupt));
        assert_eq!(open(&k, b"aad", &ct[..10]), Err(Error::Corrupt));
    }

    #[test]
    fn hkdf_rfc5869_case3_prefix() {
        // RFC 5869 test case 3 (SHA-256, empty salt and info), first 32 bytes of OKM.
        let ikm = [0x0bu8; 22];
        let k = hkdf32(&ikm, &[]);
        assert_eq!(
            hex::encode(k.expose()),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
    }
}
