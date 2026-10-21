//! 12-word BIP39 recovery phrase (128-bit entropy) and the keys derived from it.
//!
//! ```text
//! recovery_key   = HKDF-SHA256(ikm = entropy, salt = ∅, info = "hidewell/recovery/v1")
//! backup_sk      = HKDF-SHA256(ikm = recovery_key, salt = ∅, info = "hidewell/backup-x25519/v1")
//! backup_pk      = X25519(backup_sk, 9)          (HPKE DHKEM(X25519, HKDF-SHA256) keypair)
//! ```
//! The device stores only `backup_pk`.

use core::fmt;

use bip39::{Language, Mnemonic};
use hpke::{Deserializable, Kem as _, Serializable};

use crate::crypto;
use crate::error::{Error, Result};
use crate::secret::{Secret, SecretKey, SecretVec};

/// HPKE KEM used for backup manifest entries: DHKEM(X25519, HKDF-SHA256).
pub type BackupKem = hpke::kem::X25519HkdfSha256;
/// HPKE KDF: HKDF-SHA256.
pub type BackupKdf = hpke::kdf::HkdfSha256;
/// HPKE AEAD: AES-256-GCM.
pub type BackupAead = hpke::aead::AesGcm256;
/// Length of the HPKE encapsulated key prefix.
pub const HPKE_ENC_LEN: usize = 32;
/// HPKE ciphertext expansion: encapsulated key + AEAD tag.
pub const HPKE_OVERHEAD: usize = HPKE_ENC_LEN + 16;

/// HPKE base-mode single-shot seal to the backup public key (RFC 9180).
/// Output: `enc (32) || ciphertext || tag (16)`.
pub fn seal_to_backup_key(pk: &[u8; 32], info: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let pk = <BackupKem as hpke::Kem>::PublicKey::from_bytes(pk).map_err(|_| Error::Corrupt)?;
    let (enc, ct) = hpke::single_shot_seal::<BackupAead, BackupKdf, BackupKem>(
        &hpke::OpModeS::Base,
        &pk,
        info,
        plaintext,
        &[],
    )
    .map_err(|_| Error::Corrupt)?;
    let mut out = Vec::with_capacity(HPKE_ENC_LEN + ct.len());
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Phrase entropy length (128 bits).
pub const ENTROPY_LEN: usize = 16;
/// Words in the phrase.
pub const WORD_COUNT: usize = 12;

/// The recovery phrase entropy. Zeroized on drop; `Debug` redacted.
pub struct RecoveryPhrase {
    entropy: Secret<ENTROPY_LEN>,
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase([REDACTED])")
    }
}

impl RecoveryPhrase {
    /// Fresh phrase from the OS CSPRNG.
    pub fn generate() -> Self {
        RecoveryPhrase {
            entropy: Secret::random(),
        }
    }

    /// From raw entropy (test vectors).
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        Ok(RecoveryPhrase {
            entropy: Secret::from_slice(entropy).ok_or(Error::InvalidPhrase)?,
        })
    }

    /// Parse 12 English BIP39 words (case-insensitive, any whitespace), verifying the
    /// checksum.
    pub fn parse(words: &str) -> Result<Self> {
        let normalized = zeroize::Zeroizing::new(
            words
                .split_whitespace()
                .map(str::to_lowercase)
                .collect::<Vec<_>>()
                .join(" "),
        );
        let m = Mnemonic::parse_in_normalized(Language::English, &normalized)
            .map_err(|_| Error::InvalidPhrase)?;
        if m.word_count() != WORD_COUNT {
            return Err(Error::InvalidPhrase);
        }
        let (mut arr, len) = m.to_entropy_array();
        let r = Self::from_entropy(&arr[..len]);
        zeroize::Zeroize::zeroize(&mut arr);
        r
    }

    /// The 12 words, to show once at setup.
    pub fn words(&self) -> Vec<String> {
        let m = Mnemonic::from_entropy_in(Language::English, self.entropy.expose())
            .expect("16 bytes is valid BIP39 entropy");
        m.words().map(str::to_owned).collect()
    }

    /// Recovery key.
    pub fn recovery_key(&self) -> SecretKey {
        crypto::hkdf32(self.entropy.expose(), &[b"hidewell/recovery/v1"])
    }

    /// Backup entry authentication key for manifest index `i`.
    pub fn entry_auth_key(&self, i: u8) -> SecretKey {
        let rk = self.recovery_key();
        crypto::hkdf32(rk.expose(), &[b"hidewell/entry-auth/v1", &[i]])
    }

    /// Backup X25519 keypair.
    pub fn backup_keypair(&self) -> BackupKeypair {
        let rk = self.recovery_key();
        let sk_bytes = crypto::hkdf32(rk.expose(), &[b"hidewell/backup-x25519/v1"]);
        let sk = <BackupKem as hpke::Kem>::PrivateKey::from_bytes(sk_bytes.expose())
            .expect("any 32 bytes is a valid X25519 private key");
        let pk = BackupKem::sk_to_pk(&sk);
        BackupKeypair {
            sk,
            pk: pk.to_bytes().into(),
        }
    }
}

/// Backup keypair derived from the phrase. The private key never touches storage.
pub struct BackupKeypair {
    pub(crate) sk: <BackupKem as hpke::Kem>::PrivateKey,
    /// Public key stored on the device.
    pub pk: [u8; 32],
}

impl BackupKeypair {
    /// Open a [`seal_to_backup_key`] ciphertext.
    pub fn open(&self, info: &[u8], sealed: &[u8]) -> Result<SecretVec> {
        if sealed.len() < HPKE_OVERHEAD {
            return Err(Error::Corrupt);
        }
        let (enc, ct) = sealed.split_at(HPKE_ENC_LEN);
        let enc =
            <BackupKem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| Error::Corrupt)?;
        hpke::single_shot_open::<BackupAead, BackupKdf, BackupKem>(
            &hpke::OpModeR::Base,
            &self.sk,
            &enc,
            info,
            ct,
            &[],
        )
        .map(SecretVec::new)
        .map_err(|_| Error::Corrupt)
    }
}

impl fmt::Debug for BackupKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupKeypair")
            .field("pk", &self.pk)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Official BIP39 English vectors (trezor/python-mnemonic vectors.json), 128-bit.
    const VECTORS: &[(&str, &str)] = &[
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        ),
        (
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
        ),
        (
            "23db8160a31d3e0dca3688ed941adbf3",
            "cat swing flag economy stadium alone churn speed unique patch report train",
        ),
        (
            "f30f8c1da665478f49b001d94c5fc452",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        ),
    ];

    #[test]
    fn bip39_vectors() {
        for (ent, words) in VECTORS {
            let p = RecoveryPhrase::from_entropy(&hex::decode(ent).unwrap()).unwrap();
            assert_eq!(p.words().join(" "), *words);
            let q = RecoveryPhrase::parse(words).unwrap();
            assert_eq!(q.entropy.expose().to_vec(), hex::decode(ent).unwrap());
        }
    }

    #[test]
    fn parse_rejects_bad_input() {
        // Wrong checksum word.
        assert!(RecoveryPhrase::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_err());
        // Unknown word.
        assert!(RecoveryPhrase::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abaut").is_err());
        // Wrong length: 11 words, and 24 words (valid BIP39 but not ours).
        assert!(RecoveryPhrase::parse(&["abandon"; 11].join(" ")).is_err());
        let w24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        assert!(RecoveryPhrase::parse(w24).is_err());
        // Case and whitespace insensitive.
        assert!(
            RecoveryPhrase::parse("  Zoo zoo ZOO zoo zoo zoo\tzoo zoo zoo zoo zoo   wrong ")
                .is_ok()
        );
    }

    #[test]
    fn derived_keys_vector() {
        let p = RecoveryPhrase::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(
            hex::encode(p.recovery_key().expose()),
            "af9616e93096c07e4664980899273ea5e33ed25ab1b585c207f3482536b33b3b"
        );
        assert_eq!(
            hex::encode(p.backup_keypair().pk),
            "3a682b4e99c8c15d9785a3cbbe5805d6ca8d9921040fe4bba8a8a2e6fb95015b"
        );
    }

    #[test]
    fn hpke_roundtrip_and_binding() {
        let kp = RecoveryPhrase::generate().backup_keypair();
        let ct = seal_to_backup_key(&kp.pk, b"info-1", b"secret entry").unwrap();
        assert_eq!(ct.len(), 12 + HPKE_OVERHEAD);
        assert_eq!(&kp.open(b"info-1", &ct).unwrap()[..], b"secret entry");
        assert_eq!(kp.open(b"info-2", &ct).err(), Some(Error::Corrupt));
        let other = RecoveryPhrase::generate().backup_keypair();
        assert_eq!(other.open(b"info-1", &ct).err(), Some(Error::Corrupt));
        let mut bad = ct.clone();
        bad[40] ^= 1;
        assert_eq!(kp.open(b"info-1", &bad).err(), Some(Error::Corrupt));
    }

    proptest! {
        #[test]
        fn words_roundtrip(ent in any::<[u8; 16]>()) {
            let p = RecoveryPhrase::from_entropy(&ent).unwrap();
            let words = p.words();
            prop_assert_eq!(words.len(), WORD_COUNT);
            let q = RecoveryPhrase::parse(&words.join(" ")).unwrap();
            prop_assert_eq!(q.entropy.expose(), &ent);
            prop_assert_eq!(p.backup_keypair().pk, q.backup_keypair().pk);
        }
    }
}
