//! Seafile encrypted-library (E2EE) engine.
//!
//! Format reproduced from the live browser implementation and verified against
//! WebCrypto vectors:
//!
//! * v2 salt: fixed `da9045c306c7cc26`
//! * v3 salt: 32 random bytes stored with the library
//! * key        = PBKDF2-SHA256(password, salt, 1000, 32)
//! * magic      = PBKDF2-SHA256(repo_id || password, salt, 1000, 32)
//! * key IV     = PBKDF2-SHA256(key, salt, 10, 16)
//! * random key = AES-256-CBC(key, key IV, secret) where secret is 32 bytes
//! * content key = PBKDF2-SHA256(secret, salt, 1000, 32)
//! * content IV  = PBKDF2-SHA256(content key, salt, 10, 16)
//! * blocks      = AES-256-CBC(content key, content IV, PKCS#7)
//! * block id    = SHA-1(ciphertext)
//!
//! Plaintext, passwords and derived keys never leave this module in the
//! browser build. Key material is zeroized on drop.

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;

type Encryptor = cbc::Encryptor<Aes256>;
type Decryptor = cbc::Decryptor<Aes256>;

/// Fixed salt used by Seafile encryption version 2.
pub const FIXED_SALT: [u8; 8] = [0xda, 0x90, 0x45, 0xc3, 0x06, 0xc7, 0xcc, 0x26];

/// Seafile stores encrypted files in fixed 8 MiB plaintext blocks.
pub const BLOCK_BYTES: usize = 8 * 1024 * 1024;

const KEY_BYTES: usize = 32;
const IV_BYTES: usize = 16;
const SALT_V3_BYTES: usize = 32;
const AES_BLOCK_BYTES: usize = 16;

/// Derived content key and IV for one unlocked library.
pub struct RepoKey {
    key: Zeroizing<[u8; KEY_BYTES]>,
    iv: [u8; IV_BYTES],
    salt: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for RepoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoKey")
            .field("salt_len", &self.salt.len())
            .finish_non_exhaustive()
    }
}

impl RepoKey {
    /// Verify the library password and derive the content key/IV.
    ///
    /// `salt_hex` is ignored for version 2 and required for version 3.
    pub fn unlock(
        enc_version: u32,
        repo_id: &str,
        password: &str,
        magic_hex: &str,
        random_key_hex: &str,
        salt_hex: &str,
    ) -> Result<Self, Error> {
        if repo_id.is_empty() || password.is_empty() {
            return Err(Error::Config("library id and password are required".into()));
        }
        let salt = salt_for(enc_version, salt_hex)?;
        let password_bytes = password.as_bytes();

        let mut key = Zeroizing::new([0u8; KEY_BYTES]);
        pbkdf2_sha256(password_bytes, &salt, 1000, key.as_mut())?;

        let mut magic_input = Vec::with_capacity(repo_id.len() + password_bytes.len());
        magic_input.extend_from_slice(repo_id.as_bytes());
        magic_input.extend_from_slice(password_bytes);
        let mut computed_magic = Zeroizing::new([0u8; KEY_BYTES]);
        pbkdf2_sha256(&magic_input, &salt, 1000, computed_magic.as_mut())?;
        magic_input.zeroize();

        let expected_magic =
            hex::decode(magic_hex.trim()).map_err(|_| Error::InvalidHex("magic"))?;
        if expected_magic.len() != KEY_BYTES
            || computed_magic
                .as_slice()
                .ct_eq(expected_magic.as_slice())
                .unwrap_u8()
                != 1
        {
            return Err(Error::WrongPassword);
        }

        let mut key_iv = [0u8; IV_BYTES];
        pbkdf2_sha256(key.as_ref(), &salt, 10, &mut key_iv)?;

        let random_key =
            hex::decode(random_key_hex.trim()).map_err(|_| Error::InvalidHex("random_key"))?;
        let encrypted_key = Zeroizing::new(random_key);
        if encrypted_key.is_empty() || encrypted_key.len() % AES_BLOCK_BYTES != 0 {
            return Err(Error::InvalidLibraryKey);
        }
        let secret = Decryptor::new_from_slices(key.as_ref(), &key_iv)
            .map_err(|_| Error::InvalidLibraryKey)?
            .decrypt_padded_vec_mut::<Pkcs7>(encrypted_key.as_slice())
            .map_err(|_| Error::InvalidLibraryKey)?;
        let secret = Zeroizing::new(secret);
        if secret.len() != KEY_BYTES {
            return Err(Error::InvalidLibraryKey);
        }

        let mut content_key = Zeroizing::new([0u8; KEY_BYTES]);
        pbkdf2_sha256(secret.as_slice(), &salt, 1000, content_key.as_mut())?;
        let mut content_iv = [0u8; IV_BYTES];
        pbkdf2_sha256(content_key.as_ref(), &salt, 10, &mut content_iv)?;

        Ok(Self {
            key: content_key,
            iv: content_iv,
            salt: Zeroizing::new(salt),
        })
    }

    /// Encrypt one plaintext block with PKCS#7 padding.
    pub fn encrypt_block(&self, plain: &[u8]) -> Result<Vec<u8>, Error> {
        if plain.len() > BLOCK_BYTES {
            return Err(Error::BlockTooLarge(plain.len()));
        }
        Encryptor::new_from_slices(self.key.as_ref(), &self.iv)
            .map_err(|_| Error::InvalidCiphertext)
            .map(|cipher| cipher.encrypt_padded_vec_mut::<Pkcs7>(plain))
    }

    /// Decrypt one ciphertext block and validate the padding.
    pub fn decrypt_block(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK_BYTES != 0 {
            return Err(Error::InvalidCiphertext);
        }
        if ciphertext.len() > BLOCK_BYTES + AES_BLOCK_BYTES {
            return Err(Error::InvalidCiphertext);
        }
        let plain = Decryptor::new_from_slices(self.key.as_ref(), &self.iv)
            .map_err(|_| Error::InvalidCiphertext)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| Error::InvalidCiphertext)?;
        if plain.len() > BLOCK_BYTES {
            return Err(Error::InvalidCiphertext);
        }
        Ok(plain)
    }

    /// Ciphertext length for a given plaintext length, including padding.
    pub fn ciphertext_len(plain_len: usize) -> usize {
        plain_len + AES_BLOCK_BYTES - (plain_len % AES_BLOCK_BYTES)
    }
}

/// SHA-1 of the ciphertext, the block identifier used by Seafile.
pub fn block_id(ciphertext: &[u8]) -> String {
    hex::encode(Sha1::digest(ciphertext))
}

fn salt_for(enc_version: u32, salt_hex: &str) -> Result<Vec<u8>, Error> {
    match enc_version {
        2 => Ok(FIXED_SALT.to_vec()),
        3 => {
            let salt = hex::decode(salt_hex.trim()).map_err(|_| Error::InvalidHex("salt"))?;
            if salt.len() != SALT_V3_BYTES {
                return Err(Error::InvalidSalt);
            }
            Ok(salt)
        }
        other => Err(Error::UnsupportedVersion(other)),
    }
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) -> Result<(), Error> {
    if rounds == 0 || out.is_empty() {
        return Err(Error::Config("invalid PBKDF2 parameters".into()));
    }
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, rounds, out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize)]
    struct Fixture {
        password: String,
        repo_id: String,
        magic_hex: String,
        random_key_hex: String,
        salt_v3_hex: String,
        plain_hex: String,
        cipher_hex: String,
        block_id: String,
        empty_cipher_hex: String,
        empty_block_id: String,
        v3: FixtureV3,
    }

    #[derive(Debug, serde::Deserialize)]
    struct FixtureV3 {
        magic_hex: String,
        random_key_hex: String,
        cipher_hex: String,
        block_id: String,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../tests/fixtures/e2ee_kat.json"))
            .expect("fixture must be valid JSON")
    }

    fn unlock_v2(f: &Fixture) -> RepoKey {
        RepoKey::unlock(
            2,
            &f.repo_id,
            &f.password,
            &f.magic_hex,
            &f.random_key_hex,
            "",
        )
        .expect("fixture password must unlock")
    }

    #[test]
    fn browser_vector_v2_matches() {
        let f = fixture();
        let repo = unlock_v2(&f);
        let plain = hex::decode(&f.plain_hex).unwrap();
        let expected_cipher = hex::decode(&f.cipher_hex).unwrap();

        let cipher = repo.encrypt_block(&plain).unwrap();
        assert_eq!(cipher, expected_cipher);
        assert_eq!(block_id(&cipher), f.block_id);

        let decrypted = repo.decrypt_block(&expected_cipher).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn empty_block_matches_browser() {
        let f = fixture();
        let repo = unlock_v2(&f);
        let cipher = repo.encrypt_block(&[]).unwrap();
        assert_eq!(hex::encode(&cipher), f.empty_cipher_hex);
        assert_eq!(block_id(&cipher), f.empty_block_id);
        assert!(repo.decrypt_block(&cipher).unwrap().is_empty());
    }

    #[test]
    fn browser_vector_v3_matches() {
        let f = fixture();
        let repo = RepoKey::unlock(
            3,
            &f.repo_id,
            &f.password,
            &f.v3.magic_hex,
            &f.v3.random_key_hex,
            &f.salt_v3_hex,
        )
        .expect("v3 fixture must unlock");
        let plain = hex::decode(&f.plain_hex).unwrap();
        let expected_cipher = hex::decode(&f.v3.cipher_hex).unwrap();
        let cipher = repo.encrypt_block(&plain).unwrap();
        assert_eq!(cipher, expected_cipher);
        assert_eq!(block_id(&cipher), f.v3.block_id);
        assert_eq!(repo.decrypt_block(&expected_cipher).unwrap(), plain);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let f = fixture();
        let mut magic = f.magic_hex.clone();
        magic.replace_range(0..2, "00");
        let result = RepoKey::unlock(2, &f.repo_id, &f.password, &magic, &f.random_key_hex, "");
        assert!(matches!(result, Err(Error::WrongPassword)));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let f = fixture();
        let repo = unlock_v2(&f);
        let mut cipher = hex::decode(&f.cipher_hex).unwrap();
        let last = cipher.len() - 1;
        cipher[last] ^= 0xff;
        assert!(repo.decrypt_block(&cipher).is_err());
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        let f = fixture();
        assert!(matches!(
            RepoKey::unlock(
                4,
                &f.repo_id,
                &f.password,
                &f.magic_hex,
                &f.random_key_hex,
                ""
            ),
            Err(Error::UnsupportedVersion(4))
        ));
        assert!(matches!(
            RepoKey::unlock(
                3,
                &f.repo_id,
                &f.password,
                &f.magic_hex,
                &f.random_key_hex,
                ""
            ),
            Err(Error::InvalidSalt)
        ));
        assert!(matches!(
            RepoKey::unlock(2, &f.repo_id, &f.password, "zz", &f.random_key_hex, ""),
            Err(Error::InvalidHex("magic"))
        ));
    }

    #[test]
    fn round_trips_many_lengths() {
        let f = fixture();
        let repo = unlock_v2(&f);
        for len in [0usize, 1, 15, 16, 17, 255, 4096, 65_537] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let cipher = repo.encrypt_block(&plain).unwrap();
            assert_eq!(cipher.len(), RepoKey::ciphertext_len(len));
            assert_eq!(repo.decrypt_block(&cipher).unwrap(), plain);
        }
    }

    #[test]
    fn oversized_block_is_rejected() {
        let f = fixture();
        let repo = unlock_v2(&f);
        let plain = vec![0u8; BLOCK_BYTES + 1];
        assert!(matches!(
            repo.encrypt_block(&plain),
            Err(Error::BlockTooLarge(n)) if n == BLOCK_BYTES + 1
        ));
    }
}
