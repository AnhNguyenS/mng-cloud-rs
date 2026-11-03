#![forbid(unsafe_code)]

//! Thin WebAssembly boundary around `mng_core::crypto`.
//!
//! JavaScript only passes ciphertext, plaintext and public metadata across
//! this boundary. The password-derived key and IV stay in Rust/WASM memory and
//! are zeroized when the session is dropped.

use mng_core::crypto::{block_id, RepoKey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct E2eeSession {
    inner: RepoKey,
}

#[wasm_bindgen]
impl E2eeSession {
    /// Unlock a Seafile encrypted library.
    ///
    /// `salt_hex` is empty for encryption version 2 and required for version 3.
    #[wasm_bindgen(js_name = unlock)]
    pub fn unlock(
        repo_id: &str,
        password: &str,
        enc_version: u32,
        magic_hex: &str,
        random_key_hex: &str,
        salt_hex: &str,
    ) -> Result<E2eeSession, JsValue> {
        RepoKey::unlock(
            enc_version,
            repo_id,
            password,
            magic_hex,
            random_key_hex,
            salt_hex,
        )
        .map(|inner| Self { inner })
        .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = encryptBlock)]
    pub fn encrypt_block(&self, plain: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.encrypt_block(plain).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = decryptBlock)]
    pub fn decrypt_block(&self, ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.decrypt_block(ciphertext).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = ciphertextLen)]
    pub fn ciphertext_len(plain_len: usize) -> usize {
        RepoKey::ciphertext_len(plain_len)
    }
}

/// Seafile block id: lowercase SHA-1 hex of the encrypted block.
#[wasm_bindgen(js_name = blockId)]
pub fn block_id_hex(ciphertext: &[u8]) -> String {
    block_id(ciphertext)
}

fn to_js_error(error: mng_core::Error) -> JsValue {
    JsValue::from_str(&error.to_string())
}
