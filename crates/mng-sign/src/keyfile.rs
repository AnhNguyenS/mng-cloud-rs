use std::{fs, io::Write, path::Path};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

/// Private key file kept offline. The `d` scalar is hex; `x`/`y` are the
/// matching public point in base64url so the file is self-describing.
#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateKeyFile {
    pub kty: String,
    pub crv: String,
    pub d: String,
    pub x: String,
    pub y: String,
}

/// Public key pinned into the service worker at package time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl PublicJwk {
    pub fn p256(x: &[u8], y: &[u8]) -> Self {
        Self {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        }
    }
}

pub fn generate(out: &Path) -> Result<PublicJwk> {
    if out.exists() {
        bail!("refusing to overwrite existing key: {}", out.display());
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let signing = SigningKey::random(&mut OsRng);
    let public = public_jwk(&signing);
    let key = PrivateKeyFile {
        kty: "EC".to_owned(),
        crv: "P-256".to_owned(),
        d: hex::encode(signing.to_bytes().as_slice()),
        x: public.x.clone(),
        y: public.y.clone(),
    };
    write_private(out, &key)?;
    Ok(public)
}

pub fn load_signing(path: &Path) -> Result<SigningKey> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let key: PrivateKeyFile = serde_json::from_slice(&bytes).context("parse private key JSON")?;
    if key.kty != "EC" || key.crv != "P-256" {
        bail!("unsupported private key type: {}/{}", key.kty, key.crv);
    }
    let scalar = hex::decode(&key.d).context("private key d is not hex")?;
    SigningKey::from_slice(&scalar).context("invalid P-256 private key")
}

pub fn load_public(path: &Path) -> Result<VerifyingKey> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let jwk: PublicJwk = serde_json::from_slice(&bytes).context("parse public key JSON")?;
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        bail!("unsupported public key type: {}/{}", jwk.kty, jwk.crv);
    }
    let x = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .context("public key x is not base64url")?;
    let y = URL_SAFE_NO_PAD
        .decode(&jwk.y)
        .context("public key y is not base64url")?;
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).context("invalid P-256 public point")
}

pub fn public_jwk(signing: &SigningKey) -> PublicJwk {
    let verifying = signing.verifying_key();
    let point = verifying.to_encoded_point(false);
    let bytes = point.as_bytes();
    PublicJwk::p256(&bytes[1..33], &bytes[33..65])
}

/// Write a private key with owner-only permissions on Unix.
pub fn write_private(path: &Path, key: &PrivateKeyFile) -> Result<()> {
    let mut data = serde_json::to_vec_pretty(key)?;
    data.push(b'\n');

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        file.write_all(&data)?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    Ok(())
}

pub fn write_public(path: &Path, public: &PublicJwk) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let mut data = serde_json::to_vec_pretty(public)?;
    data.push(b'\n');
    fs::write(path, data).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
