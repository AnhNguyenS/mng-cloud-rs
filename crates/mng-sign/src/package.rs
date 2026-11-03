use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::keyfile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub generated_at: u64,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

/// Copy the web template, stamp the version/public key and sign the result.
///
/// The private key is only used on the offline signing machine.
pub fn package(web: &Path, out: &Path, version: &str, signing: &SigningKey) -> Result<Manifest> {
    validate_version(version)?;
    if !web.is_dir() {
        bail!("web directory does not exist: {}", web.display());
    }
    if out.exists() {
        bail!("output already exists: {}", out.display());
    }
    if out.starts_with(web) {
        bail!("output directory must not be inside the web source");
    }

    copy_tree(web, out)?;
    stamp(out, version, &keyfile::public_jwk(signing))?;

    let assets = collect(out)?;
    if assets.is_empty() {
        bail!("no assets found in {}", out.display());
    }
    let manifest = Manifest {
        version: version.to_owned(),
        generated_at: unix_now()?,
        assets,
    };
    let bytes = serde_json::to_vec(&manifest)?;
    fs::write(out.join("manifest.json"), &bytes).context("write manifest.json")?;

    let signature: Signature = signing.sign(&bytes);
    fs::write(out.join("manifest.sig"), hex::encode(signature.to_bytes()))
        .context("write manifest.sig")?;
    Ok(manifest)
}

/// Verify the signature, then every asset hash and the complete file set.
pub fn verify(root: &Path, public: &VerifyingKey) -> Result<Manifest> {
    let manifest_bytes = fs::read(root.join("manifest.json")).context("read manifest.json")?;
    let signature_hex =
        fs::read_to_string(root.join("manifest.sig")).context("read manifest.sig")?;
    let signature_bytes = hex::decode(signature_hex.trim()).context("manifest.sig is not hex")?;
    let signature =
        Signature::from_slice(&signature_bytes).context("invalid ECDSA signature encoding")?;
    public
        .verify(&manifest_bytes, &signature)
        .context("manifest signature does not match")?;

    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).context("parse manifest.json")?;
    validate_version(&manifest.version)?;

    let actual = collect(root)?;
    if actual.len() != manifest.assets.len() {
        bail!(
            "asset count mismatch: manifest has {}, directory has {}",
            manifest.assets.len(),
            actual.len()
        );
    }
    for (expected, found) in manifest.assets.iter().zip(actual.iter()) {
        if expected.path != found.path {
            bail!(
                "asset order/path mismatch: expected {}, found {}",
                expected.path,
                found.path
            );
        }
        if expected.sha256 != found.sha256 || expected.size != found.size {
            bail!("asset content mismatch: {}", expected.path);
        }
    }
    Ok(manifest)
}

pub fn collect(root: &Path) -> Result<Vec<Asset>> {
    let mut assets = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry.with_context(|| format!("walk {}", root.display()))?;
        if entry.file_type().is_symlink() {
            bail!(
                "symlinks are not allowed in a release: {}",
                entry.path().display()
            );
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = relative_path(root, entry.path())?;
        if is_excluded(&relative) {
            continue;
        }
        let bytes =
            fs::read(entry.path()).with_context(|| format!("read {}", entry.path().display()))?;
        assets.push(Asset {
            path: relative,
            sha256: hex::encode(Sha256::digest(&bytes)),
            size: bytes.len() as u64,
        });
    }
    assets.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(assets)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).with_context(|| format!("create {}", destination.display()))?;
    for entry in WalkDir::new(source).follow_links(false).sort_by_file_name() {
        let entry = entry.with_context(|| format!("walk {}", source.display()))?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .with_context(|| format!("strip prefix {}", source.display()))?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!(
                "symlinks are not allowed in the web source: {}",
                entry.path().display()
            );
        }
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target).with_context(|| format!("create {}", target.display()))?;
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative_text = relative_path(source, entry.path())?;
        if is_excluded(&relative_text) {
            continue;
        }
        fs::copy(entry.path(), &target)
            .with_context(|| format!("copy {} to {}", entry.path().display(), target.display()))?;
    }
    Ok(())
}

fn stamp(root: &Path, version: &str, public: &keyfile::PublicJwk) -> Result<()> {
    let sw_path = root.join("sw.js");
    let mut worker = fs::read_to_string(&sw_path).context("read sw.js")?;
    replace_required(
        &mut worker,
        "'__MNG_VERSION__'",
        &serde_json::to_string(version)?,
    )?;
    replace_required(
        &mut worker,
        "/*__MNG_UPDATE_PUBKEY__*/ null",
        &serde_json::to_string(public)?,
    )?;
    fs::write(&sw_path, worker).context("write stamped sw.js")?;

    // The visible version in the shell is optional, but must never stay as a
    // placeholder when present.
    let index_path = root.join("index.html");
    if index_path.is_file() {
        let mut index = fs::read_to_string(&index_path).context("read index.html")?;
        if index.contains("__MNG_VERSION__") {
            index = index.replace("__MNG_VERSION__", version);
            fs::write(&index_path, index).context("write stamped index.html")?;
        }
    }
    Ok(())
}

fn replace_required(text: &mut String, needle: &str, value: &str) -> Result<()> {
    if !text.contains(needle) {
        bail!("missing release placeholder: {needle}");
    }
    *text = text.replace(needle, value);
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("strip prefix {}", root.display()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let part = component.as_os_str().to_string_lossy();
        if part == "." {
            continue;
        }
        if part == ".." || part.contains('\\') || part.contains('\0') {
            bail!("unsafe path in release: {}", relative.display());
        }
        parts.push(part.into_owned());
    }
    Ok(parts.join("/"))
}

fn is_excluded(path: &str) -> bool {
    path == "manifest.json"
        || path == "manifest.sig"
        || path == ".DS_Store"
        || path == "Thumbs.db"
        || path.ends_with(".map")
        || path.starts_with(".git/")
}

fn validate_version(version: &str) -> Result<()> {
    if version.is_empty()
        || version.len() > 64
        || !version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
        || !version.starts_with(|c: char| c.is_ascii_digit())
    {
        bail!("invalid release version: {version}");
    }
    Ok(())
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

/// Test helper: temporary directory without extra dependencies.
#[cfg(test)]
fn temp_root(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("mng-sign-{tag}-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    fn template(root: &Path) -> PathBuf {
        let web = root.join("web");
        fs::create_dir_all(web.join("assets")).unwrap();
        fs::write(
            web.join("index.html"),
            "<!doctype html><meta name=\"mng-version\" content=\"__MNG_VERSION__\">",
        )
        .unwrap();
        fs::write(
            web.join("sw.js"),
            "const APP_VERSION = '__MNG_VERSION__';\nconst PINNED_UPDATE_KEY = /*__MNG_UPDATE_PUBKEY__*/ null;\n",
        )
        .unwrap();
        fs::write(web.join("assets/app.js"), "console.log('ok');\n").unwrap();
        fs::write(web.join("assets/app.css"), "body { color: #fff; }\n").unwrap();
        fs::write(web.join("manifest.webmanifest"), "{}\n").unwrap();
        web
    }

    #[test]
    fn package_verify_and_detect_tamper() {
        let root = temp_root("package");
        let web = template(&root);
        let out = root.join("out");
        let signing = SigningKey::random(&mut OsRng);

        let manifest = package(&web, &out, "1.2.3", &signing).unwrap();
        assert_eq!(manifest.version, "1.2.3");
        assert!(manifest.assets.iter().any(|a| a.path == "sw.js"));

        let public = signing.verifying_key();
        verify(&out, public).unwrap();

        fs::write(out.join("assets/app.js"), "tampered\n").unwrap();
        assert!(verify(&out, public).is_err());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn extra_file_is_rejected() {
        let root = temp_root("extra");
        let web = template(&root);
        let out = root.join("out");
        let signing = SigningKey::random(&mut OsRng);
        package(&web, &out, "1.0.0", &signing).unwrap();
        fs::write(out.join("assets/evil.js"), "alert(1)\n").unwrap();
        assert!(verify(&out, signing.verifying_key()).is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn invalid_versions_are_rejected() {
        for version in ["", "v1.0.0", "1.0.0;rm -rf /", "1.0.0\n"] {
            assert!(validate_version(version).is_err(), "{version:?}");
        }
    }
}
