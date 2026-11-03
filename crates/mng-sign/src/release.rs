use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::package::{self, Manifest};

/// Signed release metadata published separately from the application bundle.
///
/// The extension trusts this document, not the origin that serves the app. It
/// pins the manifest hash and the version so an old but validly signed manifest
/// cannot be replayed as the current release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub schema: u32,
    pub version: String,
    pub sequence: u64,
    pub generated_at: u64,
    pub app_base: String,
    pub manifest_sha256: String,
    pub manifest: String,
    pub manifest_signature: String,
}

pub const SCHEMA: u32 = 1;

/// Create `release.json` and `release.sig` for an already signed package.
pub fn create(
    app: &Path,
    out: &Path,
    version: &str,
    sequence: u64,
    app_base: &str,
    signing: &SigningKey,
) -> Result<Release> {
    if out.exists() {
        bail!("output already exists: {}", out.display());
    }
    if sequence == 0 {
        bail!("release sequence must be greater than zero");
    }
    validate_app_base(app_base)?;
    if !app.is_dir() {
        bail!("signed app directory does not exist: {}", app.display());
    }

    let manifest = package::verify(app, signing.verifying_key())
        .with_context(|| format!("verify {}", app.display()))?;
    if manifest.version != version {
        bail!(
            "package version {} does not match release version {}",
            manifest.version,
            version
        );
    }

    let manifest_bytes = fs::read(app.join("manifest.json")).context("read manifest.json")?;
    let release = Release {
        schema: SCHEMA,
        version: version.to_owned(),
        sequence,
        generated_at: unix_now()?,
        app_base: app_base.to_owned(),
        manifest_sha256: hex::encode(Sha256::digest(&manifest_bytes)),
        manifest: "manifest.json".to_owned(),
        manifest_signature: "manifest.sig".to_owned(),
    };

    fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;
    let bytes = serde_json::to_vec(&release)?;
    fs::write(out.join("release.json"), &bytes).context("write release.json")?;
    let signature: Signature = signing.sign(&bytes);
    fs::write(out.join("release.sig"), hex::encode(signature.to_bytes()))
        .context("write release.sig")?;

    // Keep the signed manifest next to its release metadata so the published
    // directory is self-contained.
    fs::copy(app.join("manifest.json"), out.join("manifest.json"))
        .context("copy manifest.json into release directory")?;
    fs::copy(app.join("manifest.sig"), out.join("manifest.sig"))
        .context("copy manifest.sig into release directory")?;
    Ok(release)
}

/// Verify release metadata and the manifest it points at.
///
/// `app` is optional: when present, every asset in the referenced manifest is
/// also checked against the signed package directory.
pub fn verify(
    dir: &Path,
    public: &VerifyingKey,
    app: Option<&Path>,
) -> Result<(Release, Manifest)> {
    let release_bytes = fs::read(dir.join("release.json")).context("read release.json")?;
    let signature_hex = fs::read_to_string(dir.join("release.sig")).context("read release.sig")?;
    verify_signature(&release_bytes, &signature_hex, public)?;

    let release: Release = serde_json::from_slice(&release_bytes).context("parse release.json")?;
    validate(&release)?;

    let manifest_path = safe_relative(&release.manifest, dir)?;
    let signature_path = safe_relative(&release.manifest_signature, dir)?;
    let manifest_bytes = fs::read(&manifest_path).context("read release manifest")?;
    let digest = hex::encode(Sha256::digest(&manifest_bytes));
    if digest != release.manifest_sha256 {
        bail!("release manifest hash does not match release.json");
    }

    let manifest_signature = fs::read_to_string(&signature_path).context("read manifest.sig")?;
    verify_signature(&manifest_bytes, &manifest_signature, public)?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).context("parse release manifest")?;
    if manifest.version != release.version {
        bail!(
            "manifest version {} does not match release version {}",
            manifest.version,
            release.version
        );
    }

    if let Some(app) = app {
        let checked =
            package::verify(app, public).with_context(|| format!("verify {}", app.display()))?;
        if checked.version != release.version {
            bail!(
                "package version {} does not match release version {}",
                checked.version,
                release.version
            );
        }
        let package_manifest =
            fs::read(app.join("manifest.json")).context("read package manifest.json")?;
        if hex::encode(Sha256::digest(&package_manifest)) != release.manifest_sha256 {
            bail!("package manifest does not match release manifest hash");
        }
    }

    Ok((release, manifest))
}

fn verify_signature(bytes: &[u8], signature_hex: &str, public: &VerifyingKey) -> Result<()> {
    let signature_bytes = hex::decode(signature_hex.trim()).context("signature is not hex")?;
    let signature =
        Signature::from_slice(&signature_bytes).context("invalid ECDSA signature encoding")?;
    public
        .verify(bytes, &signature)
        .context("signature does not match release bytes")
}

fn validate(release: &Release) -> Result<()> {
    if release.schema != SCHEMA {
        bail!("unsupported release schema: {}", release.schema);
    }
    package::validate_version(&release.version)?;
    if release.sequence == 0 {
        bail!("release sequence must be greater than zero");
    }
    validate_app_base(&release.app_base)?;
    if release.manifest_sha256.len() != 64
        || !release
            .manifest_sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        bail!("invalid manifest sha256");
    }
    safe_relative(&release.manifest, Path::new("."))?;
    safe_relative(&release.manifest_signature, Path::new("."))?;
    Ok(())
}

fn validate_app_base(app_base: &str) -> Result<()> {
    if !app_base.starts_with('/') || !app_base.ends_with('/') {
        bail!("app_base must start and end with '/'");
    }
    if app_base.len() > 512
        || app_base.contains("..")
        || app_base.contains('?')
        || app_base.contains('#')
        || app_base.contains('\\')
        || app_base.chars().any(|c| c.is_control() || c == ' ')
    {
        bail!("invalid app_base: {app_base}");
    }
    Ok(())
}

/// Resolve a relative name without allowing `..`, absolute paths or a
/// different directory to escape the release directory.
fn safe_relative(name: &str, root: &Path) -> Result<PathBuf> {
    if name.is_empty()
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains("..")
        || name.contains('\\')
        || name.contains('\0')
    {
        bail!("invalid relative release path: {name}");
    }
    let path = root.join(name);
    if !path.starts_with(root) {
        bail!("release path escapes its directory: {name}");
    }
    Ok(path)
}

fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    fn fixture() -> (PathBuf, PathBuf, SigningKey) {
        let root = std::env::temp_dir().join(format!(
            "mng-release-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let web = root.join("web");
        fs::create_dir_all(&web).unwrap();
        fs::write(
            web.join("index.html"),
            "<meta name=\"mng-version\" content=\"1.2.3\">",
        )
        .unwrap();
        fs::write(
            web.join("sw.js"),
            "const APP_VERSION = '__MNG_VERSION__';\nconst PINNED_UPDATE_KEY = /*__MNG_UPDATE_PUBKEY__*/ null;\n",
        )
        .unwrap();
        fs::write(web.join("manifest.webmanifest"), "{}\n").unwrap();
        fs::create_dir_all(web.join("assets")).unwrap();
        fs::write(web.join("assets/app.js"), "console.log('ok');\n").unwrap();
        let signing = SigningKey::random(&mut OsRng);
        let app = root.join("app");
        package::package(&web, &app, "1.2.3", &signing).unwrap();
        (root, app, signing)
    }

    #[test]
    fn release_metadata_verifies_and_detects_tamper() {
        let (root, app, signing) = fixture();
        let out = root.join("release");
        let release = create(&app, &out, "1.2.3", 7, "/app/", &signing).unwrap();
        assert_eq!(release.sequence, 7);
        let (checked, manifest) = verify(&out, signing.verifying_key(), Some(&app)).unwrap();
        assert_eq!(checked.version, manifest.version);
        assert_eq!(checked.app_base, "/app/");

        fs::write(out.join("release.json"), b"{\"schema\":1}").unwrap();
        assert!(verify(&out, signing.verifying_key(), None).is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn release_rejects_bad_app_base_and_sequence() {
        let (root, app, signing) = fixture();
        assert!(create(&app, &root.join("r1"), "1.2.3", 1, "app/", &signing).is_err());
        assert!(create(&app, &root.join("r2"), "1.2.3", 0, "/app/", &signing).is_err());
        assert!(create(&app, &root.join("r3"), "9.9.9", 1, "/app/", &signing).is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn release_rejects_manifest_hash_mismatch() {
        let (root, app, signing) = fixture();
        let out = root.join("release");
        create(&app, &out, "1.2.3", 1, "/app/", &signing).unwrap();
        let manifest = fs::read(app.join("manifest.json")).unwrap();
        let mut tampered = manifest.clone();
        tampered.push(b' ');
        fs::write(out.join("manifest.json"), tampered).unwrap();
        assert!(verify(&out, signing.verifying_key(), None).is_err());
        fs::remove_dir_all(&root).ok();
    }
}
