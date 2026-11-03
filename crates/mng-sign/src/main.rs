#![forbid(unsafe_code)]

//! Offline release signer.
//!
//! Run `keygen` once on a machine that is not the server, keep the private
//! JSON offline, and use `package` for every release. CI only ever sees the
//! public key, which is pinned into the service worker at package time.

mod keyfile;
mod package;
mod release;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "mng-sign",
    version,
    about = "Offline release signer for MNG Cloud"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a P-256 signing key. Refuses to overwrite an existing key.
    Keygen {
        /// Private key output (keep offline, never commit).
        #[arg(long)]
        out: PathBuf,
        /// Public JWK output to pin into the service worker.
        #[arg(long)]
        pub_out: Option<PathBuf>,
    },
    /// Copy a web template, stamp version/public key, and sign the manifest.
    Package {
        #[arg(long)]
        web: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        key: PathBuf,
    },
    /// Verify a signed release directory.
    Verify {
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        dir: PathBuf,
    },
    /// Sign release metadata that pins the current manifest and sequence.
    ///
    /// Publish `release.json`, `release.sig`, `manifest.json` and `manifest.sig`
    /// to GitHub Pages. The browser extension reads them from there, not from
    /// the cloud origin.
    Release {
        #[arg(long)]
        app: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long, default_value = "/app/")]
        app_base: String,
        #[arg(long)]
        key: PathBuf,
    },
    /// Verify release metadata, its manifest signature and (optionally) assets.
    VerifyRelease {
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        /// Signed app directory to check against the release manifest.
        #[arg(long)]
        app: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { out, pub_out } => {
            let public = keyfile::generate(&out)?;
            if let Some(path) = pub_out {
                keyfile::write_public(&path, &public)?;
                println!("public key: {}", path.display());
            }
            println!("private key: {} (keep offline)", out.display());
            println!("public JWK: {}", serde_json::to_string(&public)?);
        }
        Command::Package {
            web,
            out,
            version,
            key,
        } => {
            let signing = keyfile::load_signing(&key)?;
            let manifest = package::package(&web, &out, &version, &signing)?;
            println!(
                "signed {} v{}: {} assets, manifest {}/manifest.json",
                out.display(),
                manifest.version,
                manifest.assets.len(),
                out.display()
            );
        }
        Command::Verify { public_key, dir } => {
            let public = keyfile::load_public(&public_key)?;
            let manifest = package::verify(&dir, &public)
                .with_context(|| format!("verify {}", dir.display()))?;
            println!(
                "verified {} v{}: {} assets",
                dir.display(),
                manifest.version,
                manifest.assets.len()
            );
        }
        Command::Release {
            app,
            out,
            version,
            sequence,
            app_base,
            key,
        } => {
            let signing = keyfile::load_signing(&key)?;
            let release = release::create(&app, &out, &version, sequence, &app_base, &signing)?;
            println!(
                "signed release v{} sequence {} from {}: {}/release.json",
                release.version,
                release.sequence,
                app.display(),
                out.display()
            );
        }
        Command::VerifyRelease {
            public_key,
            dir,
            app,
        } => {
            let public = keyfile::load_public(&public_key)?;
            let (release, manifest) = release::verify(&dir, &public, app.as_deref())
                .with_context(|| format!("verify release {}", dir.display()))?;
            println!(
                "verified release v{} sequence {}: {} assets, app_base {}",
                release.version,
                release.sequence,
                manifest.assets.len(),
                release.app_base
            );
        }
    }
    Ok(())
}
