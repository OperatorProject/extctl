// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Distro-independent wrapper over systemd-sysext for signing and
/// installing system extensions.
#[derive(Parser)]
#[command(name = "extctl", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scaffold a new extension tree with a generated extension-release manifest.
    Init {
        /// Name of the extension (also the image filename base).
        name: String,
    },
    /// Package an extension tree into a .raw image (mkfs.erofs).
    Build {
        /// Name of the extension (matches the tree directory created by init).
        name: String,
    },
    /// Generate a signing key/cert and trust it for verification.
    Keygen,
    /// Produce signed verity sidecars (.verity, .roothash, .roothash.p7s).
    Sign {
        /// Path to the extension image (.raw).
        image: PathBuf,
        /// Signing certificate (.crt). Defaults to the keygen'd one.
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Signing private key. Defaults to the keygen'd one.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Verify a candidate image without installing (metadata + signature gate).
    Verify {
        /// Path to the extension image (.raw).
        image: PathBuf,
    },
    /// Copy a verified image into the extension dir and refresh.
    Install {
        /// Path to the extension image (.raw).
        image: PathBuf,
        /// Install to /run/extensions instead of /var/lib/extensions.
        #[arg(short, long)]
        boot: bool,
        /// Show what would be done without writing anything (no root needed).
        #[arg(long)]
        dry_run: bool,
    },
    /// Compact one-line list of installed extensions and their merge state.
    Ls,
    /// Remove an installed extension (from /var/lib/extensions, or --boot from /run).
    Remove {
        /// Name of the installed extension.
        name: String,
        /// Remove from /run/extensions instead of /var/lib/extensions.
        #[arg(short, long)]
        boot: bool,
        /// Show what would be done without writing anything (no root needed).
        #[arg(long)]
        dry_run: bool,
    },
    /// Show merge status and why each candidate is not active.
    Status,
    /// Alias for `status`.
    Doctor,
    /// Run `systemd-sysext refresh`.
    Refresh,
    /// Run `systemd-sysext unmerge`.
    Unmerge,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init { name } => extctl::init(&name),
        Command::Build { name } => extctl::build(&name),
        Command::Keygen => extctl::keygen(),
        Command::Sign { image, cert, key } => extctl::sign(&image, cert.as_deref(), key.as_deref()),
        Command::Verify { image } => extctl::verify(&image),
        Command::Install {
            image,
            boot,
            dry_run,
        } => extctl::install(&image, boot, dry_run),
        Command::Ls => extctl::ls(),
        Command::Remove {
            name,
            boot,
            dry_run,
        } => extctl::remove(&name, boot, dry_run),
        Command::Status | Command::Doctor => extctl::status(),
        Command::Refresh => extctl::refresh(),
        Command::Unmerge => extctl::unmerge(),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("extctl: {e}");
            ExitCode::FAILURE
        }
    }
}
