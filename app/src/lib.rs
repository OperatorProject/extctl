// SPDX-License-Identifier: GPL-3.0-or-later

pub mod osrelease;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde::Deserialize;

/// Parsed extension-release manifest from a candidate image.
pub struct Manifest {
    pub name: String,
    pub id: Option<String>,
    pub version_id: Option<String>,
    pub sysext_level: Option<String>,
    pub architecture: Option<String>,
}

/// Search directories for extensions, in systemd's priority order.
const SEARCH_DIRS: &[&str] = &[
    "/etc/extensions",
    "/run/extensions",
    "/var/lib/extensions",
    "/usr/lib/extensions",
];

/// Default signing key/cert location, plus the trust-store entry it lands in.
const KEY_DIR: &str = "/etc/extctl";
const KEY_PATH: &str = "/etc/extctl/sysext.key";
const CERT_PATH: &str = "/etc/extctl/sysext.crt";
const TRUST_CERT: &str = "/etc/verity.d/sysext.crt";

pub fn init(name: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err(format!(
            "invalid extension name '{name}': must be [A-Za-z0-9._-]+"
        ));
    }
    let root = Path::new(name);
    if root.exists() {
        return Err(format!("directory '{name}' already exists"));
    }

    let release = osrelease::OsRelease::read("/usr/lib/os-release")?;
    let manifest_dir = root.join("usr").join("lib").join("extension-release.d");
    fs::create_dir_all(root.join("usr").join("bin"))
        .map_err(|e| format!("creating {}/usr/bin: {e}", root.display()))?;
    fs::create_dir_all(&manifest_dir)
        .map_err(|e| format!("creating {}: {e}", manifest_dir.display()))?;

    let mut manifest = String::new();
    manifest.push_str(&format!("EXTENSION={name}\n"));
    if let Some(id) = &release.id {
        manifest.push_str(&format!("ID={id}\n"));
    }
    if let Some(v) = &release.version_id {
        manifest.push_str(&format!("VERSION_ID={v}\n"));
    }
    if let Some(s) = &release.sysext_level {
        manifest.push_str(&format!("SYSEXT_LEVEL={s}\n"));
    }
    let manifest_path = manifest_dir.join(format!("extension-release.{name}"));
    fs::write(&manifest_path, manifest)
        .map_err(|e| format!("writing {}: {e}", manifest_path.display()))?;

    println!("Created {name}/");
    println!("  usr/bin/                         <- drop your tool here");
    println!("  usr/lib/extension-release.d/extension-release.{name}");
    println!("Manifest populated from host os-release. Package it with:");
    println!("  extctl build {name}");
    Ok(())
}

pub fn build(name: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err(format!(
            "invalid extension name '{name}': must be [A-Za-z0-9._-]+"
        ));
    }
    let root = Path::new(name);
    if !root.is_dir() {
        return Err(format!(
            "no extension tree '{name}' found; run 'extctl init {name}' first"
        ));
    }
    let manifest_dir = root.join("usr").join("lib").join("extension-release.d");
    let manifest = manifest_dir.join(format!("extension-release.{name}"));
    if !manifest.exists() {
        return Err(format!(
            "{} missing; run 'extctl init {name}' to scaffold it",
            manifest.display()
        ));
    }

    let raw = format!("{name}.raw");
    if Path::new(&raw).exists() {
        return Err(format!("{raw} already exists; remove it first"));
    }

    run("mkfs.erofs", &["-L", name, &raw, name], None)?;
    println!("Built {raw}");
    println!("Sign it with:");
    println!("  extctl sign {raw}");
    Ok(())
}

pub fn keygen() -> Result<(), String> {
    if libc_geteuid() != 0 {
        return Err("must be run as root (writes /etc/extctl and /etc/verity.d)".into());
    }
    if Path::new(KEY_PATH).exists() || Path::new(CERT_PATH).exists() {
        return Err(format!(
            "{} already exists; remove it to regenerate (your existing extensions will break)",
            KEY_DIR
        ));
    }
    fs::create_dir_all(KEY_DIR).map_err(|e| format!("creating {KEY_DIR}: {e}"))?;

    run(
        "openssl",
        &[
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            KEY_PATH,
            "-out",
            CERT_PATH,
            "-nodes",
            "-days",
            "3650",
            "-subj",
            "/CN=extctl sysext signing key",
        ],
        None,
    )?;
    // Keep the private key root-only.
    fs::set_permissions(KEY_PATH, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 600 {KEY_PATH}: {e}"))?;

    // Trust the cert: drop it into the verity.d store so verify/install
    // accept extensions signed with this key out of the box.
    fs::create_dir_all("/etc/verity.d").map_err(|e| format!("creating /etc/verity.d: {e}"))?;
    fs::copy(CERT_PATH, TRUST_CERT).map_err(|e| format!("installing {TRUST_CERT}: {e}"))?;

    println!("Generated signing key:");
    println!("  {KEY_PATH}");
    println!("  {CERT_PATH}");
    println!("Trusted for verification:");
    println!("  {TRUST_CERT}");
    println!("Now sign extensions without flags: 'extctl sign <name>.raw'");
    Ok(())
}

pub fn sign(image: &Path, cert: Option<&Path>, key: Option<&Path>) -> Result<(), String> {
    let name = image_name(image)?;
    let verity = sidecar(image, "verity");
    let roothash = sidecar(image, "roothash");
    let sig = sidecar(image, "roothash.p7s");

    match sign_impl(image, cert, key, &verity, &roothash, &sig) {
        Ok(()) => {
            println!("Signed {name}:");
            println!(
                "  {} ({})",
                verity.display(),
                fs::metadata(&verity).map(|m| m.len()).unwrap_or(0)
            );
            println!("  {} (64 bytes)", roothash.display());
            println!("  {}", sig.display());
            println!("Install with: extctl install {}", image.display());
            Ok(())
        }
        Err(e) => {
            // Don't leave truncated/partial sidecars behind: a 0-byte
            // .roothash.p7s would make later verify/install fail confusingly.
            for p in [&verity, &roothash, &sig] {
                let _ = fs::remove_file(p);
            }
            Err(e)
        }
    }
}

fn sign_impl(
    image: &Path,
    cert: Option<&Path>,
    key: Option<&Path>,
    verity: &Path,
    roothash: &Path,
    sig: &Path,
) -> Result<(), String> {
    let cert = match cert {
        Some(c) => c.to_path_buf(),
        None => default_cert()?,
    };
    let key = match key {
        Some(k) => k.to_path_buf(),
        None => default_key()?,
    };

    // 1. Compute verity.
    let out = run_capture(
        "veritysetup",
        &["format", image.to_str().unwrap(), verity.to_str().unwrap()],
        None,
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let root_hash = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("Root hash:"))
        .map(|h| h.trim().to_string())
        .ok_or_else(|| "could not parse Root hash from veritysetup output".to_string())?;
    if root_hash.len() != 64 || !root_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "unexpected root hash '{root_hash}' (want 64 hex chars)"
        ));
    }

    // 2. Write the hex with NO trailing newline, byte-exact.
    let mut f =
        fs::File::create(roothash).map_err(|e| format!("creating {}: {e}", roothash.display()))?;
    f.write_all(root_hash.as_bytes())
        .map_err(|e| format!("writing {}: {e}", roothash.display()))?;
    f.sync_all()
        .map_err(|e| format!("syncing {}: {e}", roothash.display()))?;
    drop(f);
    let size = fs::metadata(roothash).map_err(|e| e.to_string())?.len();
    if size != 64 {
        return Err(format!(
            "roothash file is {size} bytes, want 64 (trailing newline?); aborting"
        ));
    }

    // 3. Detached DER PKCS#7 signature over the exact hex bytes.
    run(
        "openssl",
        &[
            "smime",
            "-sign",
            "-binary",
            "-in",
            roothash.to_str().unwrap(),
            "-signer",
            cert.to_str().unwrap(),
            "-inkey",
            key.to_str().unwrap(),
            "-outform",
            "DER",
            "-noattr",
            "-out",
            sig.to_str().unwrap(),
        ],
        None,
    )?;
    Ok(())
}

pub fn verify(image: &Path) -> Result<(), String> {
    let manifest = read_manifest(image)?;
    let host = osrelease::OsRelease::read("/usr/lib/os-release")?;
    check_metadata(&manifest, &host)?;
    check_signature(image)?;
    println!("OK: {} is a valid extension for this host", manifest.name);
    Ok(())
}

pub fn install(image: &Path, boot: bool, dry_run: bool) -> Result<(), String> {
    let manifest = read_manifest(image)?;
    let host = osrelease::OsRelease::read("/usr/lib/os-release")?;
    check_metadata(&manifest, &host)?;
    check_signature(image)?;

    let target_dir = if boot {
        "/run/extensions"
    } else {
        "/var/lib/extensions"
    };
    let dest = Path::new(target_dir).join(format!("{}.raw", manifest.name));

    if dry_run {
        if dest.exists() {
            return Err(format!(
                "{} already installed; remove it first (extctl remove {})",
                dest.display(),
                manifest.name
            ));
        }
        println!("Would install {}", manifest.name);
        println!("  {} -> {}", image.display(), dest.display());
        for ext in ["verity", "roothash", "roothash.p7s"] {
            if sidecar(image, ext).exists() {
                println!(
                    "  {} -> {}",
                    sidecar(image, ext).display(),
                    Path::new(target_dir)
                        .join(format!("{}.{}", manifest.name, ext))
                        .display()
                );
            }
        }
        println!("  then refresh and confirm merge");
        return Ok(());
    }

    if libc_geteuid() != 0 {
        return Err("must be run as root to install extensions".into());
    }

    fs::create_dir_all(target_dir).map_err(|e| format!("creating {target_dir}: {e}"))?;
    if dest.exists() {
        return Err(format!(
            "{} already installed; remove it first (extctl remove {})",
            dest.display(),
            manifest.name
        ));
    }

    // Atomic copy: write to temp, rename into place.
    let tmp = Path::new(target_dir).join(format!(".{}.raw.tmp", manifest.name));
    fs::copy(image, &tmp).map_err(|e| format!("copying to {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &dest).map_err(|e| format!("renaming to {}: {e}", dest.display()))?;

    // Also copy sidecars if present next to the source.
    for ext in ["verity", "roothash", "roothash.p7s"] {
        let src = sidecar(image, ext);
        if src.exists() {
            let dst = Path::new(target_dir).join(format!("{}.{}", manifest.name, ext));
            fs::copy(&src, &dst).map_err(|e| format!("copying {}: {e}", src.display()))?;
        }
    }

    match refresh() {
        Ok(()) => {}
        Err(e) => {
            // Roll back: remove the image and every sidecar we copied.
            remove_installed(Path::new(target_dir), &manifest.name);
            // A single un-installable sibling image makes systemd-sysext
            // refresh fail for *everyone*, so point at the culprits instead
            // of leaving the user staring at a one-line refresh error.
            let blockers = blocking_candidates();
            if blockers.is_empty() {
                return Err(format!("refresh failed; rolled back install: {e}"));
            }
            let mut msg = format!("refresh failed; rolled back install: {e}");
            msg.push_str("\nblocked by other candidate image(s):");
            for (file, reason) in blockers {
                msg.push_str(&format!("\n  - {file}: {reason}"));
            }
            return Err(msg);
        }
    }

    if merged(&manifest.name)? {
        println!("Installed and merged: {}", manifest.name);
        Ok(())
    } else {
        // Not merged; roll back.
        remove_installed(Path::new(target_dir), &manifest.name);
        Err(format!(
            "{} installed but did not merge; rolled back. Run 'extctl status' for why.",
            manifest.name
        ))
    }
}

/// Delete an installed extension image and all of its sidecars, ignoring
/// errors (used for rollback).
fn remove_installed(target_dir: &Path, name: &str) {
    let _ = fs::remove_file(target_dir.join(format!("{name}.raw")));
    for ext in ["verity", "roothash", "roothash.p7s"] {
        let _ = fs::remove_file(target_dir.join(format!("{name}.{ext}")));
    }
}

pub fn status() -> Result<(), String> {
    let merged = merged_names()?;
    let cands = candidates();
    for c in &cands {
        let mut reasons = Vec::new();
        if let Some(r) = candidate_reason(c) {
            reasons.push(r);
        }
        if !merged.contains(&c.stem) && reasons.is_empty() {
            reasons.push("not merged (see systemd-sysext status)".to_string());
        }

        if reasons.is_empty() {
            println!("{}  merged", c.file);
        } else {
            println!("{}  NOT merged:", c.file);
            for r in reasons {
                println!("    - {r}");
            }
        }
    }
    if cands.is_empty() {
        println!("(no extensions installed)");
    }
    Ok(())
}

/// One installed extension: its directory, filename, and stem name.
struct Candidate {
    dir: PathBuf,
    file: String,
    stem: String,
}

/// Why a candidate cannot be merged, if we can tell: a metadata mismatch or
/// an unreadable release. Returns None if nothing is obviously wrong.
fn candidate_reason(c: &Candidate) -> Option<String> {
    let path = c.dir.join(&c.file);
    match read_manifest(&path) {
        Ok(manifest) => {
            let host = osrelease::OsRelease::read("/usr/lib/os-release").unwrap_or_default();
            metadata_problem(&manifest, &host)
        }
        Err(_) => Some("could not read extension-release".to_string()),
    }
}

/// Candidates that would make `systemd-sysext refresh` fail for everyone:
/// images systemd cannot even read metadata from, or whose release does not
/// match the host. Used to explain a refresh failure.
fn blocking_candidates() -> Vec<(String, String)> {
    candidates()
        .iter()
        .filter_map(|c| candidate_reason(c).map(|r| (c.file.clone(), r)))
        .collect()
}

fn candidates() -> Vec<Candidate> {
    let mut out = Vec::new();
    for dir in SEARCH_DIRS {
        if !Path::new(dir).is_dir() {
            continue;
        }
        let mut names: Vec<String> = fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.path().extension().map(|x| x == "raw").unwrap_or(false))
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        for fname in names {
            out.push(Candidate {
                dir: PathBuf::from(dir),
                stem: fname.trim_end_matches(".raw").to_string(),
                file: fname,
            });
        }
    }
    out
}

/// docker ps-style one-liner: name + source dir + merged state.
pub fn ls() -> Result<(), String> {
    let merged = merged_names()?;
    let mut any = false;
    for c in candidates() {
        any = true;
        let state = if merged.contains(&c.stem) {
            "merged".to_string()
        } else {
            match candidate_reason(&c) {
                Some(why) => format!("not merged ({why})"),
                None => "not merged".to_string(),
            }
        };
        println!("{:<24} {:<22} {}", c.stem, c.dir.display(), state);
    }
    if !any {
        println!("(no extensions installed)");
    }
    Ok(())
}

pub fn remove(name: &str, boot: bool, dry_run: bool) -> Result<(), String> {
    if !valid_name(name) {
        return Err(format!("invalid extension name '{name}'"));
    }
    let target_dir = if boot {
        "/run/extensions"
    } else {
        "/var/lib/extensions"
    };

    let raw = Path::new(target_dir).join(format!("{name}.raw"));
    if !raw.exists() {
        return Err(format!(
            "{} not installed in {} (nothing to remove)",
            name,
            Path::new(target_dir).display()
        ));
    }

    if dry_run {
        println!(
            "Would remove {name} from {}",
            Path::new(target_dir).display()
        );
        for ext in ["", "verity", "roothash", "roothash.p7s"] {
            let suffix = if ext.is_empty() { "raw" } else { ext };
            let f = Path::new(target_dir).join(format!("{name}.{suffix}"));
            if f.exists() {
                println!("  {}", f.display());
            }
        }
        println!("  then refresh and confirm unmerge");
        return Ok(());
    }

    if libc_geteuid() != 0 {
        return Err("must be run as root to remove extensions".into());
    }

    fs::remove_file(&raw).map_err(|e| format!("removing {}: {e}", raw.display()))?;
    for ext in ["verity", "roothash", "roothash.p7s"] {
        let side = Path::new(target_dir).join(format!("{name}.{ext}"));
        if side.exists() {
            fs::remove_file(&side).map_err(|e| format!("removing {}: {e}", side.display()))?;
        }
    }

    refresh()?;
    if merged(name)? {
        return Err(format!(
            "{name} removed but still merged after refresh; run 'extctl status'"
        ));
    }
    println!("Removed: {name}");
    Ok(())
}

pub fn refresh() -> Result<(), String> {
    run("systemd-sysext", &["refresh"], None)
}

pub fn unmerge() -> Result<(), String> {
    run("systemd-sysext", &["unmerge"], None)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn libc_geteuid() -> u32 {
    // SAFETY: geteuid is async-signal-safe and has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn libc_geteuid() -> u32 {
    0
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

fn image_name(image: &Path) -> Result<String, String> {
    let file = image
        .file_name()
        .ok_or_else(|| format!("invalid image path {}", image.display()))?
        .to_string_lossy()
        .to_string();
    let stem = file.trim_end_matches(".raw");
    if stem.is_empty() || stem == file {
        return Err(format!("{}: expected a .raw image file", image.display()));
    }
    Ok(stem.to_string())
}

fn sidecar(image: &Path, ext: &str) -> PathBuf {
    let mut p = image.as_os_str().to_owned();
    p.push(format!(".{ext}"));
    PathBuf::from(p)
}

fn default_cert() -> Result<PathBuf, String> {
    if Path::new(CERT_PATH).exists() {
        Ok(PathBuf::from(CERT_PATH))
    } else {
        Err(format!(
            "no signing cert at {CERT_PATH}; run 'sudo extctl keygen' first (or pass --cert)"
        ))
    }
}

fn default_key() -> Result<PathBuf, String> {
    if Path::new(KEY_PATH).exists() {
        Ok(PathBuf::from(KEY_PATH))
    } else {
        Err(format!(
            "no signing key at {KEY_PATH}; run 'sudo extctl keygen' first (or pass --key)"
        ))
    }
}

fn run(prog: &str, args: &[&str], cwd: Option<&Path>) -> Result<(), String> {
    let out = run_capture(prog, args, cwd)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{prog} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn run_capture(prog: &str, args: &[&str], cwd: Option<&Path>) -> Result<Output, String> {
    let mut cmd = Command::new(prog);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(c) = cwd {
        cmd.current_dir(c);
    }
    cmd.output().map_err(|e| format!("spawning {prog}: {e}"))
}

fn read_manifest(image: &Path) -> Result<Manifest, String> {
    let out = run_capture(
        "systemd-dissect",
        &["--json=short", image.to_str().unwrap()],
        None,
    )?;
    if !out.status.success() {
        return Err(format!(
            "systemd-dissect failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let info: DissectInfo =
        serde_json::from_str(&text).map_err(|e| format!("parsing systemd-dissect output: {e}"))?;
    if !info.use_system_extension {
        return Err(format!(
            "{} is not a system extension (systemd-dissect reports useSystemExtension=false)",
            image.display()
        ));
    }
    let mut id = None;
    let mut version_id = None;
    let mut sysext_level = None;
    let mut architecture = None;
    for line in info.sysext_release {
        if let Some(v) = line.strip_prefix("ID=") {
            id = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version_id = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("SYSEXT_LEVEL=") {
            sysext_level = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("ARCHITECTURE=") {
            architecture = Some(v.to_string());
        }
    }
    // systemd derives the extension name from the image filename (the
    // release file must be `extension-release.<filename-stem>`); the
    // EXTENSION= field is ignored. Match that behavior so install never
    // renames the image away from the name systemd expects.
    let name = image_name(image)?;
    Ok(Manifest {
        name,
        id,
        version_id,
        sysext_level,
        architecture,
    })
}

#[derive(Deserialize)]
struct DissectInfo {
    #[serde(rename = "sysextRelease", default)]
    sysext_release: Vec<String>,
    #[serde(rename = "useSystemExtension")]
    use_system_extension: bool,
}

fn check_metadata(m: &Manifest, host: &osrelease::OsRelease) -> Result<(), String> {
    if let Some(problem) = metadata_problem(m, host) {
        return Err(problem);
    }
    Ok(())
}

/// The host CPU architecture, named the way systemd does (e.g. "x86-64",
/// "arm64"). Returns None for architectures we don't recognize, in which
/// case ARCHITECTURE= validation is skipped rather than falsely rejected.
fn host_architecture() -> Option<String> {
    #[cfg(unix)]
    {
        // SAFETY: uname() has no preconditions and writes into the provided
        // buffer; we zero it first and check the return value.
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut u) } != 0 {
            return None;
        }
        // SAFETY: uname() guarantees machine is a NUL-terminated C string.
        let machine = unsafe { std::ffi::CStr::from_ptr(u.machine.as_ptr()) };
        machine_to_systemd_arch(&machine.to_string_lossy()).map(str::to_string)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Map a `uname -m` machine string to systemd's `architecture_to_string()`
/// value (see systemd's src/basic/architecture.c).
fn machine_to_systemd_arch(machine: &str) -> Option<&'static str> {
    Some(match machine {
        "aarch64" => "arm64",
        "aarch64_be" => "arm64-be",
        "armv8l" | "armv7ml" | "armv7l" | "armv6l" | "armv5tl" | "armv5tel" | "armv5tejl"
        | "armv4tl" | "armv4l" => "arm",
        "armv8b" | "armv7mb" | "armv7b" | "armv6b" | "armv5tejb" | "armv5teb" | "armv5tb"
        | "armv4tb" | "armv4b" => "arm-be",
        "x86_64" => "x86-64",
        "i686" | "i586" | "i486" | "i386" => "x86",
        "alpha" => "alpha",
        "arc" => "arc",
        "arceb" => "arc-be",
        "crisv32" => "cris",
        "ia64" => "ia64",
        "loongarch64" => "loongarch64",
        "m68k" => "m68k",
        "mips64" => "mips64",
        "mips" => "mips",
        "nios2" => "nios2",
        "parisc64" => "parisc64",
        "parisc" => "parisc",
        "ppc64le" => "ppc64-le",
        "ppc64" => "ppc64",
        "ppcle" => "ppc-le",
        "ppc" => "ppc",
        "riscv64" => "riscv64",
        "riscv32" => "riscv32",
        "s390x" => "s390x",
        "s390" => "s390",
        "sh5" => "sh64",
        "sh4a" | "sh4" | "sh3" | "sh2a" | "sh2" => "sh",
        "sparc64" => "sparc64",
        "sparc" => "sparc",
        "tilegx" => "tilegx",
        _ => return None,
    })
}

fn metadata_problem(m: &Manifest, host: &osrelease::OsRelease) -> Option<String> {
    // Mirror systemd's extension_release_validate(): architecture and ID
    // must match, and version matching differs depending on whether
    // SYSEXT_LEVEL is in play.
    if let Some(ext_arch) = m.architecture.as_deref()
        && !ext_arch.is_empty()
        && ext_arch != "_any"
        && let Some(host_arch) = host_architecture()
        && ext_arch != host_arch.as_str()
    {
        return Some(format!(
            "ARCHITECTURE='{ext_arch}' does not match host '{host_arch}'"
        ));
    }

    let id = match m.id.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => {
            return Some(
                "extension-release has no ID= (systemd requires ID= or ID=_any)".to_string(),
            );
        }
    };

    // A host-OS-independent extension matches any host and skips version checks.
    if id == "_any" {
        return None;
    }

    if let Some(host_id) = host.id.as_deref() {
        let id_like_ok = host
            .id_like
            .as_deref()
            .map(|l| l.split_whitespace().any(|t| t == id))
            .unwrap_or(false);
        if id != host_id && !id_like_ok {
            let like = host
                .id_like
                .as_deref()
                .map(|l| format!(" (or ID_LIKE '{l}')"))
                .unwrap_or_default();
            return Some(format!("ID='{id}' does not match host '{host_id}'{like}"));
        }
    }

    let host_has_version = host.version_id.is_some();
    let host_has_level = host.sysext_level.is_some();

    // Rolling releases typically set neither VERSION_ID nor SYSEXT_LEVEL.
    if !host_has_version && !host_has_level {
        return None;
    }

    // If both the host and the extension declare an API level, those must
    // match; otherwise fall back to comparing the OS VERSION_ID.
    if host_has_level && m.sysext_level.is_some() {
        if m.sysext_level != host.sysext_level {
            return Some(format!(
                "SYSEXT_LEVEL='{}' does not match host '{}'",
                m.sysext_level.as_deref().unwrap_or("(unset)"),
                host.sysext_level.as_deref().unwrap_or("(unset)")
            ));
        }
        return None;
    }

    if host_has_version {
        match m.version_id.as_deref() {
            Some(v) if Some(v) == host.version_id.as_deref() => {}
            Some(v) => {
                return Some(format!(
                    "VERSION_ID='{v}' does not match host '{}' (set SYSEXT_LEVEL to bypass)",
                    host.version_id.as_deref().unwrap_or("(unset)")
                ));
            }
            None => {
                return Some(format!(
                    "extension-release has no VERSION_ID= but host requires '{}'",
                    host.version_id.as_deref().unwrap_or("(unset)")
                ));
            }
        }
    }
    None
}

fn check_signature(image: &Path) -> Result<(), String> {
    let name = image_name(image)?;
    let has_sidecars = ["verity", "roothash", "roothash.p7s"]
        .iter()
        .any(|e| sidecar(image, e).exists());
    if !has_sidecars {
        // Unsigned accepted (no authenticity verification). Matches systemd.
        return Ok(());
    }
    // At minimum require all three sidecars present together.
    for ext in ["verity", "roothash", "roothash.p7s"] {
        if !sidecar(image, ext).exists() {
            return Err(format!(
                "{} has signature sidecars but {} is missing",
                name,
                sidecar(image, ext).display()
            ));
        }
    }
    // Verify the PKCS#7 signature against every cert in the trust store.
    let certs = trust_certs();
    if certs.is_empty() {
        return Err(format!(
            "{name}: signed extension but no verity.d trust certs found to verify against"
        ));
    }
    let roothash = sidecar(image, "roothash");
    let sig = sidecar(image, "roothash.p7s");
    let mut ok = false;
    let mut last_err = String::new();
    for cert in &certs {
        let out = run_capture(
            "openssl",
            &[
                "smime",
                "-verify",
                "-inform",
                "DER",
                "-in",
                sig.to_str().unwrap(),
                "-content",
                roothash.to_str().unwrap(),
                "-CAfile",
                cert.to_str().unwrap(),
            ],
            None,
        );
        match out {
            Ok(o) if o.status.success() => {
                ok = true;
                break;
            }
            Ok(o) => last_err = String::from_utf8_lossy(&o.stderr).trim().to_string(),
            Err(e) => last_err = e,
        }
    }
    if ok {
        Ok(())
    } else {
        Err(format!("{name}: signature verification failed: {last_err}"))
    }
}

fn trust_certs() -> Vec<PathBuf> {
    let dirs = [
        "/etc/verity.d",
        "/run/verity.d",
        "/usr/local/lib/verity.d",
        "/usr/lib/verity.d",
    ];
    let mut out = Vec::new();
    for d in dirs {
        if let Ok(rd) = fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "crt").unwrap_or(false) {
                    out.push(p);
                }
            }
        }
    }
    out
}

fn merged_names() -> Result<Vec<String>, String> {
    let out = run_capture("systemd-sysext", &["status", "--no-legend"], None)?;
    if !out.status.success() {
        return Err(format!(
            "systemd-sysext status failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut names = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // Format: <hierarchy> <extensions> <since>; extensions is a
        // comma-separated list or "none".
        let mut it = line.split_whitespace();
        let _hier = it.next();
        let Some(ext) = it.next() else { continue };
        if ext == "none" || ext == "-" {
            continue;
        }
        for name in ext.split(',') {
            names.push(name.to_string());
        }
    }
    Ok(names)
}

fn merged(name: &str) -> Result<bool, String> {
    Ok(merged_names()?.iter().any(|n| n == name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(id: Option<&str>, version: Option<&str>, level: Option<&str>) -> Manifest {
        Manifest {
            name: "ext".to_string(),
            id: id.map(str::to_string),
            version_id: version.map(str::to_string),
            sysext_level: level.map(str::to_string),
            architecture: None,
        }
    }

    fn host(
        id: &str,
        id_like: Option<&str>,
        version: Option<&str>,
        level: Option<&str>,
    ) -> osrelease::OsRelease {
        osrelease::OsRelease {
            id: Some(id.to_string()),
            id_like: id_like.map(str::to_string),
            version_id: version.map(str::to_string),
            sysext_level: level.map(str::to_string),
        }
    }

    #[test]
    fn exact_id_and_version_match() {
        let m = manifest(Some("fedora"), Some("44"), None);
        let h = host("fedora", None, Some("44"), None);
        assert_eq!(metadata_problem(&m, &h), None);
    }

    #[test]
    fn version_mismatch_is_reported() {
        let m = manifest(Some("fedora"), Some("99"), None);
        let h = host("fedora", None, Some("44"), None);
        let p = metadata_problem(&m, &h).unwrap();
        assert!(p.contains("VERSION_ID='99'"), "{p}");
    }

    #[test]
    fn id_like_is_accepted() {
        let m = manifest(Some("rhel"), Some("44"), None);
        let h = host("fedora", Some("rhel centos"), Some("44"), None);
        assert_eq!(metadata_problem(&m, &h), None);
    }

    #[test]
    fn id_any_bypasses_version_checks() {
        let m = manifest(Some("_any"), Some("99"), None);
        let h = host("fedora", None, Some("44"), None);
        assert_eq!(metadata_problem(&m, &h), None);
    }

    #[test]
    fn missing_id_is_rejected() {
        let m = manifest(None, Some("44"), None);
        let h = host("fedora", None, Some("44"), None);
        assert!(metadata_problem(&m, &h).is_some());
    }

    #[test]
    fn sysext_level_mismatch_is_reported() {
        let m = manifest(Some("fedora"), None, Some("999"));
        let h = host("fedora", None, Some("44"), Some("1"));
        let p = metadata_problem(&m, &h).unwrap();
        assert!(p.contains("SYSEXT_LEVEL"), "{p}");
    }

    #[test]
    fn sysext_level_match_is_accepted() {
        let m = manifest(Some("fedora"), Some("99"), Some("1"));
        let h = host("fedora", None, Some("44"), Some("1"));
        assert_eq!(metadata_problem(&m, &h), None);
    }

    #[test]
    fn extension_level_without_host_level_falls_back_to_version() {
        // Host has no SYSEXT_LEVEL, so systemd compares VERSION_ID even when
        // the extension declares SYSEXT_LEVEL.
        let m = manifest(Some("fedora"), Some("99"), Some("1"));
        let h = host("fedora", None, Some("44"), None);
        assert!(metadata_problem(&m, &h).is_some());
    }

    #[test]
    fn rolling_host_accepts_any_version() {
        let m = manifest(Some("fedora"), None, None);
        let h = host("fedora", None, None, None);
        assert_eq!(metadata_problem(&m, &h), None);
    }

    #[test]
    fn dissect_info_tolerates_missing_sysext_release() {
        let json = r#"{"useSystemExtension":false}"#;
        let info: DissectInfo = serde_json::from_str(json).unwrap();
        assert!(!info.use_system_extension);
        assert!(info.sysext_release.is_empty());
    }

    #[test]
    fn image_name_strips_raw_suffix() {
        assert_eq!(image_name(Path::new("/tmp/foo.raw")).unwrap(), "foo");
        assert!(image_name(Path::new("/tmp/foo.txt")).is_err());
        assert!(image_name(Path::new("/tmp/.raw")).is_err());
    }

    #[test]
    fn architecture_any_is_accepted() {
        let mut m = manifest(Some("fedora"), Some("44"), None);
        m.architecture = Some("_any".to_string());
        let h = host("fedora", None, Some("44"), None);
        assert_eq!(metadata_problem(&m, &h), None);
    }

    #[test]
    fn architecture_mismatch_is_reported() {
        // Pick an architecture that can't match our real host: if the host
        // reports x86-64, claim arm64, and vice versa.
        let fake = if host_architecture().as_deref() == Some("arm64") {
            "x86-64"
        } else {
            "arm64"
        };
        let mut m = manifest(Some("fedora"), Some("44"), None);
        m.architecture = Some(fake.to_string());
        let h = host("fedora", None, Some("44"), None);
        let p = metadata_problem(&m, &h).unwrap();
        assert!(p.contains("ARCHITECTURE="), "{p}");
    }

    #[test]
    fn architecture_mapping_matches_systemd_strings() {
        assert_eq!(machine_to_systemd_arch("x86_64"), Some("x86-64"));
        assert_eq!(machine_to_systemd_arch("aarch64"), Some("arm64"));
        assert_eq!(machine_to_systemd_arch("armv7l"), Some("arm"));
        assert_eq!(machine_to_systemd_arch("ppc64le"), Some("ppc64-le"));
        assert_eq!(machine_to_systemd_arch("s390x"), Some("s390x"));
        assert_eq!(machine_to_systemd_arch("made-up"), None);
    }
}
