# extctl

`extctl` is a **super simple `systemd-sysext` wrapper** for signing and
installing system extensions on a running Linux machine. It wraps the raw
`veritysetup` / `openssl` / `install` / `refresh` incantations into a
single command with a docker-like feel.

`extctl` is a super simple `systemd-sysext` wrapper. It runs on any distro
with `systemd-sysext`, `veritysetup`, `openssl`, and `mkfs.erofs`, and is
not tied to any particular distribution.

## Quick start

The whole lifecycle, exactly as you would type it:

```sh
$ sudo extctl keygen            # one-time setup; like `docker login`
$ extctl init mytool            # scaffold ./mytool/ + manifest
$ $EDITOR mytool/usr/bin/*      # drop your tool in
$ extctl build mytool           # package -> mytool.raw
$ sudo extctl sign mytool.raw   # sign (uses the keygen'd root-only key)
$ sudo extctl install mytool.raw  # verify + copy + merge
$ extctl ls                     # see it installed + merged
$ sudo extctl remove mytool     # tear it back down
```

`keygen`, `install`, `remove`, `refresh`, and `unmerge` need root, as does
`sign` when it uses the default key (which is stored mode `0600` under
`/etc`). Pass `sign --key <readable-key>` to sign unprivileged. `init`,
`build`, `ls`, and `status` run as a normal user; `verify` and
`install --dry-run` write nothing but mounting the image to read its
manifest may still require root.

## Installation

Build and install the binary:

```sh
cargo install --path app --locked
```

Or build an RPM (requires `rpmbuild`):

```sh
./build-rpm        # produces dist/extctl-<version>.rpm
```

## Commands

| Subcommand | What it does                                             |
|------------|----------------------------------------------------------|
| `keygen`   | Generate a signing key/cert and trust it for verification |
| `init <name>` | Scaffold an extension tree with a host-derived manifest |
| `build <name>` | Package `./<name>/` into `<name>.raw` (`mkfs.erofs`)   |
| `sign <raw>` | Produce `.verity` / `.roothash` / `.roothash.p7s` sidecars |
| `verify <raw>` | Check metadata + signature without installing           |
| `install [--boot] [--dry-run] <raw>` | Verify, copy, merge, confirm          |
| `ls`        | One-line list of installed extensions + merge state      |
| `remove [--boot] [--dry-run] <name>` | Tear an extension back down          |
| `status` / `doctor` | Human "why is this not merged" diagnostics          |
| `refresh`   | `systemd-sysext refresh`                                 |
| `unmerge`   | `systemd-sysext unmerge`                                 |

## Building and signing

`init` scaffolds a tree with the `extension-release` manifest auto-filled
from the host's own `os-release` (`ID=`, `VERSION_ID=`, and `SYSEXT_LEVEL=`
if the host sets it). This removes the most common failure mode — a
hand-written manifest with a mismatched `ID`/`VERSION_ID`.

```sh
$ extctl init mytool
Created mytool/
  usr/bin/                         <- drop your tool here
  usr/lib/extension-release.d/extension-release.mytool
Manifest populated from host os-release. Package it with:
  extctl build mytool

$ $EDITOR mytool/usr/bin/mytool      # put your tool inside
$ extctl build mytool                # -> mytool.raw
$ sudo extctl sign mytool.raw        # -> mytool.raw.{verity,roothash,p7s}
```

Each step prints the next command, so the tool walks you through it.

`sign` produces byte-exact sidecars: the `.roothash` is asserted to be
exactly 64 hex chars with no trailing newline, since systemd requires that
for verity. If you keep your key elsewhere, pass `--cert` / `--key`; by
default they resolve to the `keygen`'d pair.

## First-time setup: `keygen`

`extctl keygen` generates an RSA signing key and self-signed certificate
under `/etc/extctl/` (the private key is root-only, mode `0600`), then drops
the certificate into the systemd trust store at `/etc/verity.d/sysext.crt`.

That second step is the important one: because the cert is trusted, every
extension you sign with this key is accepted by `verify` and `install`
without any further ceremony. Run it once; it refuses to overwrite an
existing key (regenerating would invalidate already-installed extensions).

## Installing, listing, removing

```sh
$ sudo extctl install mytool.raw   # verify + copy to /var/lib + merge
Installed and merged: mytool

$ extctl ls                           # docker ps-style
mytool                  /var/lib/extensions    merged

$ sudo extctl remove mytool           # delete raw + sidecars, unmerge
Removed: mytool
```

- `install` re-verifies metadata and signature, copies atomically, runs
  `refresh`, confirms the extension actually merged, and rolls back if it
  did not.
- `remove` deletes the `.raw` and its sidecars, refreshes, and confirms the
  unmerge.
- `--boot` installs/removes under `/run/extensions/` instead of
  `/var/lib/extensions/`. `/run` is tmpfs and reboot-clean, so this is a
  try-before-you-commit scope — handy when you are not sure you want to
  keep something. It still needs root (merging is a privileged op).
- `--dry-run` prints exactly what would happen without writing anything.
  `remove --dry-run` needs no root; `install --dry-run` still does, because
  reading the image's manifest requires mounting it.

## Why is my extension not merged?

`extctl status` (alias `doctor`) inspects every candidate in the search
directories and reports the concrete reason any are inactive:

```
$ extctl status
demo.raw   merged
demo2.raw  NOT merged:
    - VERSION_ID='99' does not match host '44' (set SYSEXT_LEVEL to bypass)
```

Reasons it can report: filename does not match `NAME`, `ID` /
`VERSION_ID` / `SYSEXT_LEVEL` mismatch, an unreadable manifest, or simply
not merged. If the tool's answer is "not merged (see systemd-sysext
status)", check `systemd-sysext status` for the kernel-level reason.

## Trust store

Verification uses the same `verity.d` search path systemd uses: `/etc`,
`/run`, `/usr/local/lib`, `/usr/lib` under `verity.d/`. A certificate is
trusted the moment it is placed in any of those directories. `keygen` puts
yours in `/etc/verity.d/`.

Unsigned extensions are accepted (no authenticity check), matching systemd's
behavior. If sidecars are present, all three must be present together and
the signature must verify against a trusted cert, or the extension is
rejected.

## How it works

`extctl` is an **orchestrator + validator**, not a crypto or filesystem
library. It shells out to the standard tools (`systemd-sysext`,
`veritysetup`, `openssl`, `mkfs.erofs`, `systemd-dissect`) and validates
their output, so its behavior matches the documented manual flow. It never
reimplements the overlay or signing logic.

## Development

```sh
cargo fmt --check
cargo clippy --all-features --locked -- -D warnings
cargo test --locked
```

## License

[GPL-3.0-or-later](./LICENSE) — see the repository for full text.
