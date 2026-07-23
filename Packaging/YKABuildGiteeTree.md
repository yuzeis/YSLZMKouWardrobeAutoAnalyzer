# Gitee Publication Tree Builder

`YKABuildGiteeTree.py` creates a new, sanitized publication tree. It never
modifies either source project, contacts Gitee, invokes Git, or copies release
binaries into the Git tree.

## Output

The output contains only:

```text
src/pc/
src/android/
config/latest.json
release/index.json
release/SHA256SUMS.txt
```

APK and EXE inputs are hashed for the release metadata. They remain outside the
tree and must be uploaded separately as Gitee Release attachments.

## Usage

Run from the PC project root and choose an output directory outside both source
projects:

```powershell
python Packaging\YKABuildGiteeTree.py `
  --output ..\gitee-publication-staging `
  --release-id Ver1.1 `
  --artifact dist\product-windows-x64.exe `
  --artifact ..\YKAPhone-ver1.0-Preview\dist\product-android.apk `
  --generated-at 2026-07-23T08:00:00Z
```

Add `--strict-release` only for a public release candidate. Strict mode rejects
known license declaration conflicts, undocumented audio or noncommercial icon
assets, Android debug signing, an unsigned Windows executable, missing
third-party notices, incomplete artifact sets, expired configuration, and a
built-in configuration mismatch.

The output path must not exist or must be an empty ordinary directory. The
builder preflights all selected files before replacing that empty directory.

## Safety Boundary

Copying is allowlist-based. Build output, caches, evidence, packet captures,
reports, screenshots, local settings, credentials, signing material, game or
mini-program packages, and vendor test corpora are never selected. Selected
files fail closed when they contain a file over 50 MiB, a likely phone or
account identifier, secret material, a credential-bearing URL, or an absolute
machine-local path.

The configuration private key must stay outside both source trees. This tool
accepts only an already signed public configuration and does not read any
private key.

## Exit Codes

- `0`: the tree was built and validated.
- `2`: input, privacy, integrity, or strict-release validation failed.

Failure output is JSON containing issue codes and relative publication paths.
It never prints matched secret values.
