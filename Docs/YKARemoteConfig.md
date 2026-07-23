# YKA Signed Remote Configuration

## Stable Entry

PC and Android read one public HTTPS object:

`https://gitee.com/yuzeis/yka/raw/main/config/latest.json`

The request runs in the background. Capture and analysis never wait for it.
Redirects are accepted only from `gitee.com` to HTTPS
`raw.giteeusercontent.com`.

## Fallback Order

1. Valid local current configuration.
2. Valid local previous configuration.
3. Configuration bundled with the installed PC or Android release.
4. Built-in content-driven protocol analysis.

Network failure, HTTP errors, rate limits, invalid JSON, unsupported schema,
signature failure, expiry, rollback, or an incomplete write cannot remove any
fallback.

## Bundle Schema

`latest.json` is one signed JSON object containing:

- `schema_version`
- monotonically increasing `config_version`
- `config_id`
- UTC `issued_at` and `expires_at`
- `min_shell_version`
- `target_package`
- `game_version_range`
- canonical SHA-256 values for all four embedded sections
- `compatibility_profiles`
- `compact_catalog`
- `compact_registry`
- `pool_catalog`
- RSA signature metadata

The signature is RSA-3072 PKCS#1 v1.5 with SHA-256 over deterministic JSON
bytes: UTF-8, object keys sorted recursively, no insignificant whitespace, and
`signature` removed from the signed root object. JSON numbers retain their
parsed numeric representation, including a fractional suffix such as `.0`.

## Activation Rules

- Both clients embed the same public key and reject unknown key IDs or
  algorithms.
- All metadata, section hashes, schemas, target package, catalog binding,
  timestamps, and minimum shell version must pass before activation.
- The accepted bundle is written to a temporary file on the same volume,
  flushed, renamed, re-read, and verified before the active pointer changes.
- A lower `config_version` than the highest accepted version is rejected.
- The prior valid version remains available as LKG rollback.
- Remote configuration cannot change memory limits, export completeness gates,
  account binding, canonical JSON verification, or unknown-data semantics.

## Repository Boundary

`config/` contains JSON data only. Signing tools live under `tools/`; the
private key never enters source control, releases, APKs, EXEs, logs, or Gitee.
