from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


SCHEMA_VERSION = 1
MIN_SHELL_VERSION = 1
TARGET_PACKAGE = "com.zulong.yslzm"
SIGNATURE_ALGORITHM = "RSA-3072-PKCS1-v1_5-SHA256"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def section_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest().upper()


def build_bundle(
    *,
    profile_path: Path,
    compact_catalog_path: Path,
    compact_registry_path: Path,
    pool_catalog_path: Path,
    private_key_path: Path,
    config_version: int,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    if config_version <= 0:
        raise ValueError("config_version must be positive")
    if expires_at <= issued_at:
        raise ValueError("expires_at must be after issued_at")

    compatibility_profiles = read_object(profile_path)
    compact_catalog = read_object(compact_catalog_path)
    compact_registry = read_object(compact_registry_path)
    pool_catalog = read_object(pool_catalog_path)

    if compatibility_profiles.get("schema_version") != 1:
        raise ValueError("unsupported compatibility profile schema")
    if compact_catalog.get("schema_version") != 1:
        raise ValueError("unsupported compact catalog schema")
    if compact_registry.get("schema_version") != 1:
        raise ValueError("unsupported compact registry schema")
    if pool_catalog.get("schema_version") != 5:
        raise ValueError("unsupported pool catalog schema")

    active_id = compatibility_profiles.get("active_profile_id")
    profiles = compatibility_profiles.get("profiles")
    active = next(
        (
            item
            for item in profiles
            if isinstance(profiles, list)
            and isinstance(item, dict)
            and item.get("profile_id") == active_id
        ),
        None,
    )
    if active is None:
        raise ValueError("active compatibility profile is missing")
    if active.get("catalog_bundle_id") != compact_catalog.get("catalog_id"):
        raise ValueError("profile and compact catalog are not bound")
    registry_catalogs = compact_registry.get("catalogs")
    compact_catalog_id = compact_catalog.get("catalog_id")
    registry_content_hash = (
        registry_catalogs.get(compact_catalog_id)
        if isinstance(registry_catalogs, dict) and isinstance(compact_catalog_id, str)
        else None
    )
    if registry_content_hash != compact_catalog.get("content_sha256"):
        raise ValueError("compact registry and compact catalog are not bound")
    if TARGET_PACKAGE not in active.get("package_names", []):
        raise ValueError("active profile does not target the expected package")

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "config_version": config_version,
        "config_id": (
            issued_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + f"-v{config_version:08d}"
        ),
        "issued_at": utc_text(issued_at),
        "expires_at": utc_text(expires_at),
        "min_shell_version": MIN_SHELL_VERSION,
        "target_package": TARGET_PACKAGE,
        "game_version_range": {
            "min": 1049,
            "max": 2147483647,
        },
        "content_sha256": {
            "compatibility_profiles": section_hash(compatibility_profiles),
            "compact_catalog": section_hash(compact_catalog),
            "compact_registry": section_hash(compact_registry),
            "pool_catalog": section_hash(pool_catalog),
        },
        "compatibility_profiles": compatibility_profiles,
        "compact_catalog": compact_catalog,
        "compact_registry": compact_registry,
        "pool_catalog": pool_catalog,
    }

    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None,
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("configuration signing key must be RSA")
    numbers = private_key.private_numbers().public_numbers
    if private_key.key_size != 3072 or numbers.e != 65537:
        raise ValueError("configuration signing key must be RSA-3072 with exponent 65537")

    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = "yka-config-rsa3072-" + hashlib.sha256(public_der).hexdigest()[:16]
    signature = private_key.sign(
        canonical_bytes(payload),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    payload["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return payload


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build one signed YKA compatibility configuration bundle."
    )
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--compact-catalog", required=True, type=Path)
    parser.add_argument("--compact-registry", required=True, type=Path)
    parser.add_argument("--pool-catalog", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--config-version", required=True, type=int)
    parser.add_argument("--issued-at")
    parser.add_argument("--expires-at")
    return parser.parse_args()


def parse_timestamp(value: str | None, default: datetime) -> datetime:
    if value is None:
        return default
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def main() -> int:
    args = parse_args()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued_at = parse_timestamp(args.issued_at, now)
    expires_at = parse_timestamp(args.expires_at, issued_at + timedelta(days=365))
    bundle = build_bundle(
        profile_path=args.profile.resolve(),
        compact_catalog_path=args.compact_catalog.resolve(),
        compact_registry_path=args.compact_registry.resolve(),
        pool_catalog_path=args.pool_catalog.resolve(),
        private_key_path=args.private_key.resolve(),
        config_version=args.config_version,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    atomic_write_json(args.output.resolve(), bundle)
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "config_id": bundle["config_id"],
                "config_version": bundle["config_version"],
                "issued_at": bundle["issued_at"],
                "expires_at": bundle["expires_at"],
                "bytes": args.output.resolve().stat().st_size,
                "sha256": hashlib.sha256(args.output.resolve().read_bytes())
                .hexdigest()
                .upper(),
                "key_id": bundle["signature"]["key_id"],
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
