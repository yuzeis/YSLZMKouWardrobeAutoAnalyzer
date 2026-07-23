from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from YKAConfigManager import ConfigSnapshot, load_config_snapshot_or_none
from YKACore import PROJECT_ROOT, SOURCE_ROOT


PROFILE_OVERRIDE_ENV = "YKA_COMPATIBILITY_PROFILE"
DEFAULT_PROFILE_PATH = Path("DatAnDict") / "YKACompatibilityProfiles.json"


class SignedConfigurationUnavailable(ValueError):
    pass


@dataclass(frozen=True)
class CompatibilityProfile:
    profile_id: str
    service_ports: frozenset[int]
    client_authentication_type_ids: frozenset[int]
    server_handshake_type_ids: frozenset[int]
    server_business_wrapper_type_ids: frozenset[int]
    key_exchange_type_ids: frozenset[int]
    business_opcodes: dict[str, frozenset[int]]
    transport: str
    business_schema_id: str
    catalog_bundle_id: str
    parser_version: int

    def is_known_service_port(self, port: int) -> bool:
        return port in self.service_ports


def _integer_set(value: Any, field: str, *, maximum: int) -> frozenset[int]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"compatibility profile {field} must be a non-empty list")
    parsed = frozenset(item for item in value if type(item) is int)
    if len(parsed) != len(value) or any(item <= 0 or item > maximum for item in parsed):
        raise ValueError(f"compatibility profile {field} contains an invalid integer")
    return parsed


def _profile_path() -> Path:
    override = os.environ.get(PROFILE_OVERRIDE_ENV, "").strip()
    if override:
        return Path(override).expanduser().resolve()
    packaged = PROJECT_ROOT / DEFAULT_PROFILE_PATH
    if packaged.is_file():
        return packaged
    return SOURCE_ROOT / DEFAULT_PROFILE_PATH


def _compact_catalog_path() -> Path:
    packaged = PROJECT_ROOT / "DatAnDict" / "YKACompactCatalog.json"
    if packaged.is_file():
        return packaged
    return SOURCE_ROOT / "DatAnDict" / "YKACompactCatalog.json"


def load_compatibility_profile(
    path: Path | None = None,
    *,
    snapshot: ConfigSnapshot | None = None,
) -> CompatibilityProfile:
    override = os.environ.get(PROFILE_OVERRIDE_ENV, "").strip()
    use_snapshot = path is None and not override
    selected_snapshot = (
        snapshot or load_config_snapshot_or_none()
        if use_snapshot
        else None
    )
    if use_snapshot and selected_snapshot is None:
        raise SignedConfigurationUnavailable(
            "no valid signed compatibility configuration is available"
        )
    if selected_snapshot is not None:
        document = selected_snapshot.compatibility_profiles
        compact_catalog = selected_snapshot.compact_catalog
        source_label = (
            f"signed config {selected_snapshot.config_id} "
            f"({selected_snapshot.source})"
        )
    else:
        source = (path or _profile_path()).resolve()
        source_label = str(source)
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(
                f"cannot load compatibility profile {source}: {error}"
            ) from error
        try:
            compact_catalog = json.loads(
                _compact_catalog_path().read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(
                f"cannot load compact catalog for compatibility binding: {error}"
            ) from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError(
            f"unsupported compatibility profile schema from {source_label}"
        )
    active_id = document.get("active_profile_id")
    profiles = document.get("profiles")
    if not isinstance(active_id, str) or not isinstance(profiles, list):
        raise ValueError("compatibility profile registry is incomplete")
    active = next(
        (item for item in profiles if isinstance(item, dict) and item.get("profile_id") == active_id),
        None,
    )
    if active is None:
        raise ValueError("active compatibility profile is missing")
    signature = active.get("protocol_signature")
    if not isinstance(signature, dict):
        raise ValueError("compatibility protocol signature is missing")
    parser_version = active.get("parser_version")
    if (
        parser_version != 1
        or active.get("transport") != "compact-mppc-v1"
        or active.get("business_schema_id") != "yslzm-business-v1"
    ):
        raise ValueError("compatibility profile requires an unsupported parser")
    catalog_bundle_id = active.get("catalog_bundle_id")
    if (
        not isinstance(catalog_bundle_id, str)
        or len(catalog_bundle_id) != 8
        or not catalog_bundle_id.isdigit()
    ):
        raise ValueError("compatibility profile catalog bundle is invalid")
    if not isinstance(compact_catalog, dict) or compact_catalog.get("catalog_id") != catalog_bundle_id:
        raise ValueError("compatibility profile catalog bundle does not match loaded catalog")
    service_ports = _integer_set(active.get("service_ports"), "service_ports", maximum=65535)
    client_authentication_type_ids = _integer_set(
            signature.get("client_authentication_type_ids"),
            "client_authentication_type_ids",
            maximum=0xFFFFFFFF,
        )
    server_handshake_type_ids = _integer_set(
            signature.get("server_handshake_type_ids"),
            "server_handshake_type_ids",
            maximum=0xFFFFFFFF,
        )
    server_business_wrapper_type_ids = _integer_set(
            signature.get("server_business_wrapper_type_ids"),
            "server_business_wrapper_type_ids",
            maximum=0xFFFFFFFF,
        )
    key_exchange_type_ids = _integer_set(
            signature.get("key_exchange_type_ids"),
            "key_exchange_type_ids",
            maximum=0xFFFFFFFF,
        )
    server_control_sets = (
        server_handshake_type_ids,
        server_business_wrapper_type_ids,
        key_exchange_type_ids,
    )
    if any(left & right for index, left in enumerate(server_control_sets) for right in server_control_sets[index + 1 :]):
        raise ValueError("compatibility profile server protocol type ids overlap")
    return CompatibilityProfile(
        profile_id=active_id,
        service_ports=service_ports,
        client_authentication_type_ids=client_authentication_type_ids,
        server_handshake_type_ids=server_handshake_type_ids,
        server_business_wrapper_type_ids=server_business_wrapper_type_ids,
        key_exchange_type_ids=key_exchange_type_ids,
        business_opcodes=_business_opcodes(active.get("business_opcodes")),
        transport=str(active.get("transport")),
        business_schema_id=str(active.get("business_schema_id")),
        catalog_bundle_id=catalog_bundle_id,
        parser_version=parser_version,
    )


_BUSINESS_OPCODE_NAMES = (
    "fashion_info_ack", "fashion_info", "active_fashion", "fashion_expire",
    "fashion_renew", "photo_info", "diy_fashion_data", "fashion_obtain_suit",
    "luckydraw_operate_re", "photo_operate_re",
)


def generic_content_profile() -> CompatibilityProfile:
    return CompatibilityProfile(
        profile_id="generic-content-fallback",
        service_ports=frozenset({9227}),
        client_authentication_type_ids=frozenset({3}),
        server_handshake_type_ids=frozenset({1, 68}),
        server_business_wrapper_type_ids=frozenset({34}),
        key_exchange_type_ids=frozenset({2}),
        business_opcodes={
            name: frozenset() for name in _BUSINESS_OPCODE_NAMES
        },
        transport="compact-mppc-v1",
        business_schema_id="content-only",
        catalog_bundle_id="",
        parser_version=1,
    )


def _business_opcodes(value: Any) -> dict[str, frozenset[int]]:
    if not isinstance(value, dict):
        raise ValueError("compatibility profile business_opcodes is missing")
    parsed: dict[str, frozenset[int]] = {}
    owners: dict[int, str] = {}
    for name in _BUSINESS_OPCODE_NAMES:
        opcodes = _integer_set(value.get(name), f"business_opcodes.{name}", maximum=0xFFFFFFFF)
        for opcode in opcodes:
            if opcode in owners:
                raise ValueError(
                    f"compatibility profile business opcode {opcode} overlaps "
                    f"{owners[opcode]} and {name}"
                )
            owners[opcode] = name
        parsed[name] = opcodes
    return parsed
