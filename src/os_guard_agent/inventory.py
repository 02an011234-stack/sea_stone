"""Deterministic, non-secret Unix inventory snapshots."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from . import MANIFEST_ID, MODULE_VERSION, __version__
from .models import (
    CollectionError,
    CollectionResult,
    CollectionStatus,
    Inventory,
    OsInfo,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical_service(service: Mapping[str, Any]) -> str:
    return json.dumps(
        service,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def deterministic_inventory_version(observation: Mapping[str, Any]) -> str:
    """Apply the Central CC-03 normalization and SHA-256 version contract."""

    normalized = dict(observation)
    normalized["roles"] = sorted(observation.get("roles", []))
    normalized["services"] = sorted(
        observation.get("services", []), key=_canonical_service
    )
    canonical = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def build_inventory(agent_id: str, os_info: OsInfo) -> Inventory:
    """Build one immutable snapshot without inventing role/service vocabulary."""

    os_observation = {
        "family": "UNIX",
        "distribution": os_info.distro,
        "edition": os_info.version,
        "version": os_info.version_id,
        "architecture": os_info.architecture,
    }
    collection = {
        "os": CollectionResult(CollectionStatus.SUCCEEDED),
        "roles": CollectionResult(
            CollectionStatus.FAILED,
            CollectionError(
                "STANDARD_NOT_AGREED",
                "Role collection standard is not agreed",
            ),
        ),
        "services": CollectionResult(
            CollectionStatus.FAILED,
            CollectionError(
                "STANDARD_NOT_AGREED",
                "Service collection standard is not agreed",
            ),
        ),
    }
    observation: dict[str, Any] = {
        "hostname": os_info.hostname,
        "os": os_observation,
        "roles": [],
        "services": [],
        "platform": "linux",
        "agent_version": __version__,
        "module_version": MODULE_VERSION,
        "manifest_id": MANIFEST_ID,
        "collection": {
            name: result.to_dict() for name, result in collection.items()
        },
    }
    return Inventory(
        schema_version="2.0",
        message_id=str(uuid4()),
        sent_at=_utc_now(),
        agent_id=agent_id,
        inventory_version=deterministic_inventory_version(observation),
        hostname=os_info.hostname,
        os=os_observation,
        roles=(),
        services=(),
        platform="linux",
        agent_version=__version__,
        module_version=MODULE_VERSION,
        manifest_id=MANIFEST_ID,
        collection=collection,
    )
