"""Loading and validation for the trusted local Unix module manifest."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping

from . import MODULE_VERSION
from .models import Action, OsInfo

SUPPORTED_MANIFEST_SCHEMA = "1.0"
UNIX_ITEM_IDS = frozenset(f"U-{number:02d}" for number in range(1, 68))
_ITEM_ID_PATTERN = re.compile(r"^U-\d{2}$")


class ManifestError(RuntimeError):
    """Raised when the local manifest cannot be trusted."""


@dataclass(frozen=True)
class ManifestItem:
    item_id: str
    module: str
    implemented: bool
    actions: tuple[Action, ...]
    supported_os: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class Manifest:
    schema_version: str
    manifest_id: str
    module_version: str
    platform: str
    supported_os: Mapping[str, tuple[str, ...]]
    items: Mapping[str, ManifestItem]
    modules_dir: Path

    def require_item(self, item_id: str) -> ManifestItem:
        try:
            return self.items[item_id]
        except KeyError:
            raise ManifestError(f"item is not registered in manifest: {item_id}") from None

    def resolve_module(self, item: ManifestItem) -> Path:
        return _safe_module_path(self.modules_dir, item.module)


def load_manifest(path: Path, expected_manifest_id: str, os_info: OsInfo) -> Manifest:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ManifestError(f"manifest file not found: {path}") from None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ManifestError("manifest file is unreadable or invalid JSON") from None
    if not isinstance(payload, Mapping):
        raise ManifestError("manifest root must be a JSON object")

    schema_version = _required_string(payload, "schema_version")
    manifest_id = _required_string(payload, "manifest_id")
    module_version = _required_string(payload, "module_version")
    platform = _required_string(payload, "platform")

    if schema_version != SUPPORTED_MANIFEST_SCHEMA:
        raise ManifestError("unsupported manifest schema_version")
    if manifest_id != expected_manifest_id:
        raise ManifestError("Job manifest_id does not match local manifest")
    if module_version != MODULE_VERSION:
        raise ManifestError("manifest module_version does not match Agent module version")
    if platform != "unix":
        raise ManifestError("manifest platform must be unix")

    supported_os = _parse_supported_os(payload.get("supported_os"), "manifest")
    _validate_os_support(supported_os, os_info, "manifest")

    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise ManifestError("manifest items must be a list")

    modules_dir = path.parent.resolve()
    items: dict[str, ManifestItem] = {}
    for raw_item in raw_items:
        if not isinstance(raw_item, Mapping):
            raise ManifestError("manifest item must be an object")
        item_id = _required_string(raw_item, "item_id")
        if not _ITEM_ID_PATTERN.fullmatch(item_id) or item_id in items:
            raise ManifestError(f"invalid or duplicate manifest item_id: {item_id}")
        module = _required_string(raw_item, "module")
        _safe_module_path(modules_dir, module)
        implemented = raw_item.get("implemented", False)
        if not isinstance(implemented, bool):
            raise ManifestError(f"manifest item implemented flag is invalid: {item_id}")

        raw_actions = raw_item.get("actions")
        if not isinstance(raw_actions, list) or not raw_actions:
            raise ManifestError(f"manifest item actions are invalid: {item_id}")
        try:
            actions = tuple(Action(value) for value in raw_actions)
        except (TypeError, ValueError):
            raise ManifestError(f"manifest item has an invalid action: {item_id}") from None
        if len(set(actions)) != len(actions):
            raise ManifestError(f"manifest item has duplicate actions: {item_id}")

        item_supported_os = _parse_supported_os(
            raw_item.get("supported_os"), f"item {item_id}"
        )
        items[item_id] = ManifestItem(
            item_id=item_id,
            module=module,
            implemented=implemented,
            actions=actions,
            supported_os=item_supported_os,
        )

    if set(items) != UNIX_ITEM_IDS:
        raise ManifestError("FULL Unix manifest must contain exactly U-01 through U-67")

    return Manifest(
        schema_version=schema_version,
        manifest_id=manifest_id,
        module_version=module_version,
        platform=platform,
        supported_os=supported_os,
        items=items,
        modules_dir=modules_dir,
    )


def validate_item_support(item: ManifestItem, os_info: OsInfo, action: Action) -> None:
    if action not in item.actions:
        raise ManifestError(f"action {action.value} is not allowed for {item.item_id}")
    _validate_os_support(item.supported_os, os_info, f"item {item.item_id}")


def _required_string(values: Mapping[str, Any], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"manifest field '{key}' is required")
    return value.strip()


def _parse_supported_os(value: Any, owner: str) -> Mapping[str, tuple[str, ...]]:
    if not isinstance(value, Mapping) or not value:
        raise ManifestError(f"{owner} supported_os is invalid")
    result: dict[str, tuple[str, ...]] = {}
    for distro, versions in value.items():
        if not isinstance(distro, str) or not isinstance(versions, list) or not versions:
            raise ManifestError(f"{owner} supported_os is invalid")
        if any(not isinstance(version, str) or not version for version in versions):
            raise ManifestError(f"{owner} supported_os is invalid")
        result[distro] = tuple(versions)
    return result


def _validate_os_support(
    supported_os: Mapping[str, tuple[str, ...]], os_info: OsInfo, owner: str
) -> None:
    major_version = os_info.version_id.split(".", 1)[0]
    if os_info.distro not in supported_os or major_version not in supported_os[os_info.distro]:
        raise ManifestError(
            f"{owner} does not support OS {os_info.distro} {os_info.version_id}"
        )


def _safe_module_path(modules_dir: Path, module: str) -> Path:
    posix_path = PurePosixPath(module)
    windows_path = PureWindowsPath(module)
    if posix_path.is_absolute() or windows_path.is_absolute():
        raise ManifestError("absolute module paths are not allowed")
    if ".." in posix_path.parts or ".." in windows_path.parts:
        raise ManifestError("module path traversal is not allowed")
    if not posix_path.parts or posix_path.parts[0] != "unix":
        raise ManifestError("module path is outside the allowed unix modules directory")

    allowed_root = (modules_dir / "unix").resolve()
    candidate = (modules_dir / Path(*posix_path.parts)).resolve()
    if not candidate.is_relative_to(allowed_root):
        raise ManifestError("module path is outside the allowed unix modules directory")
    return candidate
