from __future__ import annotations

import json

from os_guard_agent.api_client import ApiClient
from os_guard_agent.inventory import build_inventory, deterministic_inventory_version
from os_guard_agent.models import OperatingCredential, OsInfo

from test_api_client import FakeResponse


def os_info(distro: str = "ubuntu", version: str = "24.04") -> OsInfo:
    return OsInfo(
        distro=distro,
        version=f"{distro} {version}",
        version_id=version,
        kernel="6.8.0-test",
        hostname="unix-test",
        architecture="x86_64",
        supported=True,
    )


def credential() -> OperatingCredential:
    return OperatingCredential("server-1", "agent-1", "cred-1", "secret-token", "expiry")


def test_inventory_has_release_identity_and_explicit_collection_failures() -> None:
    inventory = build_inventory("agent-1", os_info())
    payload = inventory.to_dict()

    assert payload["platform"] == "linux"
    assert payload["agent_version"] == "0.1.0"
    assert payload["module_version"] == "unix-2026.1"
    assert payload["manifest_id"] == "manifest-unix-67-v1"
    assert payload["os"]["family"] == "UNIX"
    assert payload["roles"] == []
    assert payload["services"] == []
    assert payload["collection"]["os"] == {"status": "SUCCEEDED", "error": None}
    assert payload["collection"]["roles"]["status"] == "FAILED"
    assert payload["collection"]["services"]["status"] == "FAILED"


def test_inventory_version_is_order_stable_and_collection_sensitive() -> None:
    first = {
        "hostname": "host",
        "os": {"family": "UNIX"},
        "roles": ["z", "a"],
        "services": [{"name": "z"}, {"name": "a"}],
        "collection": {"services": {"status": "SUCCEEDED", "error": None}},
    }
    reordered = {
        "services": [{"name": "a"}, {"name": "z"}],
        "roles": ["a", "z"],
        "os": {"family": "UNIX"},
        "hostname": "host",
        "collection": {"services": {"error": None, "status": "SUCCEEDED"}},
    }
    failed = dict(reordered)
    failed["collection"] = {
        "services": {
            "status": "FAILED",
            "error": {"code": "DENIED", "message": "Access denied"},
        }
    }

    assert deterministic_inventory_version(first) == deterministic_inventory_version(reordered)
    assert deterministic_inventory_version(first) != deterministic_inventory_version(failed)


def test_inventory_api_sends_exact_version_and_bearer() -> None:
    captured = {}
    inventory = build_inventory("agent-1", os_info("rocky", "10.2"))

    def opener(request, **_kwargs):
        captured["request"] = request
        return FakeResponse(
            {
                "inventory_version": inventory.inventory_version,
                "received_at": "2026-10-13T00:00:00Z",
                "duplicate": False,
            },
            status=200,
        )

    response = ApiClient(
        "https://central.example/agent-api/v2", opener=opener
    ).send_inventory(credential(), inventory)

    payload = json.loads(captured["request"].data)
    assert response.inventory_version == inventory.inventory_version
    assert captured["request"].get_header("Authorization") == "Bearer secret-token"
    assert payload["inventory_version"].startswith("sha256:")
    assert payload["collection"]["services"]["status"] == "FAILED"


def test_supported_os_inventory_fields() -> None:
    for distro, version in (
        ("rocky", "9.5"),
        ("rocky", "10.2"),
        ("ubuntu", "22.04"),
        ("ubuntu", "24.04"),
    ):
        payload = build_inventory("agent-1", os_info(distro, version)).to_dict()
        assert payload["os"]["distribution"] == distro
        assert payload["os"]["version"] == version
