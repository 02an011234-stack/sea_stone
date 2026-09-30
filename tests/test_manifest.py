from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from os_guard_agent.manifest import ManifestError, UNIX_ITEM_IDS, load_manifest
from os_guard_agent.models import OsInfo


PROJECT_MANIFEST = Path(__file__).parents[1] / "modules" / "manifest.json"


def os_info(distro: str = "rocky", version_id: str = "9.4") -> OsInfo:
    return OsInfo(
        distro=distro,
        version=version_id,
        version_id=version_id,
        kernel="test-kernel",
        hostname="test-host",
        architecture="x86_64",
        supported=True,
    )


class ManifestTests(unittest.TestCase):
    def load_modified(self, mutate):
        payload = json.loads(PROJECT_MANIFEST.read_text(encoding="utf-8"))
        mutate(payload)
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            return load_manifest(manifest_path, "manifest-unix-67-v1", os_info())

    def test_load_valid_full_manifest(self) -> None:
        manifest = load_manifest(
            PROJECT_MANIFEST, "manifest-unix-67-v1", os_info("ubuntu", "24.04")
        )
        self.assertEqual(set(manifest.items), UNIX_ITEM_IDS)
        self.assertEqual(len(manifest.items), 67)

    def test_manifest_id_mismatch(self) -> None:
        with self.assertRaisesRegex(ManifestError, "manifest_id"):
            load_manifest(PROJECT_MANIFEST, "other-manifest", os_info())

    def test_module_version_mismatch(self) -> None:
        with self.assertRaisesRegex(ManifestError, "module_version"):
            self.load_modified(
                lambda payload: payload.update(module_version="unix-unsupported")
            )

    def test_unsupported_os(self) -> None:
        with self.assertRaisesRegex(ManifestError, "does not support OS"):
            load_manifest(PROJECT_MANIFEST, "manifest-unix-67-v1", os_info("debian", "12"))

    def test_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "manifest.json"
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "invalid JSON"):
                load_manifest(path, "manifest-unix-67-v1", os_info())

    def test_missing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "missing.json"
            with self.assertRaisesRegex(ManifestError, "not found"):
                load_manifest(path, "manifest-unix-67-v1", os_info())

    def test_path_traversal_is_rejected(self) -> None:
        with self.assertRaisesRegex(ManifestError, "traversal"):
            self.load_modified(
                lambda payload: payload["items"][0].update(module="../outside.sh")
            )

    def test_absolute_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(ManifestError, "absolute"):
            self.load_modified(
                lambda payload: payload["items"][0].update(module="/tmp/outside.sh")
            )

    def test_path_outside_unix_modules_is_rejected(self) -> None:
        with self.assertRaisesRegex(ManifestError, "outside"):
            self.load_modified(
                lambda payload: payload["items"][0].update(module="other/U-01.sh")
            )

    def test_full_manifest_requires_all_67_items(self) -> None:
        with self.assertRaisesRegex(ManifestError, "U-01 through U-67"):
            self.load_modified(lambda payload: payload["items"].pop())

    def test_all_67_items_are_implemented_for_check(self) -> None:
        manifest = load_manifest(PROJECT_MANIFEST, "manifest-unix-67-v1", os_info())
        self.assertEqual(len(manifest.items), 67)
        self.assertTrue(all(item.implemented for item in manifest.items.values()))
        self.assertTrue(all(tuple(action.value for action in item.actions) == ("CHECK",) for item in manifest.items.values()))


if __name__ == "__main__":
    unittest.main()
