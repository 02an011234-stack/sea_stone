from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from os_guard_agent.os_detect import detect_os


class OsDetectTests(unittest.TestCase):
    def detect(self, content: str):
        with tempfile.TemporaryDirectory() as temp_dir:
            os_release = Path(temp_dir) / "os-release"
            os_release.write_text(content, encoding="utf-8")
            with (
                patch("os_guard_agent.os_detect.platform.release", return_value="test-kernel"),
                patch("os_guard_agent.os_detect.platform.machine", return_value="x86_64"),
                patch("os_guard_agent.os_detect.socket.gethostname", return_value="test-host"),
            ):
                return detect_os(os_release)

    def test_rocky_9_is_supported(self) -> None:
        result = self.detect('ID="rocky"\nVERSION="9.4 (Blue Onyx)"\nVERSION_ID="9.4"\n')
        self.assertEqual(result.distro, "rocky")
        self.assertEqual(result.version_id, "9.4")
        self.assertTrue(result.supported)
        self.assertIsNone(result.unsupported_reason)

    def test_rocky_10_is_supported(self) -> None:
        result = self.detect('ID=rocky\nVERSION="10.0"\nVERSION_ID="10.0"\n')
        self.assertTrue(result.supported)

    def test_ubuntu_22_is_supported(self) -> None:
        result = self.detect('ID=ubuntu\nVERSION="22.04.5 LTS"\nVERSION_ID="22.04"\n')
        self.assertTrue(result.supported)

    def test_ubuntu_24_is_supported(self) -> None:
        result = self.detect('ID=ubuntu\nVERSION="24.04.1 LTS"\nVERSION_ID="24.04"\n')
        self.assertTrue(result.supported)

    def test_other_linux_is_unsupported(self) -> None:
        result = self.detect('ID=debian\nVERSION="12"\nVERSION_ID="12"\n')
        self.assertFalse(result.supported)
        self.assertIn("unsupported Linux distribution", result.unsupported_reason or "")

    def test_invalid_os_release_is_unsupported(self) -> None:
        result = self.detect("not-valid-os-release")
        self.assertFalse(result.supported)
        self.assertIn("cannot parse os-release", result.unsupported_reason or "")

    def test_missing_os_release_is_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing-os-release"
            result = detect_os(missing_path)
        self.assertFalse(result.supported)
        self.assertIn("cannot read os-release", result.unsupported_reason or "")


if __name__ == "__main__":
    unittest.main()
