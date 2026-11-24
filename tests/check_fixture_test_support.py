from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from os_guard_agent import MODULE_VERSION


ROOT = Path(__file__).parents[1]


def shell_path() -> str | None:
    discovered = shutil.which("sh")
    if discovered:
        return discovered
    candidate = Path(r"C:\Program Files\Git\bin\sh.exe")
    return str(candidate) if candidate.is_file() else None


class CheckFixtureTestBase(unittest.TestCase):
    __test__ = False
    item_id = ""

    def setUp(self):
        self.shell = shell_path()
        if not self.shell:
            self.skipTest("POSIX shell is unavailable")
        self.module = ROOT / "modules" / "unix" / f"{self.item_id}.sh"

    @staticmethod
    def posix_path(path: Path) -> str:
        value = path.as_posix()
        if os.name == "nt" and len(value) > 2 and value[1] == ":":
            return f"/{value[0].lower()}{value[2:]}"
        return value

    @staticmethod
    def write_command(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=ROOT)

    def environment(self, root: Path, command_dir: Path, distro: str, version: str):
        return {
            "PATH": f"{self.posix_path(command_dir)}:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "OS_GUARD_DISTRO": distro,
            "OS_GUARD_VERSION_ID": version,
            "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
            "OS_GUARD_TEST_ROOT": self.posix_path(root),
        }

    def run_check(self, environment: dict[str, str]):
        completed = subprocess.run(
            [self.shell, str(self.module)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.count("\n"), 1, completed.stdout)
        return json.loads(completed.stdout), completed.stdout + completed.stderr
