from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from check_fixture_test_support import CheckFixtureTestBase


SSHD = shutil.which("sshd") if os.name == "posix" else None
SSH_KEYGEN = shutil.which("ssh-keygen") if os.name == "posix" else None
pytestmark = pytest.mark.skipif(
    not SSHD or not SSH_KEYGEN,
    reason="a POSIX OpenSSH server and ssh-keygen are required",
)


class TestU01OpenSshIntegration(CheckFixtureTestBase):
    __test__ = True
    item_id = "U-01"

    def create_fixture(self, temp_dir: str, permit_root_login: str, *, match=False):
        root = Path(temp_dir)
        command_directory = root / "bin"
        ssh_directory = root / "etc/ssh"
        include_directory = ssh_directory / "sshd_config.d"
        pam_directory = root / "etc/pam.d"
        command_directory.mkdir(parents=True)
        include_directory.mkdir(parents=True)
        pam_directory.mkdir(parents=True)

        host_key = root / "ssh_host_ed25519_key"
        subprocess.run(
            [SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)],
            check=True,
            capture_output=True,
            text=True,
        )
        included_lines = [f"PermitRootLogin {permit_root_login}"]
        if match:
            included_lines.extend(["Match User root", "    PermitRootLogin no"])
        (include_directory / "policy.conf").write_text(
            "\n".join(included_lines) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        configuration = ssh_directory / "sshd_config"
        configuration.write_text(
            f"HostKey {host_key}\n"
            f"PidFile {root / 'sshd.pid'}\n"
            "UsePAM no\n"
            "Include sshd_config.d/*.conf\n",
            encoding="utf-8",
            newline="\n",
        )
        (pam_directory / "login").write_text(
            "auth required pam_securetty.so\n",
            encoding="utf-8",
            newline="\n",
        )
        (root / "etc/securetty").write_text("tty1\n", encoding="utf-8")
        self.write_command(
            command_directory / "systemctl",
            "#!/bin/sh\n"
            "case \"${2:-}\" in\n"
            "  ssh.service|sshd.service|ssh.socket|sshd.socket) printf 'active\\n'; exit 0 ;;\n"
            "  *) printf 'inactive\\n'; exit 3 ;;\n"
            "esac\n",
        )
        self.write_command(command_directory / "pgrep", "#!/bin/sh\nexit 1\n")
        return root, command_directory, configuration

    def run_fixture(self, root: Path, commands: Path, distro="ubuntu", version="24.04"):
        return self.run_check(self.environment(root, commands, distro, version))

    def test_real_sshd_syntax_and_effective_good(self):
        with self.temporary_directory() as temp_dir:
            root, commands, configuration = self.create_fixture(temp_dir, "no")
            syntax = subprocess.run(
                [SSHD, "-t", "-f", str(configuration)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert syntax.returncode == 0, syntax.stderr
            result, _ = self.run_fixture(root, commands)
            assert result["status"] == "GOOD"
            assert result["current_value"]["ssh"]["permit_root_login"] == "no"

    def test_real_sshd_effective_vulnerable(self):
        with self.temporary_directory() as temp_dir:
            root, commands, _ = self.create_fixture(temp_dir, "yes")
            result, _ = self.run_fixture(root, commands)
            assert result["status"] == "VULNERABLE"

    def test_real_sshd_match_remains_pending(self):
        with self.temporary_directory() as temp_dir:
            root, commands, _ = self.create_fixture(temp_dir, "yes", match=True)
            result, _ = self.run_fixture(root, commands)
            assert result["status"] is None
            assert result["review_state"] == "PENDING"
