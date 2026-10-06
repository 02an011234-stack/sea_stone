from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action, OsInfo, ResultStatus, ReviewState
from os_guard_agent.module_runner import ModuleRunner


ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "modules" / "manifest.json"
MODULES = ROOT / "modules" / "unix"

# These fixtures intentionally describe the actual OS-family topology instead of
# assigning four different names to one shared fixture. Rocky 9 and 10 have the
# same paths for these checks; their distinct major versions still exercise the
# manifest and Runner version gates independently.
SUPPORTED_OS_FIXTURES = (
    {
        "name": "rocky9",
        "distro": "rocky",
        "version_id": "9.6",
        "ssh_primary_unit": "sshd.service",
        "ssh_activation_unit": "sshd.socket",
        "telnet_super_server": "/etc/xinetd.d/telnet",
        "password_pam": ("/etc/pam.d/system-auth", "/etc/pam.d/password-auth"),
        "lockout_pam": ("/etc/pam.d/system-auth", "/etc/pam.d/password-auth"),
        "auth_profile_tool": "authselect",
    },
    {
        "name": "rocky10",
        "distro": "rocky",
        "version_id": "10.0",
        "ssh_primary_unit": "sshd.service",
        "ssh_activation_unit": "sshd.socket",
        "telnet_super_server": "/etc/xinetd.d/telnet",
        "password_pam": ("/etc/pam.d/system-auth", "/etc/pam.d/password-auth"),
        "lockout_pam": ("/etc/pam.d/system-auth", "/etc/pam.d/password-auth"),
        "auth_profile_tool": "authselect",
    },
    {
        "name": "ubuntu22",
        "distro": "ubuntu",
        "version_id": "22.04",
        "ssh_primary_unit": "ssh.service",
        "ssh_activation_unit": "ssh.service",
        "telnet_super_server": "/etc/inetd.conf",
        "password_pam": ("/etc/pam.d/common-password",),
        "lockout_pam": ("/etc/pam.d/common-auth", "/etc/pam.d/common-account"),
        "auth_profile_tool": None,
    },
    {
        "name": "ubuntu24",
        "distro": "ubuntu",
        "version_id": "24.04",
        "ssh_primary_unit": "ssh.service",
        "ssh_activation_unit": "ssh.socket",
        "telnet_super_server": "/etc/inetd.conf",
        "password_pam": ("/etc/pam.d/common-password",),
        "lockout_pam": ("/etc/pam.d/common-auth", "/etc/pam.d/common-account"),
        "auth_profile_tool": None,
    },
)

COMMON_ITEM_PATHS = {
    "U-04": ("/etc/passwd", "/etc/shadow"),
    "U-05": ("/etc/passwd",),
    "U-06": ("/usr/bin/su", "/bin/su", "/etc/pam.d/su", "/etc/group", "/etc/passwd"),
    "U-07": ("/etc/passwd", "/etc/shadow", "/etc/login.defs"),
    "U-08": ("/etc/passwd", "/etc/group"),
    "U-09": ("/etc/passwd", "/etc/group", "/etc/nsswitch.conf"),
    "U-10": ("/etc/passwd",),
    "U-11": ("/etc/passwd",),
    "U-12": ("/etc/profile", "/etc/profile.d", "/etc/csh.cshrc", "/etc/csh.login"),
    "U-13": ("/etc/passwd", "/etc/shadow", "/etc/login.defs", "/etc/pam.d/"),
    "U-14": ("/etc/passwd", "/etc/profile", "/etc/profile.d"),
    "U-15": ("-nouser", "-nogroup", "-xdev"),
    "U-16": ("/etc/passwd", "stat", "0644"),
    "U-17": ("/etc/systemd/system", "/etc/init.d", "/etc/rc.d", "stat", "readlink"),
    "U-18": ("/etc/shadow", "stat", "0400"),
    "U-19": ("/etc/hosts", "stat", "0644"),
    "U-20": ("/etc/inetd.conf", "/etc/xinetd.conf", "/etc/xinetd.d", "/etc/systemd", "stat", "0600"),
    "U-21": ("/etc/syslog.conf", "/etc/rsyslog.conf", "/etc/rsyslog.d", "/etc/systemd/journald.conf", "stat", "getent", "0640"),
    "U-22": ("/etc/services", "stat", "getent", "0644"),
    "U-23": ("find", "timeout", "-xdev", "-user root", "-type f", "-perm -04000", "-perm -02000"),
    "U-24": ("/etc/passwd", ".profile", ".bashrc", ".netrc", "stat", "0022"),
    "U-25": ("find", "timeout", "-xdev", "-type f", "-perm -0002"),
    "U-26": ("/dev", "mqueue", "shm", "find", "-xdev"),
    "U-27": ("rsh.socket", "rlogin.socket", "rexec.socket", "/etc/xinetd.d", "/etc/inetd.conf", "/etc/hosts.equiv", ".rhosts", "0600"),
    "U-28": ("nft", "iptables", "firewall-cmd", "ufw", "hosts.allow", "hosts.deny"),
    "U-29": ("/etc/hosts.lpd", "stat", "0600"),
    "U-30": ("/etc/profile", "/etc/login.defs", "/etc/profile.d", "0022"),
    "U-31": ("/etc/passwd", "stat", "getfacl"),
    "U-32": ("/etc/passwd",),
    "U-33": ("find", "timeout", "-xdev", "-name '.*'"),
    "U-34": ("finger.service", "finger.socket", "/etc/inetd.conf", "/etc/xinetd.d/finger"),
    "U-35": ("vsftpd.service", "nfs-server.service", "smb.service", "/etc/exports", "/etc/samba/smb.conf"),
    "U-36": ("rsh.socket", "rlogin.socket", "rexec.socket", "rsync.service", "/etc/inetd.conf"),
    "U-37": ("/usr/bin/crontab", "/usr/bin/at", "/etc/cron.allow", "/etc/at.allow", "/var/spool/cron"),
    "U-38": ("echo.socket", "discard.socket", "daytime.socket", "chargen.socket", "snmpd.service", "named.service"),
    "U-39": ("nfs-server.service", "rpc-statd.service", "nfs-mountd.service"),
    "U-40": ("nfs-server.service", "/etc/exports", "root_squash", "0644"),
    "U-41": ("autofs.service", "automount.service", "pgrep"),
    "U-42": ("rpc.cmsd", "sadmind", "rpc.rquotad", "cachefsd", "/etc/inetd.conf"),
    "U-43": ("ypserv", "ypbind", "ypxfrd", "rpc.yppasswdd", "rpc.ypupdated"),
    "U-44": ("tftp.socket", "talk.socket", "ntalk.socket", "/etc/inetd.conf"),
    "U-45": ("postfix.service", "sendmail.service", "exim4.service", "--cacheonly", "--no-download"),
    "U-46": ("restrictqrun", "postsuper", "exiqgrep"),
    "U-47": ("promiscuous_relay", "reject_unauth_destination", "relay_from_hosts"),
    "U-48": ("noexpn", "novrfy", "goaway", "disable_vrfy_command"),
    "U-49": ("named.service", "bind9.service", "--cacheonly", "--no-download"),
    "U-50": ("/etc/named.conf", "/etc/bind/named.conf", "allow-transfer"),
    "U-51": ("/etc/named.conf", "/etc/bind/named.conf", "allow-update", "update-policy"),
    "U-52": ("telnet.service", "telnet.socket", "/etc/inetd.conf", "/etc/xinetd.d/telnet"),
    "U-53": ("vsftpd.service", "proftpd.service", "ftpd_banner", "ServerIdent"),
    "U-54": ("vsftpd.service", "proftpd.service", "ftp.socket", "force_local_logins_ssl", "TLSRequired"),
    "U-55": ("/etc/passwd", "/bin/false", "/sbin/nologin", "/usr/sbin/nologin"),
    "U-56": ("vsftpd.service", "proftpd.service", "/etc/hosts.allow", "/etc/hosts.deny", "Allow"),
    "U-57": ("/etc/ftpusers", "/etc/ftpd/ftpusers", "userlist_enable", "RootLogin"),
    "U-58": ("snmpd.service", "snmptrapd.service", "pgrep", "/etc/inetd.conf"),
    "U-59": ("snmpd.service", "snmptrapd.service", "/etc/snmp/snmpd.conf", "rocommunity", "rouser"),
    "U-60": ("/etc/snmp/snmpd.conf", "/var/lib/net-snmp/snmpd.conf", "createUser"),
    "U-61": ("/etc/snmp/snmpd.conf", "rocommunity", "com2sec", "rouser"),
    "U-62": ("/etc/issue", "/etc/issue.net", "ftpd_banner", "smtpd_banner", "version"),
    "U-63": ("/etc/sudoers", "stat", "0640"),
    "U-64": ("--cacheonly", "--security", "$a -s upgrade", "/var/log/dnf.log", "/var/log/apt/history.log"),
    "U-65": ("chronyd.service", "ntpd.service", "systemd-timesyncd.service", "chronyc", "ntpq", "timedatectl"),
    "U-66": ("rsyslog.service", "systemd-journald.service", "/etc/rsyslog.conf", "/etc/systemd/journald.conf", "/usr/lib/systemd/journald.conf", "systemd-analyze", "cat-config", "/var/log"),
    "U-67": ("/var/log", "find", "-type f", "%U|%u|%m", "0644"),
}


def os_info(fixture: dict[str, object]) -> OsInfo:
    version_id = str(fixture["version_id"])
    return OsInfo(
        distro=str(fixture["distro"]),
        version=version_id,
        version_id=version_id,
        kernel=f"fixture-{fixture['name']}",
        hostname=f"fixture-{fixture['name']}",
        architecture="x86_64",
        supported=True,
    )


def result_payload(item_id: str, fixture: dict[str, object]) -> str:
    return json.dumps(
        {
            "item_id": item_id,
            "status": "GOOD",
            "review_state": "NOT_REQUIRED",
            "current_value": {"fixture_profile": fixture["name"]},
            "evidence": {
                "item_id": item_id,
                "collection_method": "supported OS compatibility fixture",
                "os": {
                    "distro": fixture["distro"],
                    "version_id": fixture["version_id"],
                },
                "observed_at": "2026-09-28T00:00:00Z",
                "module_version": MODULE_VERSION,
                "decision_reason": "representative supported OS fixture",
            },
            "error": None,
        }
    )


class SupportedOsCompatibilityTests(unittest.TestCase):
    def assert_item_matrix(self, item_id: str) -> None:
        for fixture in SUPPORTED_OS_FIXTURES:
            with self.subTest(item_id=item_id, os=fixture["name"]):
                detected = os_info(fixture)
                manifest = load_manifest(MANIFEST, "manifest-unix-67-v1", detected)
                runner = ModuleRunner(manifest, detected)
                planned = runner.prepare_item(item_id, Action.CHECK)
                completed = subprocess.CompletedProcess(
                    [str(planned.module_path)], 0, result_payload(item_id, fixture), ""
                )
                with (
                    patch("os_guard_agent.module_runner.os.access", return_value=True),
                    patch(
                        "os_guard_agent.module_runner.subprocess.run",
                        return_value=completed,
                    ) as run,
                ):
                    result = runner.execute_check(planned)

                self.assertEqual(planned.module_path.name, f"{item_id}.sh")
                self.assertEqual(result.status, ResultStatus.GOOD)
                self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
                self.assertEqual(result.current_value["fixture_profile"], fixture["name"])
                self.assertEqual(
                    result.evidence["os"],
                    {
                        "distro": fixture["distro"],
                        "version_id": fixture["version_id"],
                    },
                )
                self.assertEqual(result.evidence["kernel"], detected.kernel)
                call = run.call_args
                self.assertEqual(call.args[0], [str(planned.module_path)])
                self.assertFalse(call.kwargs["shell"])
                self.assertEqual(call.kwargs["env"]["OS_GUARD_DISTRO"], fixture["distro"])
                self.assertEqual(
                    call.kwargs["env"]["OS_GUARD_VERSION_ID"], fixture["version_id"]
                )

    def test_u01_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-01")

    def test_u02_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-02")

    def test_u03_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-03")

    def test_u04_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-04")

    def test_u05_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-05")

    def test_u06_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-06")

    def test_u07_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-07")

    def test_u08_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-08")

    def test_u09_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-09")

    def test_u10_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-10")

    def test_u11_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-11")

    def test_u12_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-12")

    def test_u13_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-13")

    def test_u14_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-14")

    def test_u15_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-15")

    def test_u16_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-16")

    def test_u17_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-17")

    def test_u18_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-18")

    def test_u19_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-19")

    def test_u20_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-20")

    def test_u21_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-21")

    def test_u22_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-22")

    def test_u23_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-23")

    def test_u24_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-24")

    def test_u25_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-25")

    def test_u26_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-26")

    def test_u27_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-27")

    def test_u28_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-28")

    def test_u29_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-29")

    def test_u30_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-30")

    def test_u31_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-31")

    def test_u32_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-32")

    def test_u33_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-33")

    def test_u34_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-34")

    def test_u35_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-35")

    def test_u36_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-36")

    def test_u37_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-37")

    def test_u38_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-38")

    def test_u39_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-39")

    def test_u40_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-40")

    def test_u41_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-41")

    def test_u42_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-42")

    def test_u43_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-43")

    def test_u44_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-44")

    def test_u45_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-45")

    def test_u46_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-46")

    def test_u47_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-47")

    def test_u48_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-48")

    def test_u49_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-49")

    def test_u50_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-50")

    def test_u51_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-51")

    def test_u52_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-52")

    def test_u53_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-53")

    def test_u54_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-54")

    def test_u55_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-55")

    def test_u56_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-56")

    def test_u57_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-57")

    def test_u58_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-58")

    def test_u59_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-59")

    def test_u60_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-60")

    def test_u61_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-61")

    def test_u62_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-62")

    def test_u63_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-63")

    def test_u64_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-64")

    def test_u65_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-65")

    def test_u66_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-66")

    def test_u67_supported_os_matrix(self) -> None:
        self.assert_item_matrix("U-67")

    def test_u01_service_and_telnet_topologies_cover_all_supported_os(self) -> None:
        source = (MODULES / "U-01.sh").read_text(encoding="utf-8")
        for fixture in SUPPORTED_OS_FIXTURES:
            with self.subTest(os=fixture["name"]):
                self.assertIn(str(fixture["ssh_primary_unit"]), source)
                self.assertIn(str(fixture["ssh_activation_unit"]), source)
                self.assertIn(str(fixture["telnet_super_server"]), source)
        self.assertIn("command -v sshd", source)
        self.assertIn('"$sshd_bin" -T -C', source)
        self.assertIn("/etc/ssh/sshd_config", source)
        self.assertIn("/etc/pam.d/login", source)
        self.assertIn("/etc/securetty", source)

    def test_u02_password_policy_topologies_cover_all_supported_os(self) -> None:
        source = (MODULES / "U-02.sh").read_text(encoding="utf-8")
        for fixture in SUPPORTED_OS_FIXTURES:
            with self.subTest(os=fixture["name"]):
                for pam_path in fixture["password_pam"]:
                    self.assertIn(str(pam_path), source)
        for path in (
            "/etc/login.defs",
            "/etc/security/pwquality.conf",
            "/etc/security/pwquality.conf.d",
            "/etc/security/pwhistory.conf",
        ):
            self.assertIn(path, source)

    def test_u03_lockout_topologies_cover_all_supported_os(self) -> None:
        source = (MODULES / "U-03.sh").read_text(encoding="utf-8")
        for fixture in SUPPORTED_OS_FIXTURES:
            with self.subTest(os=fixture["name"]):
                for pam_path in fixture["lockout_pam"]:
                    self.assertIn(str(pam_path), source)
                if fixture["auth_profile_tool"]:
                    self.assertIn(str(fixture["auth_profile_tool"]), source)
        self.assertIn("/etc/security/faillock.conf", source)

    def test_u04_through_u67_use_shared_linux_paths_without_false_os_branches(self) -> None:
        for item_id, required_paths in COMMON_ITEM_PATHS.items():
            with self.subTest(item_id=item_id):
                source = (MODULES / f"{item_id}.sh").read_text(encoding="utf-8")
                self.assertIn("OS_GUARD_TEST_ROOT", source)
                for required_path in required_paths:
                    self.assertIn(required_path, source)

    def test_all_67_modules_are_implemented_read_only_and_u68_does_not_exist(self) -> None:
        mutation_commands = (
            "sed -i",
            "systemctl start",
            "systemctl stop",
            "systemctl restart",
            "usermod ",
            "useradd ",
            "userdel ",
            "groupmod ",
            "chmod ",
            "chown ",
        )
        detected = os_info(SUPPORTED_OS_FIXTURES[0])
        manifest = load_manifest(MANIFEST, "manifest-unix-67-v1", detected)
        for number in range(1, 68):
            item_id = f"U-{number:02d}"
            with self.subTest(item_id=item_id):
                self.assertTrue(manifest.require_item(item_id).implemented)
                source = (MODULES / f"{item_id}.sh").read_text(encoding="utf-8")
                for command in mutation_commands:
                    self.assertNotIn(command, source)
        self.assertNotIn("U-68", manifest.items)
        self.assertFalse((MODULES / "U-68.sh").exists())


if __name__ == "__main__":
    unittest.main()
