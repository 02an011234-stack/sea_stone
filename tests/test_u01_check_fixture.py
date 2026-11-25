from pathlib import Path

from check_fixture_test_support import CheckFixtureTestBase


class TestU01CheckFixture(CheckFixtureTestBase):
    __test__ = True
    item_id = "U-01"

    def create_fixture(
        self,
        temp_dir: str,
        *,
        permit_root_login: str | None = "no",
        include: bool = False,
        absolute_include: bool = False,
        match: bool = False,
    ):
        root = Path(temp_dir)
        ssh_directory = root / "etc/ssh"
        pam_directory = root / "etc/pam.d"
        command_directory = root / "bin"
        ssh_directory.mkdir(parents=True)
        pam_directory.mkdir(parents=True)
        command_directory.mkdir()

        configuration_lines = []
        if include:
            include_directory = ssh_directory / "sshd_config.d"
            include_directory.mkdir()
            (include_directory / "policy.conf").write_text(
                f"PermitRootLogin {permit_root_login}\n",
                encoding="utf-8",
                newline="\n",
            )
            include_pattern = "sshd_config.d/*.conf"
            if absolute_include:
                include_pattern = f"{self.posix_path(include_directory)}/*.conf"
            configuration_lines.append(f"Include {include_pattern}")
        elif permit_root_login is not None:
            configuration_lines.append(f"PermitRootLogin {permit_root_login}")
        if match:
            configuration_lines.extend(["Match User root", "    PermitRootLogin no"])
        (ssh_directory / "sshd_config").write_text(
            "\n".join(configuration_lines) + "\n",
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
            r'''#!/bin/sh
unit=${2:-}
case "$unit" in
    ssh.service|sshd.service|ssh.socket|sshd.socket)
        [ "${OS_GUARD_FIXTURE_SSH_ACTIVE:-true}" = true ] && printf 'active\n' && exit 0
        printf 'inactive\n'
        exit 3
        ;;
    telnet.service|telnet.socket|telnetd.service|in.telnetd.service)
        [ "${OS_GUARD_FIXTURE_TELNET_ACTIVE:-false}" = true ] && printf 'active\n' && exit 0
        printf 'inactive\n'
        exit 3
        ;;
    *) printf 'inactive\n'; exit 3 ;;
esac
''',
        )
        self.write_command(command_directory / "pgrep", "#!/bin/sh\nexit 1\n")
        self.write_command(command_directory / "hostname", "#!/bin/sh\nprintf 'fixture-host\\n'\n")
        self.write_command(
            command_directory / "sshd",
            r'''#!/bin/sh
configuration=''
while [ "$#" -gt 0 ]; do
    if [ "$1" = -f ]; then
        shift
        configuration=${1:-}
    fi
    shift
done
[ -n "$configuration" ] && [ -r "$configuration" ] || exit 1
value=$(awk '
    /^[[:space:]]*#/ { next }
    tolower($1) == "permitrootlogin" { print tolower($2); exit }
' "$configuration")
if [ -z "$value" ]; then
    include_pattern=$(awk '
        /^[[:space:]]*#/ { next }
        tolower($1) == "include" { print $2; exit }
    ' "$configuration")
    if [ -n "$include_pattern" ]; then
        case "$include_pattern" in
            /*) resolved_pattern=$include_pattern ;;
            *) resolved_pattern="${configuration%/*}/$include_pattern" ;;
        esac
        for included_file in $resolved_pattern; do
            [ -r "$included_file" ] || continue
            value=$(awk '
                /^[[:space:]]*#/ { next }
                tolower($1) == "permitrootlogin" { print tolower($2); exit }
            ' "$included_file")
            [ -z "$value" ] || break
        done
    fi
fi
[ -n "$value" ] || value=prohibit-password
printf 'permitrootlogin %s\n' "$value"
''',
        )
        return root, command_directory

    def run_fixture(self, root, command_directory, *, distro="rocky", version="9.6", extra=None):
        environment = self.environment(root, command_directory, distro, version)
        environment.update(
            {
                "OS_GUARD_FIXTURE_SSH_ACTIVE": "true",
                "OS_GUARD_FIXTURE_TELNET_ACTIVE": "false",
            }
        )
        if extra:
            environment.update(extra)
        return self.run_check(environment)

    def test_good_effective_configuration(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir)
            result, _ = self.run_fixture(root, commands)
            self.assertEqual(result["status"], "GOOD")
            self.assertEqual(result["current_value"]["ssh"]["permit_root_login"], "no")

    def test_vulnerable_effective_configuration(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir, permit_root_login="yes")
            result, _ = self.run_fixture(root, commands)
            self.assertEqual(result["status"], "VULNERABLE")

    def test_include_effective_configuration(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir, include=True)
            result, output = self.run_fixture(root, commands)
            self.assertEqual(result["status"], "GOOD")
            self.assertTrue(result["evidence"]["include_present"])
            self.assertNotIn(self.posix_path(root), output)

    def test_absolute_include_inside_fixture_is_allowed(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(
                temp_dir,
                include=True,
                absolute_include=True,
            )
            result, output = self.run_fixture(root, commands)
            self.assertEqual(result["status"], "GOOD")
            self.assertEqual(result["current_value"]["ssh"]["permit_root_login"], "no")
            self.assertNotIn(self.posix_path(root), output)

    def test_match_requires_review(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir, match=True)
            result, _ = self.run_fixture(root, commands)
            self.assertIsNone(result["status"])
            self.assertEqual(result["review_state"], "PENDING")

    def test_effective_configuration_failure_is_uncheckable(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir)
            (commands / "sshd").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            result, _ = self.run_fixture(root, commands)
            self.assertEqual(result["status"], "UNCHECKABLE")

    def test_telnet_without_restriction_is_vulnerable(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir)
            (root / "etc/pam.d/login").write_text("auth required pam_unix.so\n", encoding="utf-8")
            result, _ = self.run_fixture(
                root,
                commands,
                extra={
                    "OS_GUARD_FIXTURE_SSH_ACTIVE": "false",
                    "OS_GUARD_FIXTURE_TELNET_ACTIVE": "true",
                },
            )
            self.assertEqual(result["status"], "VULNERABLE")

    def test_supported_os_matrix(self):
        for distro, version in (
            ("rocky", "9.6"),
            ("rocky", "10.1"),
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
        ):
            with self.subTest(distro=distro, version=version), self.temporary_directory() as temp_dir:
                root, commands = self.create_fixture(temp_dir)
                result, _ = self.run_fixture(root, commands, distro=distro, version=version)
                self.assertEqual(result["status"], "GOOD")

    def test_agent_runner_does_not_forward_fixture_environment(self):
        source = (Path(__file__).parents[1] / "src/os_guard_agent/module_runner.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('"OS_GUARD_TEST_ROOT"', source)

    def test_include_path_traversal_is_uncheckable(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir, permit_root_login=None)
            (root / "etc/ssh/sshd_config").write_text(
                "Include ../../outside.conf\n",
                encoding="utf-8",
                newline="\n",
            )
            result, _ = self.run_fixture(root, commands)
            self.assertEqual(result["status"], "UNCHECKABLE")

    def test_absolute_include_outside_fixture_is_uncheckable(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir, permit_root_login=None)
            (root / "etc/ssh/sshd_config").write_text(
                "Include /etc/ssh/sshd_config.d/*.conf\n",
                encoding="utf-8",
                newline="\n",
            )
            result, _ = self.run_fixture(root, commands)
            self.assertEqual(result["status"], "UNCHECKABLE")

    def test_symlink_include_is_uncheckable(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir, include=True)
            include_directory = root / "etc/ssh/sshd_config.d"
            policy = include_directory / "policy.conf"
            target = include_directory / "policy-target.conf"
            policy.replace(target)
            try:
                policy.symlink_to(target.name)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            result, _ = self.run_fixture(root, commands)
            self.assertEqual(result["status"], "UNCHECKABLE")

    def test_symlink_include_directory_outside_fixture_is_uncheckable(self):
        with (
            self.temporary_directory() as temp_dir,
            self.temporary_directory() as outside_dir,
        ):
            root, commands = self.create_fixture(temp_dir, include=True)
            include_directory = root / "etc/ssh/sshd_config.d"
            (include_directory / "policy.conf").unlink()
            include_directory.rmdir()
            outside_policy_directory = Path(outside_dir) / "policy"
            outside_policy_directory.mkdir()
            (outside_policy_directory / "policy.conf").write_text(
                "PermitRootLogin no\n",
                encoding="utf-8",
                newline="\n",
            )
            try:
                include_directory.symlink_to(
                    outside_policy_directory,
                    target_is_directory=True,
                )
            except OSError:
                self.skipTest("directory symlink creation is unavailable")
            result, _ = self.run_fixture(root, commands)
            self.assertEqual(result["status"], "UNCHECKABLE")
