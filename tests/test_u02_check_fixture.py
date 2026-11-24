from pathlib import Path

from check_fixture_test_support import CheckFixtureTestBase


class TestU02CheckFixture(CheckFixtureTestBase):
    __test__ = True
    item_id = "U-02"

    def create_fixture(self, temp_dir: str, *, distro="rocky", policy="good", pam_include=False):
        root = Path(temp_dir)
        command_directory = root / "bin"
        pam_directory = root / "etc/pam.d"
        security_directory = root / "etc/security"
        command_directory.mkdir(parents=True)
        pam_directory.mkdir(parents=True)
        security_directory.mkdir(parents=True)

        (root / "etc/login.defs").write_text(
            "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\n",
            encoding="utf-8",
            newline="\n",
        )
        minimum_length = "7" if policy == "vulnerable" else "8"
        malformed_length = "invalid" if policy == "malformed" else minimum_length
        (security_directory / "pwquality.conf").write_text(
            f"minlen = {malformed_length}\n"
            "dcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\n"
            "enforce_for_root\n",
            encoding="utf-8",
            newline="\n",
        )
        (security_directory / "pwhistory.conf").write_text(
            "remember = 4\nenforce_for_root\n",
            encoding="utf-8",
            newline="\n",
        )
        pam_content = (
            "password required pam_pwquality.so\n"
            "password required pam_pwhistory.so\n"
            "password required pam_unix.so\n"
        )
        if pam_include:
            pam_content = "password include custom-password\n" + pam_content
        pam_name = "system-auth" if distro == "rocky" else "common-password"
        (pam_directory / pam_name).write_text(pam_content, encoding="utf-8", newline="\n")
        if distro == "rocky":
            (pam_directory / "password-auth").write_text(pam_content, encoding="utf-8", newline="\n")
        return root, command_directory

    def run_fixture(self, root, commands, distro, version):
        return self.run_check(self.environment(root, commands, distro, version))

    def test_good_policy(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir)
            result, output = self.run_fixture(root, commands, "rocky", "9.6")
            self.assertEqual(result["status"], "GOOD")
            self.assertNotIn(self.posix_path(root), output)

    def test_vulnerable_policy(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir, policy="vulnerable")
            result, _ = self.run_fixture(root, commands, "rocky", "9.6")
            self.assertEqual(result["status"], "VULNERABLE")
            self.assertIn("MIN_LENGTH_BELOW_8", result["evidence"]["criteria_failures"])

    def test_malformed_policy_is_uncheckable(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir, policy="malformed")
            result, _ = self.run_fixture(root, commands, "rocky", "9.6")
            self.assertEqual(result["status"], "UNCHECKABLE")

    def test_pam_include_requires_review(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir, pam_include=True)
            result, _ = self.run_fixture(root, commands, "rocky", "9.6")
            self.assertIsNone(result["status"])
            self.assertEqual(result["review_state"], "PENDING")

    def test_missing_login_defs_is_vulnerable_not_good(self):
        with self.temporary_directory() as temp_dir:
            root, commands = self.create_fixture(temp_dir)
            (root / "etc/login.defs").unlink()
            result, _ = self.run_fixture(root, commands, "rocky", "9.6")
            self.assertEqual(result["status"], "VULNERABLE")

    def test_supported_os_matrix(self):
        for distro, version in (
            ("rocky", "9.6"),
            ("rocky", "10.1"),
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
        ):
            with self.subTest(distro=distro, version=version), self.temporary_directory() as temp_dir:
                root, commands = self.create_fixture(temp_dir, distro=distro)
                result, _ = self.run_fixture(root, commands, distro, version)
                self.assertEqual(result["status"], "GOOD")

    def test_agent_runner_does_not_forward_fixture_environment(self):
        source = (Path(__file__).parents[1] / "src/os_guard_agent/module_runner.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('"OS_GUARD_TEST_ROOT"', source)

    def test_fixture_symlink_guard_is_present(self):
        source = self.module.read_text(encoding="utf-8")
        self.assertIn("FIXTURE_SYMLINK_NOT_ALLOWED", source)
        self.assertIn('[ -L "$fixture_path" ]', source)
