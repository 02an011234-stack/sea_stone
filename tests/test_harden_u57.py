from pathlib import Path

from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU57Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-57"
    target_path = "/etc/ftpusers"
    active_unit = "vsftpd.service"
    fixture_result_variable = "OS_GUARD_TEST_U57_FILE"
    vulnerable_content = "daemon\n"
    good_content = "daemon\nroot\n"
    expected_fragment = "root\n"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_FTP_DAEMON": "vsftpd",
        "OS_GUARD_TEST_APPROVED_BLOCKED_ACCOUNT": "root",
        "OS_GUARD_TEST_VSFTPD_CONFIGURATION_SOURCE": "static-vsftpd-conf",
        "OS_GUARD_TEST_PAM_FTPUSERS_MECHANISM_VERIFIED": "true",
        "OS_GUARD_TEST_FTP_LOGIN_IMPACT_VERIFIED": "true",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def create_fixture(self, temp_dir: str, *, good=False, content=None):
        fixture = super().create_fixture(temp_dir, good=good, content=content)
        root = fixture["root"]
        configuration = root / "etc" / "vsftpd" / "vsftpd.conf"
        configuration.parent.mkdir(parents=True, exist_ok=True)
        configuration.write_text(
            "userlist_enable=YES\nuserlist_deny=NO\n",
            encoding="utf-8",
            newline="\n",
        )
        user_list = root / "etc" / "vsftpd" / "user_list"
        user_list.write_text("root\n", encoding="utf-8", newline="\n")
        pam = root / "etc" / "pam.d" / "vsftpd"
        pam.parent.mkdir(parents=True, exist_ok=True)
        pam.write_text(
            "auth required pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed\n",
            encoding="utf-8",
            newline="\n",
        )
        fixture.update({"configuration": configuration, "pam": pam, "user_list": user_list})
        return fixture

    def pending_fixture_row(self):
        return "complete|1|0|0|1\n"

    def assert_supported(self, distro, version):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            if distro == "ubuntu":
                ubuntu_path = fixture["root"] / "etc" / "vsftpd.conf"
                ubuntu_path.write_bytes(fixture["configuration"].read_bytes())
                fixture["configuration"].unlink()
                fixture["configuration"] = ubuntu_path
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(fixture, distro=distro, version=version),
            )
            self.assertEqual(result["outcome"], "PLANNED")

    def test_21_reload_approval_is_required_for_execute(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            preview, result, _ = self.execute(
                fixture,
                extra={"OS_GUARD_TEST_RELOAD_APPROVED": "false"},
            )
            self.assertFalse(preview["preview"]["service_restart_required"])
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_25_missing_ftpusers_file_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            fixture["target"].unlink()
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "FTPUSERS_TARGET_INVALID")

    def test_26_unverified_pam_mechanism_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            fixture["pam"].write_text(
                "auth required pam_unix.so\n",
                encoding="utf-8",
                newline="\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "PAM_FTPUSERS_DENY_RULE_UNVERIFIED")

    def test_27_unapproved_account_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_BLOCKED_ACCOUNT": "daemon"},
                ),
            )
            self.assertEqual(result["error"]["code"], "FTP_ACCOUNT_POLICY_NOT_APPROVED")

    def test_28_sensitive_values_are_not_reported(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, output = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "PLANNED")
            self.assertNotIn("pam_listfile", output)
            self.assertNotIn("onerr=succeed", output)
