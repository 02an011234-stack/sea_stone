from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU35Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-35"
    target_path = "/etc/vsftpd/vsftpd.conf"
    active_unit = "vsftpd.service"
    fixture_result_variable = "OS_GUARD_TEST_SHARE_FILE"
    vulnerable_content = "anonymous_enable=YES\nlocal_enable=YES\n"
    good_content = "anonymous_enable=NO\nlocal_enable=YES\n"
    expected_fragment = "anonymous_enable=NO"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SHARE_SERVICE": "vsftpd",
        "OS_GUARD_TEST_ANONYMOUS_ACCESS_DISABLE_APPROVED": "true",
        "OS_GUARD_TEST_VSFTPD_CONFIGURATION_SOURCE": "static-vsftpd-conf",
        "OS_GUARD_TEST_SHARE_BUSINESS_IMPACT_VERIFIED": "true",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def pending_fixture_row(self):
        return "complete|5|1|0|0|1|1|0|0\n"

    def assert_supported(self, distro, version):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            if distro == "ubuntu":
                ubuntu_path = fixture["root"] / "etc" / "vsftpd.conf"
                ubuntu_path.write_bytes(fixture["target"].read_bytes())
                fixture["target"].unlink()
                fixture["target"] = ubuntu_path
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(fixture, distro=distro, version=version),
            )
            self.assertEqual(result["outcome"], "PLANNED")

    def test_25_business_exception_without_disable_approval_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_ANONYMOUS_ACCESS_DISABLE_APPROVED": "false"},
                ),
            )
            self.assertEqual(result["error"]["code"], "ANONYMOUS_ACCESS_POLICY_NOT_APPROVED")

    def test_26_duplicate_assignment_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content="anonymous_enable=YES\nanonymous_enable=NO\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(
                result["error"]["code"],
                "VSFTPD_ANONYMOUS_CONFIGURATION_AMBIGUOUS",
            )

    def test_27_include_configuration_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content="include_dir=/etc/vsftpd/conf.d\nanonymous_enable=YES\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "VSFTPD_INCLUDE_NOT_SUPPORTED")

    def test_28_authenticated_user_setting_is_preserved(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            self.execute(fixture)
            content = fixture["target"].read_text(encoding="utf-8")
            self.assertIn("local_enable=YES", content)
