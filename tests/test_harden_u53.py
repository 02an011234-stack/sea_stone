from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU53Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-53"
    target_path = "/etc/vsftpd/vsftpd.conf"
    active_unit = "vsftpd.service"
    fixture_result_variable = "OS_GUARD_TEST_U53_FILE"
    vulnerable_content = "ftpd_banner=vsftpd 3.0.5 FTP Server\n"
    good_content = "ftpd_banner=Authorized access only\n"
    expected_fragment = "ftpd_banner=Authorized access only"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_FTP_DAEMON": "vsftpd",
        "OS_GUARD_TEST_VSFTPD_CONFIGURATION_SOURCE": "static-vsftpd-conf",
        "OS_GUARD_TEST_APPROVED_VSFTPD_VERSION": "3.0.5",
        "OS_GUARD_TEST_APPROVED_BANNER": "Authorized access only",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def pending_fixture_row(self):
        return "complete|1|0|0|0|1|vsftpd\n"

    def assert_supported(self, distro, version):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            if distro == "ubuntu":
                ubuntu_target = fixture["root"] / "etc" / "vsftpd.conf"
                ubuntu_target.write_bytes(fixture["target"].read_bytes())
                fixture["target"].unlink()
                fixture["target"] = ubuntu_target
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(fixture, distro=distro, version=version),
            )
            self.assertEqual(result["outcome"], "PLANNED")

    def test_25_unsupported_daemon_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_FTP_DAEMON": "proftpd"},
                ),
            )
            self.assertEqual(result["error"]["code"], "FTP_DAEMON_NOT_SUPPORTED")

    def test_26_duplicate_banner_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content="ftpd_banner=vsftpd 3.0\nftpd_banner=FTP Server 2.0\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "VSFTPD_BANNER_CONFIGURATION_AMBIGUOUS")

    def test_27_include_configuration_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content="include_dir=/etc/vsftpd/conf.d\nftpd_banner=vsftpd 3.0\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "VSFTPD_INCLUDE_NOT_SUPPORTED")

    def test_28_unverified_vsftpd_version_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_VSFTPD_VERSION": "unknown"},
                ),
            )
            self.assertEqual(result["error"]["code"], "VSFTPD_VERSION_UNVERIFIED")

    def test_29_distribution_specific_configuration_path_is_required(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            rocky_path = fixture["target"]
            ubuntu_path = fixture["root"] / "etc" / "vsftpd.conf"
            ubuntu_path.write_text(
                rocky_path.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(
                result["error"]["code"],
                "VSFTPD_CONFIGURATION_AMBIGUOUS",
            )
