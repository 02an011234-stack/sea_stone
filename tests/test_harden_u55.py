from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU55Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-55"
    target_path = "/etc/passwd"
    active_unit = "vsftpd.service"
    fixture_result_variable = "OS_GUARD_TEST_U55_FILE"
    sensitive_marker = "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    vulnerable_content = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "ftp:x:14:50:FTP:/srv/ftp:/bin/bash\n"
    )
    good_content = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "ftp:x:14:50:FTP:/srv/ftp:/sbin/nologin\n"
    )
    expected_fragment = "ftp:x:14:50:FTP:/srv/ftp:/sbin/nologin"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_FTP_ACCOUNT_SHELL_CHANGE_APPROVED": "true",
        "OS_GUARD_TEST_LOCAL_IDENTITY_SOURCE_VERIFIED": "true",
        "OS_GUARD_TEST_FTP_SESSIONS_CLEARED": "true",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def pending_fixture_row(self):
        return "complete|1|2|0|0|0|0|1|1\n"

    def test_06_state_drift(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            current = fixture["target"].read_text(encoding="utf-8")
            fixture["target"].write_text(
                current
                + "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
                encoding="utf-8",
                newline="\n",
            )
            environment.update(
                {
                    "OS_GUARD_HARDEN_APPROVED": "true",
                    "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"][
                        "state_fingerprint"
                    ],
                }
            )
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "STATE_DRIFT")
