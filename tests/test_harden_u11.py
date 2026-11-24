from harden_content_test_support import ContentHardenTestBase


class TestU11Harden(ContentHardenTestBase):
    __test__ = True
    item_id = "U-11"
    target_path = "/etc/passwd"
    vulnerable_content = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/bin/bash\n"
    )
    good_content = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/sbin/nologin\n"
    )
    expected_fragment = "daemon:x:1:1:daemon:/usr/sbin:/sbin/nologin"
    sensitive_marker = "regularuser:x:1000:1000:User:/home/regularuser:/bin/bash"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SHELL_ACCOUNTS": "daemon",
        "OS_GUARD_TEST_APPROVED_RESTRICTED_SHELL": "/sbin/nologin",
        "OS_GUARD_TEST_LOCAL_ACCOUNT_SOURCE_VERIFIED": "true",
        "OS_GUARD_TEST_ACCOUNT_DEPENDENCY_VERIFIED": "true",
        "OS_GUARD_TEST_ACCOUNT_SESSION_STATE_VERIFIED": "true",
    }

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        merged = dict(self.fixture_policy)
        if extra:
            merged.update(extra)
        return super().environment(
            fixture,
            distro=distro,
            version=version,
            extra=merged,
        )

    def test_20_policy_fixture_is_required(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_POLICY_FIXTURE": "false"},
                ),
            )
            self.assertEqual(result["error"]["code"], "POLICY_INTEGRATION_REQUIRED")

    def test_21_root_account_cannot_be_approved(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_SHELL_ACCOUNTS": "root"},
                ),
            )
            self.assertEqual(result["error"]["code"], "ACCOUNT_POLICY_INVALID")

    def test_22_unapproved_vulnerable_account_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content=self.vulnerable_content + "games:x:5:60:games:/usr/games:/bin/bash\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(
                result["error"]["code"],
                "UNAPPROVED_VULNERABLE_ACCOUNT_PRESENT",
            )

    def test_23_session_or_dependency_evidence_is_required(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            for field_name in (
                "OS_GUARD_TEST_ACCOUNT_DEPENDENCY_VERIFIED",
                "OS_GUARD_TEST_ACCOUNT_SESSION_STATE_VERIFIED",
            ):
                result, _ = self.run_action(
                    "PREVIEW",
                    self.environment(fixture, extra={field_name: "false"}),
                )
                self.assertEqual(
                    result["error"]["code"],
                    "ACCOUNT_SAFETY_EVIDENCE_REQUIRED",
                )

    def test_24_external_or_missing_account_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_SHELL_ACCOUNTS": "games"},
                ),
            )
            self.assertEqual(
                result["error"]["code"],
                "UNAPPROVED_VULNERABLE_ACCOUNT_PRESENT",
            )

    def test_25_duplicate_uid_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content=(
                    self.vulnerable_content
                    + "games:x:1:60:games:/usr/games:/sbin/nologin\n"
                ),
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "LOCAL_PASSWD_STATE_INVALID")

    def test_26_root_and_regular_user_records_are_preserved(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["target"].read_text(encoding="utf-8")
            root_before = next(line for line in before.splitlines() if line.startswith("root:"))
            user_before = next(
                line for line in before.splitlines() if line.startswith("regularuser:")
            )
            self.execute(fixture)
            after = fixture["target"].read_text(encoding="utf-8")
            self.assertIn(root_before, after)
            self.assertIn(user_before, after)

    def test_27_sensitive_passwd_fields_are_not_reported(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, output = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "PLANNED")
            self.assertNotIn("regularuser", output)
            self.assertNotIn("root:x:0:0", output)

    def test_06_state_drift(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            changed = fixture["target"].read_text(encoding="utf-8").replace(
                "daemon:x:1:1:daemon:/usr/sbin:/bin/bash",
                "daemon:x:1:1:daemon:/usr/sbin:/bin/sh",
            )
            fixture["target"].write_text(changed, encoding="utf-8", newline="\n")
            environment.update(
                {
                    "OS_GUARD_HARDEN_APPROVED": "true",
                    "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                }
            )
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "STATE_DRIFT")
