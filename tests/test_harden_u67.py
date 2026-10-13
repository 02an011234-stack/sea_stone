from harden_multi_test_support import MultiTargetHardenTestBase


class TestU67Harden(MultiTargetHardenTestBase):
    __test__ = True
    item_id = "U-67"
    targets = (
        ("/var/log/messages", "file", "640", "log"),
        ("/var/log/secure", "file", "600", "log"),
    )

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        policy = {
            "OS_GUARD_TEST_POLICY_FIXTURE": "true",
            "OS_GUARD_TEST_APPROVED_LOG_PATHS": "\n".join(
                [target[0] for target in self.targets]
                + [self.targets[0][0] + ".new"]
            ),
            "OS_GUARD_TEST_LOG_WRITER_VERIFIED": "true",
            "OS_GUARD_TEST_LOGROTATE_POLICY_VERIFIED": "true",
            "OS_GUARD_TEST_LOG_WRITE_HEALTHCHECK_APPROVED": "true",
        }
        if extra:
            policy.update(extra)
        return super().environment(
            fixture,
            distro=distro,
            version=version,
            extra=policy,
        )

    def assert_owner_policy_rejected(self, vulnerability):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability=vulnerability)
            before = fixture["state"].read_bytes()
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "LOG_OWNER_POLICY_UNRESOLVED")
            self.assertEqual(fixture["state"].read_bytes(), before)

    def test_02_owner_only(self):
        self.assert_owner_policy_rejected("owner")

    def test_04_owner_and_permission(self):
        self.assert_owner_policy_rejected("both")

    def test_10_chown_failure_rolls_back(self):
        self.assert_owner_policy_rejected("owner")

    def test_29_missing_targets_follow_check_policy(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="good")
            for display, _, _, _ in self.targets:
                (fixture["root"] / display.lstrip("/")).unlink()
            fixture["state"].write_text("", encoding="utf-8")
            environment = self.environment(fixture)
            result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["outcome"], "NO_CHANGE")

    def test_30_policy_fixture_is_required(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="permission")
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_POLICY_FIXTURE": "false"},
                ),
            )
            self.assertEqual(result["error"]["code"], "POLICY_INTEGRATION_REQUIRED")

    def test_31_unapproved_log_path_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="permission")
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_LOG_PATHS": "/var/log/messages"},
                ),
            )
            self.assertEqual(result["error"]["code"], "LOG_PATH_NOT_APPROVED")

    def test_32_log_writer_evidence_is_required(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="permission")
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_LOG_WRITER_VERIFIED": "false"},
                ),
            )
            self.assertEqual(
                result["error"]["code"],
                "LOG_OPERATING_EVIDENCE_REQUIRED",
            )


def test_u67_non_root_service_owner_is_not_changed():
    case = TestU67Harden("test_01_good_state_no_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, vulnerability="owner")
        before = fixture["state"].read_bytes()
        result, _ = case.run_action("PREVIEW", case.environment(fixture))
        assert result["error"]["code"] == "LOG_OWNER_POLICY_UNRESOLVED"
        assert fixture["state"].read_bytes() == before


def test_u67_log_contents_are_preserved():
    case = TestU67Harden("test_24_content_preserved")
    case.setUp()
    case.test_24_content_preserved()
