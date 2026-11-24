from pathlib import Path

from harden_content_test_support import ContentHardenTestBase


class TestU06Harden(ContentHardenTestBase):
    __test__ = True
    item_id = "U-06"
    target_path = "/etc/pam.d/su"
    vulnerable_content = "auth required pam_unix.so\n"
    good_content = (
        "auth required pam_wheel.so use_uid group=wheel\n"
        "auth required pam_unix.so\n"
    )
    expected_fragment = "auth required pam_wheel.so use_uid group=wheel\n"

    policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SU_GROUP": "wheel",
        "OS_GUARD_TEST_IDENTITY_SOURCE": "local-files",
        "OS_GUARD_TEST_SU_GROUP_MEMBERSHIP_VERIFIED": "true",
        "OS_GUARD_TEST_ALTERNATIVE_ADMIN_ACCESS_VERIFIED": "true",
        "OS_GUARD_TEST_CONSOLE_RECOVERY_VERIFIED": "true",
    }

    def create_fixture(self, temp_dir: str, *, good=False, content=None):
        fixture = super().create_fixture(temp_dir, good=good, content=content)
        root = fixture["root"]
        (root / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "fixture-admin:x:1000:10::/home/fixture-admin:/bin/sh\n",
            encoding="utf-8",
            newline="\n",
        )
        (root / "etc/group").write_text(
            "root:x:0:\nwheel:x:10:fixture-admin\n",
            encoding="utf-8",
            newline="\n",
        )
        su_binary = root / "usr/bin/su"
        su_binary.parent.mkdir(parents=True, exist_ok=True)
        su_binary.write_text("fixture executable placeholder\n", encoding="utf-8")
        su_binary.chmod(0o755)
        self._write_command(
            fixture["stat"],
            r'''#!/bin/sh
[ "${OS_GUARD_TEST_STAT_FAILURE:-false}" = true ] && exit 1
format=''
for argument in "$@"; do
    case "$argument" in
        %*) format=$argument ;;
    esac
done
IFS='|' read -r device inode uid gid mode mtime ctime context < "$OS_GUARD_TEST_METADATA_STATE"
case "$format" in
    '%G|%a') printf 'root|755\n' ;;
    '%d|%i|%u|%g|%a|%Y|%Z') printf '%s|%s|%s|%s|%s|%s|%s\n' "$device" "$inode" "$uid" "$gid" "$mode" "$mtime" "$ctime" ;;
    '%C')
        [ "${OS_GUARD_TEST_SELINUX_CONTEXT_FAILURE:-false}" != true ] || exit 1
        printf '%s\n' "$context"
        ;;
    '%u|%g|%a') printf '%s|%s|%s\n' "$uid" "$gid" "$mode" ;;
    '%u|%U|%a')
        owner_name=root
        [ "$uid" = 0 ] || owner_name=fixture-user
        printf '%s|%s|%s\n' "$uid" "$owner_name" "$mode"
        ;;
    *) exit 2 ;;
esac
''',
        )
        fixture["su"] = su_binary
        return fixture

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        merged = dict(self.policy)
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
            result, output = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_POLICY_FIXTURE": "false"},
                ),
            )
            self.assertEqual(result["error"]["code"], "POLICY_INTEGRATION_REQUIRED")
            self.assertNotIn("fixture-admin", output)

    def test_21_unapproved_group_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_SU_GROUP": "missing"},
                ),
            )
            self.assertEqual(result["error"]["code"], "APPROVED_SU_GROUP_NOT_ACTIONABLE")

    def test_22_group_without_members_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            (fixture["root"] / "etc/group").write_text(
                "root:x:0:\nwheel:x:10:\n",
                encoding="utf-8",
                newline="\n",
            )
            (fixture["root"] / "etc/passwd").write_text(
                "root:x:0:0:root:/root:/bin/bash\n"
                "fixture-admin:x:1000:1000::/home/fixture-admin:/bin/sh\n",
                encoding="utf-8",
                newline="\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "APPROVED_SU_GROUP_NOT_ACTIONABLE")

    def test_23_external_identity_source_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_IDENTITY_SOURCE": "external-nss"},
                ),
            )
            self.assertEqual(result["error"]["code"], "LOCAL_GROUP_EVIDENCE_REQUIRED")

    def test_23b_nonexistent_listed_group_member_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            (fixture["root"] / "etc/group").write_text(
                "root:x:0:\nwheel:x:10:missing-account\n",
                encoding="utf-8",
                newline="\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "LOCAL_IDENTITY_SOURCE_INVALID")

    def test_24_missing_recovery_evidence_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_CONSOLE_RECOVERY_VERIFIED": "false"},
                ),
            )
            self.assertEqual(result["error"]["code"], "ADMIN_RECOVERY_EVIDENCE_REQUIRED")

    def test_25_complex_pam_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content="auth include system-auth\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "PAM_SU_COMPLEX_CONFIGURATION")

    def test_26_existing_nonstandard_wheel_rule_is_not_rewritten(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content=(
                    "auth sufficient pam_wheel.so trust\n"
                    "auth required pam_unix.so\n"
                ),
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "CHECK_STATE_NOT_ACTIONABLE")

    def test_27_malformed_identity_data_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            (fixture["root"] / "etc/group").write_text(
                "malformed-group-row\n",
                encoding="utf-8",
                newline="\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "LOCAL_IDENTITY_SOURCE_INVALID")

    def test_28_item_validation_failure_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["target"].read_bytes()
            _, result, _ = self.execute(
                fixture,
                extra={"OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE": "true"},
            )
            self.assertEqual(result["error"]["code"], "PAM_SU_VALIDATION_FAILED")
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertTrue(result["execution"]["rollback_success"])
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_29_no_sensitive_identity_is_reported(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, output = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "PLANNED")
            self.assertNotIn("fixture-admin", output)
            self.assertNotIn("/home/fixture-admin", output)

    def test_30_no_real_os_path_is_used(self):
        source = self.module.read_text(encoding="utf-8")
        self.assertIn('${content_test_root}/etc/pam.d/su', source)
        self.assertNotIn("usermod", source)
        self.assertNotIn("groupadd", source)
        self.assertNotIn("sudo", source)

    def test_31_shell_metacharacters_in_group_are_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_SU_GROUP": "wheel;touch-x"},
                ),
            )
            self.assertEqual(result["error"]["code"], "APPROVED_SU_GROUP_INVALID")

    def assert_supported(self, distro, version):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(fixture, distro=distro, version=version),
            )
            self.assertEqual(result["outcome"], "PLANNED")
