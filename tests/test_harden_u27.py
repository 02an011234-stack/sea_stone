from pathlib import Path

from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU27Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-27"
    target_path = "/root/.rhosts"
    active_unit = "rsh.socket"
    fixture_result_variable = "OS_GUARD_TEST_SCAN_FILE"
    vulnerable_content = "+ +\ntrusted-host trusted-user\n"
    good_content = "trusted-host trusted-user\n"
    expected_fragment = "trusted-host trusted-user"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_TRUST_FILES": "/root/.rhosts",
        "OS_GUARD_TEST_RCOMMAND_TRUST_REMEDIATION_APPROVED": "true",
        "OS_GUARD_TEST_TRUST_RELATIONSHIP_IMPACT_VERIFIED": "true",
        "OS_GUARD_TEST_LOCAL_PASSWD_SOURCE_VERIFIED": "true",
    }

    def create_fixture(self, temp_dir: str, *, good=False, content=None):
        fixture = super().create_fixture(temp_dir, good=good, content=content)
        (fixture["root"] / "run" / "systemd" / "system").mkdir(parents=True)
        fixture["metadata"].write_text(
            "100|200|0|0|600|300|400|system_u:object_r:etc_t:s0\n",
            encoding="utf-8",
            newline="\n",
        )
        self._write_command(
            fixture["systemctl"],
            '''#!/bin/sh
if [ "${1:-}" != "is-active" ]; then
    exit 2
fi
for argument in "$@"; do
    if [ "$argument" = "rsh.socket" ]; then
        printf 'active\n'
        exit 0
    fi
done
printf 'inactive\n'
exit 3
''',
        )
        scan_state = fixture["root"] / "u27-check.state"
        scan_state.write_text(
            (
                "complete|1|1|1|0|0|0|0\n"
                if good
                else "complete|1|1|1|0|0|1|0\n"
            ),
            encoding="utf-8",
            newline="\n",
        )
        fixture["scan_state"] = scan_state
        return fixture

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        synchronized = {
            "OS_GUARD_TEST_SCAN_FILE": self._posix(fixture["scan_state"]),
            "OS_GUARD_TEST_SYNC_CHECK_FILE": self._posix(fixture["scan_state"]),
        }
        if extra:
            synchronized.update(extra)
        return super().environment(
            fixture,
            distro=distro,
            version=version,
            extra=synchronized,
        )

    def pending_fixture_row(self):
        return "complete|1|1|0|0|0|0|1\n"

    def test_21_reload_approval_is_required_for_execute(self):
        # Trust-file updates do not reload or restart the r-command service.
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, result, _ = self.execute(
                fixture, extra={"OS_GUARD_TEST_RELOAD_APPROVED": "false"}
            )
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_25_unapproved_trust_file_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_TRUST_FILES": "/etc/hosts.equiv"},
                ),
            )
            self.assertEqual(result["error"]["code"], "TRUST_FILE_SCOPE_NOT_APPROVED")

    def test_26_unsafe_permission_is_not_silently_repaired(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            fixture["metadata"].write_text(
                "100|200|0|0|644|300|400|system_u:object_r:etc_t:s0\n",
                encoding="utf-8",
                newline="\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "TRUST_FILE_PERMISSION_UNSAFE")

    def test_27_explicit_trust_relationship_is_preserved(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            self.execute(fixture)
            content = fixture["target"].read_text(encoding="utf-8")
            self.assertIn("trusted-host trusted-user", content)
            self.assertNotIn("+ +", content)

    def test_28_symlink_home_trust_file_is_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_FORCE_SYMLINK_PATH": "/root/.rhosts"},
                ),
            )
            self.assertEqual(result["error"]["code"], "SYMLINK_TARGET_REJECTED")

    def test_29_hosts_equiv_and_account_file_are_both_planned(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            hosts_equiv = fixture["root"] / "etc" / "hosts.equiv"
            hosts_equiv.write_text("+ trusted-user\n", encoding="utf-8", newline="\n")
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={
                        "OS_GUARD_TEST_APPROVED_TRUST_FILES": (
                            "/etc/hosts.equiv\n/root/.rhosts"
                        )
                    },
                ),
            )
            self.assertEqual(result["outcome"], "PLANNED")
            self.assertEqual(len(result["preview"]["targets"]), 2)


def test_u27_has_no_service_stop_or_account_mutation_commands():
    root = Path(__file__).parents[1]
    source = (root / "modules" / "unix" / "harden" / "U-27.sh").read_text(
        encoding="utf-8"
    )
    for forbidden in ("systemctl stop", "systemctl restart", "usermod", "chown "):
        assert forbidden not in source
