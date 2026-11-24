from __future__ import annotations

from harden_policy_service_test_support import PolicyServiceHardenHarness
from harden_service_test_support import posix_path


class SyncedPolicyServiceHardenHarness(PolicyServiceHardenHarness):
    def __init__(
        self,
        module,
        primary_unit,
        secondary_unit,
        fixture_policy,
        check_variable,
        vulnerable_row,
        good_row,
    ):
        super().__init__(module, primary_unit, secondary_unit, fixture_policy)
        self.check_variable = check_variable
        self.vulnerable_row = vulnerable_row
        self.good_row = good_row

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        check_state = fixture["root"] / "check.state"
        active = any(
            "|active|" in row
            for row in fixture["state"].read_text(encoding="utf-8").splitlines()
        )
        check_state.write_text(
            self.vulnerable_row if active else self.good_row,
            encoding="utf-8",
            newline="\n",
        )
        synchronized = {
            self.check_variable: posix_path(check_state),
            "OS_GUARD_TEST_SYNC_CHECK_FILE": posix_path(check_state),
            "OS_GUARD_TEST_SYNC_CHECK_GOOD_ROW": self.good_row.rstrip("\n"),
        }
        if extra:
            synchronized.update(extra)
        return super().environment(
            fixture,
            distro=distro,
            version=version,
            extra=synchronized,
        )
