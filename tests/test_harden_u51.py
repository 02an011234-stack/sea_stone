from test_harden_u50 import TestU50Harden as _U50HardenBase

_U50HardenBase.__test__ = False


class TestU51Harden(_U50HardenBase):
    __test__ = True
    item_id = "U-51"
    fixture_result_variable = "OS_GUARD_TEST_U51_FILE"
    vulnerable_content = "options { allow-update { any; }; };\n"
    good_content = "options { allow-update { none; }; };\n"
    expected_fragment = "allow-update { none; };"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_DYNAMIC_UPDATE_DISABLE_APPROVED": "true",
        "OS_GUARD_TEST_DDNS_DEPENDENCIES_VERIFIED": "true",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def pending_fixture_row(self):
        return "complete|1|0|0|0|1|1\n"
