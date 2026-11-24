from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU61Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-61"
    target_path = "/etc/snmp/snmpd.conf"
    active_unit = "snmpd.service"
    fixture_result_variable = "OS_GUARD_TEST_U61_FILE"
    sensitive_marker = "sysLocation PRIVATE_LOCATION"
    vulnerable_content = "rocommunity PRIVATE_COMMUNITY default\n"
    good_content = "rocommunity PRIVATE_COMMUNITY 192.0.2.0/24\n"
    expected_fragment = "rocommunity PRIVATE_COMMUNITY 192.0.2.0/24"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_SNMP_ACCESS_POLICY_APPROVED": "true",
        "OS_GUARD_TEST_SNMP_CONFIGURATION_SOURCE": "static-snmpd-conf",
        "OS_GUARD_TEST_MONITORING_CONNECTIVITY_VERIFIED": "true",
        "OS_GUARD_TEST_APPROVED_MANAGEMENT_NETWORK": "192.0.2.0/24",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def create_fixture(self, temp_dir, *, good=False, content=None):
        fixture = super().create_fixture(temp_dir, good=good, content=content)
        self._write_command(fixture["bin"] / "pgrep", "#!/bin/sh\nexit 1\n")
        return fixture

    def pending_fixture_row(self):
        return "complete|1|1|0|0|1\n"

    def test_unbounded_network_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={
                        "OS_GUARD_TEST_APPROVED_MANAGEMENT_NETWORK": "0.0.0.0/0"
                    },
                ),
            )
            self.assertEqual(result["error"]["code"], "SNMP_NETWORK_SCOPE_INVALID")

    def test_malformed_and_ipv6_networks_are_blocked(self):
        for network in ("999.0.2.0/24", "192.0.2.0/33", "2001:db8::/64"):
            with self.subTest(network=network), self.temporary_directory() as temp_dir:
                fixture = self.create_fixture(temp_dir)
                result, _ = self.run_action(
                    "PREVIEW",
                    self.environment(
                        fixture,
                        extra={
                            "OS_GUARD_TEST_APPROVED_MANAGEMENT_NETWORK": network
                        },
                    ),
                )
                self.assertEqual(
                    result["error"]["code"],
                    "SNMP_NETWORK_SCOPE_INVALID",
                )

    def test_community_value_is_not_reported(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, output = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "PLANNED")
            self.assertNotIn("PRIVATE_COMMUNITY", output)
            self.assertNotIn("PRIVATE_LOCATION", output)

    def test_complex_vacm_is_not_rewritten(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content=(
                    "rocommunity PRIVATE_COMMUNITY default\n"
                    "view systemonly included .1.3.6.1.2.1\n"
                ),
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(
                result["error"]["code"],
                "SNMP_COMPLEX_POLICY_NOT_SUPPORTED",
            )
