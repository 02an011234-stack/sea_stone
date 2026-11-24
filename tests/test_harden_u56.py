from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU56Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-56"
    target_path = "/etc/proftpd/proftpd.conf"
    active_unit = "proftpd.service"
    fixture_result_variable = "OS_GUARD_TEST_U56_FILE"
    vulnerable_content = "ServerName fixture\nDefaultRoot ~\n"
    good_content = (
        "ServerName fixture\n"
        "<Limit LOGIN>\n"
        "  Allow from 10.20.0.0/16\n"
        "  DenyAll\n"
        "</Limit>\n"
    )
    expected_fragment = "Allow from 10.20.0.0/16"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_FTP_DAEMON": "proftpd",
        "OS_GUARD_TEST_PROFTPD_CONFIGURATION_SOURCE": "static-proftpd-conf",
        "OS_GUARD_TEST_FTP_ACCESS_POLICY_APPROVED": "true",
        "OS_GUARD_TEST_FTP_CLIENT_IMPACT_VERIFIED": "true",
        "OS_GUARD_TEST_APPROVED_FTP_NETWORK": "10.20.0.0/16",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def pending_fixture_row(self):
        return "complete|1|0|0|0|1\n"

    def test_unbounded_network_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_FTP_NETWORK": "0.0.0.0/0"},
                ),
            )
            self.assertEqual(result["error"]["code"], "FTP_NETWORK_SCOPE_INVALID")

    def test_malformed_and_ipv6_networks_are_blocked(self):
        for network in ("999.20.0.0/16", "10.20.0.0/33", "2001:db8::/64"):
            with self.subTest(network=network), self.temporary_directory() as temp_dir:
                fixture = self.create_fixture(temp_dir)
                result, _ = self.run_action(
                    "PREVIEW",
                    self.environment(
                        fixture,
                        extra={"OS_GUARD_TEST_APPROVED_FTP_NETWORK": network},
                    ),
                )
                self.assertEqual(
                    result["error"]["code"],
                    "FTP_NETWORK_SCOPE_INVALID",
                )

    def test_existing_access_rules_are_not_rewritten(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content="ServerName fixture\nAllow from 192.0.2.0/24\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(
                result["error"]["code"],
                "PROFTPD_ACCESS_CONFIGURATION_AMBIGUOUS",
            )
