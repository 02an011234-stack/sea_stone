from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU50Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-50"
    target_path = "/etc/named.conf"
    active_unit = "named.service"
    fixture_result_variable = "OS_GUARD_TEST_U50_FILE"
    vulnerable_content = "options { allow-transfer { any; }; };\n"
    good_content = "options { allow-transfer { none; }; };\n"
    expected_fragment = "allow-transfer { none; };"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_ZONE_TRANSFER_DISABLE_APPROVED": "true",
        "OS_GUARD_TEST_SECONDARY_DNS_DEPENDENCIES_VERIFIED": "true",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def pending_fixture_row(self):
        return "complete|1|0|0|1|1|1\n"

    def assert_supported(self, distro, version):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            if distro == "ubuntu":
                ubuntu_path = fixture["root"] / "etc/bind/named.conf.options"
                ubuntu_path.parent.mkdir(parents=True, exist_ok=True)
                ubuntu_path.write_bytes(fixture["target"].read_bytes())
                fixture["target"].unlink()
                fixture["target"] = ubuntu_path
                systemctl_source = fixture["systemctl"].read_text(encoding="utf-8")
                fixture["systemctl"].write_text(
                    systemctl_source.replace("named.service", "bind9.service"),
                    encoding="utf-8",
                    newline="\n",
                )
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(fixture, distro=distro, version=version),
            )
            self.assertEqual(result["outcome"], "PLANNED")
