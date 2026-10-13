from harden_multi_test_support import MultiTargetHardenTestBase


class TestU21Harden(MultiTargetHardenTestBase):
    __test__ = True
    item_id = "U-21"
    targets = (
        ("/etc/rsyslog.conf", "file", "640", "configuration"),
        ("/etc/rsyslog.d/a.conf", "file", "600", "configuration"),
    )

    def add_drift_target(self, fixture):
        display = "/etc/rsyslog.d/b.conf"
        actual = fixture["root"] / display.lstrip("/")
        actual.write_text(self.sensitive_marker, encoding="utf-8")
        with fixture["state"].open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"{display}|file|0|root|0|root|640|100|9999|200|300|?|safe|0|root|configuration\n")


def test_u21_journald_only_is_no_change():
    case = TestU21Harden("test_01_good_state_no_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir)
        for display, _, _, _ in case.targets:
            (fixture["root"] / display.lstrip("/")).unlink()
        fixture["state"].write_text("", encoding="utf-8")
        (fixture["root"] / "etc/systemd").mkdir(parents=True, exist_ok=True)
        (fixture["root"] / "etc/systemd/journald.conf").write_text("", encoding="utf-8")
        environment = case.environment(
            fixture,
            extra={"OS_GUARD_TEST_LOGGING_MODEL": "journald_only"},
        )
        fixture["check"].write_text("", encoding="utf-8")
        result, _ = case.run_action("PREVIEW", environment)
        assert result["outcome"] == "NO_CHANGE"
