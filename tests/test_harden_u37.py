from harden_multi_test_support import MultiTargetHardenTestBase


class TestU37Harden(MultiTargetHardenTestBase):
    __test__ = True
    item_id = "U-37"
    targets = (
        ("/usr/bin/crontab", "file", "750", "executable"),
        ("/etc/cron.allow", "file", "640", "configuration"),
        ("/etc/cron.d", "directory", "755", "directory"),
    )

    def add_drift_target(self, fixture):
        display = "/usr/bin/at"
        actual = fixture["root"] / display.lstrip("/")
        actual.write_text(self.sensitive_marker, encoding="utf-8")
        with fixture["state"].open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"{display}|file|0|root|0|root|750|100|9999|200|300|?|safe|0|root|executable\n")
