from harden_multi_test_support import MultiTargetHardenTestBase


class TestU24Harden(MultiTargetHardenTestBase):
    __test__ = True
    item_id = "U-24"
    acl_policy = True
    targets = (
        ("/home/user/.profile", "file", "640", "environment"),
        ("/home/user2/.bashrc", "file", "600", "environment"),
    )

    def add_drift_target(self, fixture):
        display = "/home/user/.bash_profile"
        actual = fixture["root"] / display.lstrip("/")
        actual.write_text(self.sensitive_marker, encoding="utf-8")
        with fixture["state"].open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"{display}|file|1000|user|0|root|640|100|9999|200|300|?|safe|1000|user|environment\n")


def test_u24_shared_home_owner_relationship_is_rejected():
    case = TestU24Harden("test_01_good_state_no_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir)
        passwd = fixture["root"] / "etc/passwd"
        passwd.write_text(
            passwd.read_text(encoding="utf-8")
            + "alias:x:1002:1002:alias:/home/user:/bin/sh\n",
            encoding="utf-8",
            newline="\n",
        )
        result, _ = case.run_action("PREVIEW", case.environment(fixture))
        assert result["error"]["code"] == "TARGET_RELATIONSHIP_AMBIGUOUS"
