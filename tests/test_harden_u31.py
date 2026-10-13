from harden_multi_test_support import MultiTargetHardenTestBase


class TestU31Harden(MultiTargetHardenTestBase):
    __test__ = True
    item_id = "U-31"
    acl_policy = True
    targets = (
        ("/home/user", "directory", "750", "home"),
        ("/home/user2", "directory", "700", "home"),
    )

    def add_drift_target(self, fixture):
        new_display = "/home/user3"
        actual = fixture["root"] / new_display.lstrip("/")
        actual.mkdir(parents=True)
        passwd = fixture["root"] / "etc/passwd"
        with passwd.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("user3:x:1002:1002:user3:/home/user3:/bin/sh\n")
        with fixture["state"].open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"{new_display}|directory|1002|user3|0|root|700|100|9999|200|300|?|safe|1002|user3|home\n")


def test_u31_shared_home_owner_relationship_is_rejected():
    case = TestU31Harden("test_01_good_state_no_change")
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
