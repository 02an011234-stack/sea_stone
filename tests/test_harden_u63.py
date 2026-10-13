from harden_multi_test_support import MultiTargetHardenTestBase


class TestU63Harden(MultiTargetHardenTestBase):
    __test__ = True
    item_id = "U-63"
    targets = (("/etc/sudoers", "file", "640", "sudoers"),)

    def add_drift_target(self, fixture):
        data = fixture["state"].read_text(encoding="utf-8")
        fixture["state"].write_text(
            data.replace("|100|1001|", "|100|9001|", 1),
            encoding="utf-8",
            newline="\n",
        )

    def test_21_target_list_drift(self):
        self.test_20_state_drift()

    def test_17_partial_failure_is_atomic(self):
        self.test_13_validation_failure_rolls_back()


def test_u63_visudo_failure_prevents_change():
    case = TestU63Harden("test_01_good_state_no_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir)
        before = fixture["state"].read_bytes()
        _, result, _ = case.execute(
            fixture,
            extra={"OS_GUARD_TEST_VISUDO_FAILURE": "true"},
        )
        assert result["error"]["code"] == "SUDOERS_SYNTAX_INVALID"
        assert fixture["state"].read_bytes() == before


def test_u63_sudoers_content_is_preserved():
    case = TestU63Harden("test_24_content_preserved")
    case.setUp()
    case.test_24_content_preserved()
