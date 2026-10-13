from harden_multi_test_support import MultiTargetHardenTestBase


class TestU17Harden(MultiTargetHardenTestBase):
    __test__ = True
    item_id = "U-17"
    targets = (
        ("/etc/systemd/system/a.service", "file", "640", "startup"),
        ("/etc/systemd/system/b.service", "file", "600", "startup"),
    )


def test_u17_preserves_restrictive_permission():
    case = TestU17Harden("test_01_good_state_no_change")
    case.setUp()
    case.test_01_good_state_no_change()
