from harden_metadata_test_support import MetadataHardenTestBase


class TestU29Harden(MetadataHardenTestBase):
    __test__ = True
    item_id = "U-29"
    target_path = "/etc/hosts.lpd"
    good_mode = "600"
    vulnerable_mode = "666"
    missing_is_no_change = True


def test_u29_absent_target_is_not_created():
    case = TestU29Harden("test_05_missing_target_policy")
    case.setUp()
    case.test_05_missing_target_policy()
