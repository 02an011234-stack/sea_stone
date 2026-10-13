from harden_metadata_test_support import MetadataHardenTestBase


class TestU16Harden(MetadataHardenTestBase):
    __test__ = True
    item_id = "U-16"
    target_path = "/etc/passwd"
    good_mode = "644"
    vulnerable_mode = "666"


def test_u16_passwd_content_is_preserved():
    case = TestU16Harden("test_20_sensitive_content_is_not_exposed_or_changed")
    case.setUp()
    case.test_20_sensitive_content_is_not_exposed_or_changed()
