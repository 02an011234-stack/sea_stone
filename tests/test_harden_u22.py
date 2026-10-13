from harden_metadata_test_support import MetadataHardenTestBase


class TestU22Harden(MetadataHardenTestBase):
    __test__ = True
    item_id = "U-22"
    target_path = "/etc/services"
    good_mode = "644"
    vulnerable_mode = "666"


def test_u22_services_content_is_preserved():
    case = TestU22Harden("test_20_sensitive_content_is_not_exposed_or_changed")
    case.setUp()
    case.test_20_sensitive_content_is_not_exposed_or_changed()
