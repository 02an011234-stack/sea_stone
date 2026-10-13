from harden_metadata_test_support import MetadataHardenTestBase


class TestU18Harden(MetadataHardenTestBase):
    __test__ = True
    item_id = "U-18"
    target_path = "/etc/shadow"
    good_mode = "400"
    vulnerable_mode = "640"
    sensitive_marker = "root:$6$DO_NOT_EXPOSE_HASH:20000:0:99999:7:::"


def test_u18_permission_zero_is_good_and_unchanged():
    case = TestU18Harden("test_01_good_state_is_not_changed")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, mode="0")
        before = fixture[2].read_bytes()
        result, output = case.run_action("PREVIEW", case.environment(fixture))
        case.assertEqual(result["outcome"], "NO_CHANGE")
        case.assertEqual(result["preview"]["current_permission"], "0")
        case.assertEqual(fixture[2].read_bytes(), before)
        case.assertNotIn("DO_NOT_EXPOSE_HASH", output)
