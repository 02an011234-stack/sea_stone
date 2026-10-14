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


def test_u17_ubuntu_without_selinux_preview_is_read_only():
    case = TestU17Harden("test_03_permission_only")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, vulnerability="permission")
        before_state = fixture["state"].read_bytes()
        result, _ = case.run_action(
            "PREVIEW",
            case.environment(
                fixture,
                distro="ubuntu",
                version="24.04",
                extra={"OS_GUARD_TEST_SELINUX_STATE": "disabled"},
            ),
        )
        assert result["outcome"] == "PLANNED"
        assert fixture["state"].read_bytes() == before_state
        case.assert_contents_unchanged(fixture)


def test_u17_enabled_selinux_context_failure_is_blocked():
    case = TestU17Harden("test_03_permission_only")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, vulnerability="permission")
        before_state = fixture["state"].read_bytes()
        result, _ = case.run_action(
            "PREVIEW",
            case.environment(
                fixture,
                extra={
                    "OS_GUARD_TEST_SELINUX_STATE": "enabled",
                    "OS_GUARD_TEST_SELINUX_CONTEXT_FAILURE": "true",
                },
            ),
        )
        assert result["outcome"] == "FAILED"
        assert result["error"]["code"] == "SELINUX_CONTEXT_COLLECTION_FAILED"
        assert fixture["state"].read_bytes() == before_state
        case.assert_contents_unchanged(fixture)
