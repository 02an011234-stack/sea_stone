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


def test_u16_ubuntu_without_selinux_accepts_good_metadata():
    case = TestU16Harden("test_01_good_state_is_not_changed")
    case.setUp()
    for version in ("22.04", "24.04"):
        with case.temporary_directory() as temp_dir:
            fixture = case.create_fixture(temp_dir)
            before = fixture[2].read_bytes()
            result, _ = case.run_action(
                "PREVIEW",
                case.environment(
                    fixture,
                    distro="ubuntu",
                    version=version,
                    extra={"OS_GUARD_TEST_SELINUX_STATE": "disabled"},
                ),
            )
            assert result["outcome"] == "NO_CHANGE"
            assert fixture[2].read_bytes() == before


def test_u16_ubuntu_without_selinux_plans_vulnerable_metadata_read_only():
    case = TestU16Harden("test_03_permission_only_is_hardened")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, mode="666")
        before_state = fixture[2].read_bytes()
        before_content = fixture[1].read_bytes()
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
        assert result["preview"]["permission_change_required"] is True
        assert fixture[2].read_bytes() == before_state
        assert fixture[1].read_bytes() == before_content


def test_u16_rocky_with_selinux_collects_context():
    case = TestU16Harden("test_01_good_state_is_not_changed")
    case.setUp()
    for version in ("9.6", "10.2"):
        with case.temporary_directory() as temp_dir:
            fixture = case.create_fixture(temp_dir)
            result, _ = case.run_action(
                "PREVIEW",
                case.environment(
                    fixture,
                    distro="rocky",
                    version=version,
                    extra={"OS_GUARD_TEST_SELINUX_STATE": "enabled"},
                ),
            )
            assert result["outcome"] == "NO_CHANGE"


def test_u16_enabled_selinux_context_failure_is_blocked():
    case = TestU16Harden("test_01_good_state_is_not_changed")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir)
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


def test_u16_unknown_selinux_state_is_blocked():
    case = TestU16Harden("test_01_good_state_is_not_changed")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir)
        result, _ = case.run_action(
            "PREVIEW",
            case.environment(
                fixture,
                extra={"OS_GUARD_TEST_SELINUX_STATE": "unknown"},
            ),
        )
        assert result["outcome"] == "FAILED"
        assert result["error"]["code"] == "SELINUX_STATE_UNDETERMINED"
