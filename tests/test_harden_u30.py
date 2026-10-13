import pytest

from harden_content_test_support import ContentHardenTestBase


class TestU30Harden(ContentHardenTestBase):
    __test__ = True
    item_id = "U-30"
    vulnerable_content = "umask 002\n"
    good_content = "umask 027\n"
    expected_fragment = "umask 027"


def create_case() -> TestU30Harden:
    case = TestU30Harden("test_01_good_no_change")
    case.setUp()
    return case


@pytest.mark.parametrize("mask", ["022", "0022", "027", "077"])
def test_u30_compliant_masks_need_no_change(mask):
    case = create_case()
    with case.temporary_directory() as temp_directory:
        fixture = case.create_fixture(temp_directory, content=f"umask {mask}\n")
        before = fixture["target"].read_bytes()
        result, _ = case.run_action("PREVIEW", case.environment(fixture))
        assert result["outcome"] == "NO_CHANGE"
        assert fixture["target"].read_bytes() == before


@pytest.mark.parametrize("mask", ["002", "0002"])
def test_u30_noncompliant_masks_are_hardened_and_rechecked(mask):
    case = create_case()
    with case.temporary_directory() as temp_directory:
        fixture = case.create_fixture(temp_directory, content=f"umask {mask}\n")
        preview, result, _ = case.execute(fixture)
        hardened_content = fixture["target"].read_text(encoding="utf-8")

        assert preview["outcome"] == "PLANNED"
        assert result["outcome"] == "SUCCESS"
        assert result["execution"]["recheck_status"] == "GOOD"
        assert "umask 027" in hardened_content
        assert case.sensitive_marker in hardened_content


def test_u30_preview_proposes_minimal_static_change():
    case = create_case()
    with case.temporary_directory() as temp_directory:
        fixture = case.create_fixture(temp_directory)
        result, _ = case.run_action("PREVIEW", case.environment(fixture))
        assert result["outcome"] == "PLANNED"
        assert result["preview"]["targets"][0]["change_required"] is True


def test_u30_recheck_failure_rolls_back_original_content():
    case = create_case()
    with case.temporary_directory() as temp_directory:
        fixture = case.create_fixture(temp_directory)
        before = fixture["target"].read_bytes()
        _, result, _ = case.execute(
            fixture,
            extra={"OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true"},
        )

        assert result["outcome"] == "FAILED"
        assert result["error"]["code"] == "RECHECK_FAILED"
        assert result["execution"]["rollback_attempted"] is True
        assert result["execution"]["rollback_success"] is True
        assert fixture["target"].read_bytes() == before


def test_u30_unrelated_content_is_preserved_after_success():
    case = create_case()
    with case.temporary_directory() as temp_directory:
        fixture = case.create_fixture(temp_directory)
        _, result, _ = case.execute(fixture)
        content = fixture["target"].read_text(encoding="utf-8")

        assert result["outcome"] == "SUCCESS"
        assert case.sensitive_marker in content


@pytest.mark.parametrize(
    ("distro", "version"),
    (
        ("rocky", "9.6"),
        ("rocky", "10.1"),
        ("ubuntu", "22.04"),
        ("ubuntu", "24.04"),
    ),
)
def test_u30_supported_os_preview(distro, version):
    case = create_case()
    with case.temporary_directory() as temp_directory:
        fixture = case.create_fixture(temp_directory)
        result, _ = case.run_action(
            "PREVIEW",
            case.environment(fixture, distro=distro, version=version),
        )
        assert result["outcome"] == "PLANNED"
