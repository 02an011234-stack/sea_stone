from harden_content_test_support import ContentHardenTestBase


class TestU14Harden(ContentHardenTestBase):
    __test__ = True
    item_id = "U-14"
    vulnerable_content = 'PATH=".:/usr/local/sbin:/usr/bin"\nexport PATH\n'
    good_content = 'PATH="/usr/local/sbin:/usr/bin"\nexport PATH\n'
    expected_fragment = 'PATH="/usr/local/sbin:/usr/bin"'


def test_u14_middle_current_directory_removed():
    case = TestU14Harden("test_02_vulnerable_minimal_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, content='PATH="/usr/bin:.:/custom/bin"\n')
        _, result, _ = case.execute(fixture)
        content = fixture["target"].read_text(encoding="utf-8")
        assert result["outcome"] == "SUCCESS"
        assert '/usr/bin:/custom/bin' in content


def test_u14_empty_path_component_removed():
    case = TestU14Harden("test_02_vulnerable_minimal_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, content='PATH="/usr/bin::/custom/bin"\n')
        _, result, _ = case.execute(fixture)
        content = fixture["target"].read_text(encoding="utf-8")
        assert result["outcome"] == "SUCCESS"
        assert '/usr/bin:/custom/bin' in content


def test_u14_dynamic_path_is_not_modified():
    case = TestU14Harden("test_01_good_no_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, content='PATH=".:$PATH"\n')
        before = fixture["target"].read_bytes()
        result, _ = case.run_action("PREVIEW", case.environment(fixture))
        assert result["outcome"] == "FAILED"
        assert fixture["target"].read_bytes() == before
