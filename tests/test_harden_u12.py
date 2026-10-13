from harden_content_test_support import ContentHardenTestBase


class TestU12Harden(ContentHardenTestBase):
    __test__ = True
    item_id = "U-12"
    vulnerable_content = "TMOUT=900\nexport TMOUT\n"
    good_content = "TMOUT=600\nexport TMOUT\n"
    expected_fragment = "TMOUT=600"

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        policy = {
            "OS_GUARD_TEST_POLICY_FIXTURE": "true",
            "OS_GUARD_TEST_SESSION_TIMEOUT_POLICY_APPROVED": "true",
            "OS_GUARD_TEST_SESSION_TIMEOUT_SCOPE": "global-supported-shells",
            "OS_GUARD_TEST_SESSION_TIMEOUT_EXCEPTIONS": "none",
        }
        if extra:
            policy.update(extra)
        return super().environment(
            fixture,
            distro=distro,
            version=version,
            extra=policy,
        )


def test_u12_stronger_timeout_is_preserved():
    case = TestU12Harden("test_01_good_no_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, content="TMOUT=300\nexport TMOUT\n")
        result, _ = case.run_action("PREVIEW", case.environment(fixture))
        assert result["outcome"] == "NO_CHANGE"


def test_u12_missing_timeout_is_added_once():
    case = TestU12Harden("test_02_vulnerable_minimal_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir, content="# no timeout\n")
        _, result, _ = case.execute(fixture)
        content = fixture["target"].read_text(encoding="utf-8")
        assert result["outcome"] == "SUCCESS"
        assert content.count("TMOUT=600") == 1


def test_u12_policy_fixture_is_required():
    case = TestU12Harden("test_02_vulnerable_minimal_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir)
        result, _ = case.run_action(
            "PREVIEW",
            case.environment(
                fixture,
                extra={"OS_GUARD_TEST_POLICY_FIXTURE": "false"},
            ),
        )
        assert result["error"]["code"] == "POLICY_INTEGRATION_REQUIRED"


def test_u12_account_exception_policy_is_blocked():
    case = TestU12Harden("test_02_vulnerable_minimal_change")
    case.setUp()
    with case.temporary_directory() as temp_dir:
        fixture = case.create_fixture(temp_dir)
        result, _ = case.run_action(
            "PREVIEW",
            case.environment(
                fixture,
                extra={"OS_GUARD_TEST_SESSION_TIMEOUT_EXCEPTIONS": "monitoring"},
            ),
        )
        assert result["error"]["code"] == "SESSION_TIMEOUT_EXCEPTIONS_UNSUPPORTED"
