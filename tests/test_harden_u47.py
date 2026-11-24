from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU47Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-47"
    target_path = "/etc/postfix/main.cf"
    active_unit = "postfix.service"
    fixture_result_variable = "OS_GUARD_TEST_U47_FILE"
    vulnerable_content = "myhostname = mail.example\nsmtpd_relay_restrictions =\n"
    good_content = (
        "myhostname = mail.example\n"
        "smtpd_relay_restrictions = reject_unauth_destination\n"
    )
    expected_fragment = "smtpd_relay_restrictions = reject_unauth_destination"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_MTA": "postfix",
        "OS_GUARD_TEST_RELAY_POLICY_APPROVED": "true",
        "OS_GUARD_TEST_MAIL_DEPENDENCIES_VERIFIED": "true",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def pending_fixture_row(self):
        return "complete|1|0|0|1|postfix\n"
