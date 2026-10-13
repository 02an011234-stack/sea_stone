from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU46Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-46"
    target_path = "/etc/mail/sendmail.cf"
    active_unit = "sendmail.service"
    fixture_result_variable = "OS_GUARD_TEST_U46_FILE"
    vulnerable_content = "O PrivacyOptions=authwarnings\n"
    good_content = "O PrivacyOptions=authwarnings,restrictqrun\n"
    expected_fragment = "restrictqrun"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_MTA": "sendmail",
        "OS_GUARD_TEST_MAIL_EXECUTION_RESTRICTION_APPROVED": "true",
        "OS_GUARD_TEST_SENDMAIL_CONFIGURATION_SOURCE": "static-sendmail.cf",
        "OS_GUARD_TEST_MAIL_QUEUE_IMPACT_VERIFIED": "true",
        "OS_GUARD_TEST_RELOAD_APPROVED": "true",
    }

    def pending_fixture_row(self):
        return "complete|1|0|0|1|postfix\n"

    def test_25_unsupported_mta_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_MTA": "postfix"},
                ),
            )
            self.assertEqual(result["error"]["code"], "MTA_POLICY_NOT_APPROVED")

    def test_26_duplicate_privacy_options_are_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(
                temp_dir,
                content="O PrivacyOptions=authwarnings\nO PrivacyOptions=novrfy\n",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "SENDMAIL_CONFIGURATION_AMBIGUOUS")

    def test_27_generated_sendmail_configuration_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            (fixture["root"] / "etc" / "mail" / "sendmail.mc").write_text(
                "define(`confPRIVACY_FLAGS', `authwarnings')dnl\n",
                encoding="utf-8",
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(
                result["error"]["code"],
                "SENDMAIL_GENERATED_CONFIGURATION_UNSUPPORTED",
            )

    def test_28_mail_queue_impact_evidence_is_required(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_MAIL_QUEUE_IMPACT_VERIFIED": "false"},
                ),
            )
            self.assertEqual(
                result["error"]["code"],
                "MAIL_QUEUE_IMPACT_EVIDENCE_REQUIRED",
            )
