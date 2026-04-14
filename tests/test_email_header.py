import unittest

from app.analyzers.email_header import analyze_header_fields


class EmailHeaderTests(unittest.TestCase):
    def test_header_rules_are_structured(self):
        result = analyze_header_fields(
            from_value="Security Team <alerts@safe.example>",
            reply_to_value="Support <support@evil.example>",
            subject="[긴급] 송금 확인 필요",
            auth_results="spf=fail dkim=fail dmarc=fail",
            has_message_id=False,
            received_count=0,
        )

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("header.reply_to_mismatch", rule_ids)
        self.assertIn("header.spf_fail", rule_ids)
        self.assertIn("header.dkim_fail", rule_ids)
        self.assertIn("header.dmarc_fail", rule_ids)
        self.assertIn("header.urgent_subject_terms", rule_ids)

    def test_header_business_context_subject_is_detected(self):
        result = analyze_header_fields(
            from_value="Finance Team <alerts@safe.example>",
            reply_to_value="Finance Team <alerts@safe.example>",
            subject="[긴급] 세금계산서 송금 확인 필요",
            auth_results="spf=fail",
            has_message_id=True,
            received_count=1,
        )

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("header.business_context_subject", rule_ids)
        self.assertIn("결제/송금", result["detected_contexts"])

    def test_transactional_relay_receipt_is_not_overpenalized_by_header_rules(self):
        result = analyze_header_fields(
            from_value='"OpenAI OpCo, LLC" <billing+acct_123@stripe.com>',
            reply_to_value='"OpenAI OpCo, LLC" <ar@openai.com>',
            subject="Credit note from OpenAI OpCo, LLC for invoice #024A158F-0017",
            auth_results="spf=fail dkim=pass dmarc=pass",
            has_message_id=True,
            received_count=2,
        )

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("header.reply_to_mismatch", rule_ids)
        self.assertIn("header.spf_fail", rule_ids)
        self.assertNotIn("header.urgent_subject_terms", rule_ids)
        self.assertNotIn("header.business_context_subject", rule_ids)
        self.assertLess(result["score"], 30)


if __name__ == "__main__":
    unittest.main()
