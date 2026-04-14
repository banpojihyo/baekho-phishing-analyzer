import unittest
from email.message import EmailMessage

from app.analyzers.email_body import analyze_email_body, analyze_email_body_content


def build_html_message(*, html: str, plain: str = "") -> EmailMessage:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "user@example.com"
    message["Subject"] = "Body analyzer test"
    message.set_content(plain or "plain fallback")
    message.add_alternative(html, subtype="html")
    return message


class EmailBodyTests(unittest.TestCase):
    def test_html_body_rules_and_urls_are_extracted(self):
        message = build_html_message(
            html="""
            <html><body>
              <a href="https://evil.example/login">https://secure.example/login</a>
              <form action="https://forms.evil.example/submit"></form>
              <script>window.location="https://js.evil.example/go"</script>
            </body></html>
            """,
            plain="즉시 로그인 확인",
        )

        result = analyze_email_body(message)
        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}

        self.assertIn("body.anchor_domain_mismatch", rule_ids)
        self.assertIn("body.form_action_external", rule_ids)
        self.assertIn("body.javascript_redirect", rule_ids)
        self.assertIn("body.social_engineering_terms", rule_ids)
        self.assertIn("https://evil.example/login", result["urls"])
        self.assertIn("https://forms.evil.example/submit", result["urls"])
        self.assertIn("https://js.evil.example/go", result["urls"])

    def test_business_context_lure_is_detected_for_korean_office_terms(self):
        message = build_html_message(
            html="""
            <html><body>
              <a href="https://evil.example/login">세금계산서 확인</a>
            </body></html>
            """,
            plain="세금계산서 확인을 위해 즉시 로그인하세요.",
        )

        result = analyze_email_body(message)
        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}

        self.assertIn("body.business_context_lure", rule_ids)
        self.assertIn("결제/송금", result["detected_contexts"])
        self.assertIn("계정 인증", result["detected_contexts"])

    def test_mailto_links_are_not_sent_to_url_analyzer(self):
        message = build_html_message(
            html="""
            <html><body>
              <a href="mailto:marketing@example.com">문의하기</a>
            </body></html>
            """
        )

        result = analyze_email_body(message)

        self.assertNotIn("mailto:marketing@example.com", result["urls"])

    def test_wrapped_redirect_target_is_extracted_from_email_link(self):
        message = build_html_message(
            html="""
            <html><body>
              <a href="https://tracker.example/r/?target=https%3A%2F%2Fsecure-login-account-verify-portal.xyz%2Fverify%3Fuser%3Da">
                보안 포털 열기
              </a>
            </body></html>
            """
        )

        result = analyze_email_body(message)

        self.assertIn(
            "https://secure-login-account-verify-portal.xyz/verify?user=a",
            result["urls"],
        )

    def test_visible_domain_without_scheme_can_trigger_anchor_mismatch(self):
        message = build_html_message(
            html="""
            <html><body>
              <a href="https://evil.example/login">www.secure.example/login</a>
            </body></html>
            """
        )

        result = analyze_email_body(message)
        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}

        self.assertIn("body.anchor_domain_mismatch", rule_ids)

    def test_transactional_notice_without_auth_lure_stays_unflagged(self):
        message = build_html_message(
            html="""
            <html><body>
              <a href="https://billing.example.com/invoice/123">Download receipt</a>
            </body></html>
            """,
            plain="Your invoice is ready. Download your receipt from the billing portal.",
        )

        result = analyze_email_body(message)
        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}

        self.assertNotIn("body.social_engineering_terms", rule_ids)
        self.assertNotIn("body.business_context_lure", rule_ids)

    def test_invalid_ipv6_like_href_does_not_crash_body_analysis(self):
        message = build_html_message(
            html="""
            <html><body>
              <form action="http://[not-an-ipv6]/login"></form>
            </body></html>
            """
        )

        result = analyze_email_body(message)

        self.assertIsInstance(result["urls"], list)

    def test_analyze_email_body_content_scores_plain_text_dataset_record(self):
        result = analyze_email_body_content(
            text="세금계산서 확인을 위해 즉시 로그인하세요.",
            urls=["https://billing-check.example/verify"],
        )

        self.assertGreater(result["score"], 0)
        self.assertIn("결제/송금", result["detected_contexts"])
        self.assertIn("계정 인증", result["detected_contexts"])


if __name__ == "__main__":
    unittest.main()
