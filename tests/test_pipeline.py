import unittest
from email.message import EmailMessage

from app.analyzers.pipeline import analyze_eml_bytes


class PipelineTests(unittest.TestCase):
    def test_html_email_includes_body_form_analysis(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "user@example.com"
        message["Subject"] = "Please verify"
        message.set_content("fallback")
        message.add_alternative(
            """
            <html><body>
              <p>즉시 로그인해 계정을 확인하세요.</p>
              <form action="https://collector.example/submit"></form>
            </body></html>
            """,
            subtype="html",
        )

        result = analyze_eml_bytes("synthetic-form-lure.eml", message.as_bytes())
        body_result = result["mvp_outputs"]["email_body_risk_check"]
        rule_ids = {rule["rule_id"] for rule in body_result["matched_rules"]}
        self.assertIn("body.form_action_external", rule_ids)
        self.assertGreater(body_result["score"], 0)

    def test_html_only_link_is_extracted_into_pipeline_urls(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "user@example.com"
        message["Subject"] = "Please verify"
        message.set_content("fallback")
        message.add_alternative(
            """
            <html><body>
              <a href="https://evil.example/login">secure portal</a>
            </body></html>
            """,
            subtype="html",
        )

        result = analyze_eml_bytes("html-link.eml", message.as_bytes())
        self.assertIn("https://evil.example/login", result["extracted_urls"])

    def test_pipeline_explainable_report_includes_context_tags_and_snapshot(self):
        message = EmailMessage()
        message["From"] = "Finance Team <alerts@corp.example>"
        message["Reply-To"] = "Support <support@evil.example>"
        message["To"] = "user@example.com"
        message["Subject"] = "[긴급] 세금계산서 송금 확인 필요"
        message["Authentication-Results"] = "spf=fail dkim=fail"
        message.set_content("세금계산서 확인을 위해 즉시 로그인하세요.")
        message.add_alternative(
            """
            <html><body>
              <a href="http://invoice-secure-login.zip/세금계산서/verify?payment=true">
                세금계산서 확인
              </a>
            </body></html>
            """,
            subtype="html",
        )

        result = analyze_eml_bytes("invoice-context.eml", message.as_bytes())
        explainable = result["explainable_report"]

        self.assertIn("결제/송금", explainable["context_tags"])
        self.assertTrue(explainable["risk_snapshot"])
        self.assertIn("결제/송금", explainable["risk_snapshot"])

    def test_wrapped_email_link_prefers_nested_target_for_url_scoring(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "user@example.com"
        message["Subject"] = "Secure portal"
        message.set_content("포털 확인 링크")
        message.add_alternative(
            """
            <html><body>
              <a href="https://tracker.example/r/?target=https%3A%2F%2Fsecure-login-account-verify-portal.xyz%2Fverify%3Fuser%3Da">
                secure portal
              </a>
            </body></html>
            """,
            subtype="html",
        )

        result = analyze_eml_bytes("wrapped-link.eml", message.as_bytes())
        url_output = result["mvp_outputs"]["url_suspicion_scoring"]

        self.assertEqual(
            url_output["top_risky_url"],
            "https://secure-login-account-verify-portal.xyz/verify?user=a",
        )
        self.assertGreaterEqual(url_output["top_risky_score"], 30)

    def test_transactional_receipt_with_relay_sender_stays_medium(self):
        message = EmailMessage()
        message["From"] = '"OpenAI OpCo, LLC" <billing+acct_123@stripe.com>'
        message["Reply-To"] = '"OpenAI OpCo, LLC" <ar@openai.com>'
        message["To"] = "user@example.com"
        message["Subject"] = "Credit note from OpenAI OpCo, LLC for invoice #024A158F-0017"
        message["Authentication-Results"] = "spf=fail dkim=pass dmarc=pass"
        message.set_content(
            "OpenAI OpCo, LLC credit note is ready. Download your invoice PDF from the Stripe billing portal."
        )
        message.add_alternative(
            """
            <html><body>
              <a href="https://59.email.stripe.com/CL0/https:%2F%2Fpay.stripe.com%2Finvoice%2Facct_123%2Flive_receipt/pdf%3Fs=em/1/0101019c82dac84d-2f2d88b5-0cc4-476d-8e5f-86fd122b727a-000000/example">
                Download invoice PDF
              </a>
            </body></html>
            """,
            subtype="html",
        )

        result = analyze_eml_bytes("relay-receipt.eml", message.as_bytes())

        self.assertEqual(result["severity"], "medium")
        self.assertLess(result["final_risk_score"], 60)


if __name__ == "__main__":
    unittest.main()
