import unittest

from app.services.eml_analysis_response import build_eml_analysis_response


class EMLAnalysisResponseTests(unittest.TestCase):
    def test_build_eml_analysis_response_merges_evidence_and_contexts(self):
        header_result = {
            "from": "alerts@corp.example",
            "reply_to": "support@evil.example",
            "from_domain": "corp.example",
            "reply_to_domain": "evil.example",
            "subject": "[긴급] 세금계산서 송금 확인 필요",
            "score": 25,
            "evidence": ["From 도메인과 Reply-To 도메인 불일치"],
            "matched_rules": [],
            "detected_contexts": ["결제/송금"],
        }
        body_result = {
            "text": "세금계산서 확인을 위해 즉시 로그인하세요.",
            "urls": ["https://evil.example/login"],
            "score": 18,
            "severity": "medium",
            "evidence": ["본문에 사회공학 유도 표현 포함(로그인, 즉시)"],
            "matched_rules": [],
            "detected_contexts": ["계정 인증"],
            "html_present": True,
        }
        url_results = [
            {
                "url": "https://evil.example/login",
                "normalized_url": "https://evil.example/login",
                "host": "evil.example",
                "score": 70,
                "severity": "high",
                "evidence": ["사회공학 유도 키워드 포함(login)"],
                "matched_rules": [],
                "detected_contexts": ["계정 인증"],
                "probe": {"performed": False},
            }
        ]
        attachment_result = {
            "attachment_count": 1,
            "risky_attachment_count": 1,
            "score": 14,
            "severity": "medium",
            "evidence": ["invoice.html: HTML 첨부파일(.html)"],
            "attachments": [],
            "matched_rules": [],
        }

        result = build_eml_analysis_response(
            filename="invoice.eml",
            extracted_urls=["https://evil.example/login"],
            header_result=header_result,
            body_result=body_result,
            url_results=url_results,
            attachment_result=attachment_result,
        )

        self.assertEqual(result["filename"], "invoice.eml")
        self.assertEqual(result["mvp_outputs"]["url_suspicion_scoring"]["top_risky_url"], "https://evil.example/login")
        self.assertIn("[Header] From 도메인과 Reply-To 도메인 불일치", result["explainable_report"]["why_risky"])
        self.assertIn("결제/송금", result["explainable_report"]["context_tags"])
        self.assertIn("계정 인증", result["explainable_report"]["context_tags"])


if __name__ == "__main__":
    unittest.main()
