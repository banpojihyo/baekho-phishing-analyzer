import unittest

from app.services.analysis_response import build_url_analysis_response


class AnalysisResponseTests(unittest.TestCase):
    def test_build_url_analysis_response_keeps_score_and_context(self):
        result = {
            "url": "https://secure.example.com/login",
            "normalized_url": "https://secure.example.com/login",
            "host": "secure.example.com",
            "score": 68,
            "severity": "high",
            "evidence": ["HTTPS 미사용", "사회공학 유도 키워드 포함(login)"],
            "matched_rules": [],
            "detected_contexts": ["계정 인증"],
            "probe": {"performed": False},
        }

        response = build_url_analysis_response(result)

        self.assertEqual(response["input_type"], "url")
        self.assertEqual(response["url"], result["url"])
        self.assertEqual(response["final_risk_score"], 68)
        self.assertEqual(response["severity"], "high")
        self.assertIn("계정 인증", response["explainable_report"]["context_tags"])
        self.assertEqual(response["mvp_outputs"]["url_suspicion_scoring"], result)

    def test_build_url_analysis_response_uses_url_prefixed_evidence(self):
        result = {
            "url": "https://secure.example.com/login",
            "normalized_url": "https://secure.example.com/login",
            "host": "secure.example.com",
            "score": 35,
            "severity": "medium",
            "evidence": ["사회공학 유도 키워드 포함(login)"],
            "matched_rules": [],
            "detected_contexts": [],
            "probe": {"performed": False},
        }

        response = build_url_analysis_response(result)

        why_risky = response["explainable_report"]["why_risky"]
        self.assertEqual(why_risky[0], "[URL] 사회공학 유도 키워드 포함(login)")


if __name__ == "__main__":
    unittest.main()
