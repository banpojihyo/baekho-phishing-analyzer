import importlib.util
import unittest
from unittest.mock import patch


FASTAPI_RUNTIME_AVAILABLE = all(
    importlib.util.find_spec(name) is not None
    for name in ("fastapi", "starlette", "pydantic", "multipart")
)


@unittest.skipUnless(FASTAPI_RUNTIME_AVAILABLE, "FastAPI runtime dependencies are not installed")
class AnalysisRoutesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from app.main import create_app

        cls.client = TestClient(create_app())

    @patch("app.routes.analysis.record_audit_event")
    @patch("app.routes.analysis.enforce_rate_limit", return_value="test-client")
    @patch("app.routes.analysis.analyze_url")
    def test_analyze_url_route_returns_structured_response(
        self,
        mock_analyze_url,
        _mock_rate_limit,
        _mock_record_audit,
    ):
        mock_analyze_url.return_value = {
            "url": "https://secure.example.com/login",
            "normalized_url": "https://secure.example.com/login",
            "host": "secure.example.com",
            "score": 68,
            "severity": "high",
            "evidence": ["사회공학 유도 키워드 포함(login)"],
            "matched_rules": [],
            "detected_contexts": ["계정 인증"],
            "probe": {"performed": False},
        }

        response = self.client.post("/analyze/url", json={"url": "https://secure.example.com/login"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["input_type"], "url")
        self.assertEqual(body["final_risk_score"], 68)
        self.assertEqual(body["severity"], "high")
        self.assertEqual(body["mvp_outputs"]["url_suspicion_scoring"]["url"], "https://secure.example.com/login")
        mock_analyze_url.assert_called_once_with("https://secure.example.com/login", enable_probe=True)

    @patch("app.routes.analysis.record_audit_event")
    @patch("app.routes.analysis.enforce_rate_limit", return_value="test-client")
    def test_analyze_eml_route_rejects_non_eml_extension(self, _mock_rate_limit, mock_record_audit):
        response = self.client.post(
            "/analyze/eml",
            files={"file": ("sample.txt", b"hello", "text/plain")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], ".eml 파일만 업로드할 수 있습니다.")
        self.assertEqual(mock_record_audit.call_args.kwargs["note"], "invalid_extension")

    @patch("app.routes.analysis.record_audit_event")
    @patch("app.routes.analysis.enforce_rate_limit", return_value="test-client")
    def test_analyze_eml_route_rejects_empty_file(self, _mock_rate_limit, mock_record_audit):
        response = self.client.post(
            "/analyze/eml",
            files={"file": ("sample.eml", b"", "message/rfc822")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "빈 파일입니다.")
        self.assertEqual(mock_record_audit.call_args.kwargs["note"], "empty_file")

    @patch("app.routes.analysis.MAX_EML_UPLOAD_LABEL", "4 B")
    @patch("app.routes.analysis.MAX_EML_UPLOAD_BYTES", 4)
    @patch("app.routes.analysis.record_audit_event")
    @patch("app.routes.analysis.enforce_rate_limit", return_value="test-client")
    def test_analyze_eml_route_rejects_oversized_file(self, _mock_rate_limit, mock_record_audit):
        response = self.client.post(
            "/analyze/eml",
            files={"file": ("sample.eml", b"12345", "message/rfc822")},
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["detail"], "파일 크기 제한(4 B)을 초과했습니다.")
        self.assertEqual(mock_record_audit.call_args.kwargs["note"], "file_too_large")

    @patch("app.routes.analysis.record_audit_event")
    @patch("app.routes.analysis.enforce_rate_limit", return_value="test-client")
    @patch("app.routes.analysis.analyze_eml_bytes")
    def test_analyze_eml_route_returns_structured_response(
        self,
        mock_analyze_eml_bytes,
        _mock_rate_limit,
        _mock_record_audit,
    ):
        mock_analyze_eml_bytes.return_value = {
            "input_type": "eml",
            "filename": "sample.eml",
            "extracted_urls": ["https://evil.example/login"],
            "final_risk_score": 72,
            "severity": "high",
            "summary": "최종 위험 점수는 72점(high)입니다.",
            "mvp_outputs": {
                "email_header_risk_check": {"score": 20},
                "email_body_risk_check": {"score": 18},
                "url_suspicion_scoring": {"top_risky_url": "https://evil.example/login", "top_risky_score": 72},
                "attachment_static_guard": {"score": 0},
                "explainable_report_output": {"summary": "최종 위험 점수는 72점(high)입니다."},
            },
            "explainable_report": {
                "summary": "최종 위험 점수는 72점(high)입니다.",
                "risk_snapshot": "URL 영역에서 복합 신호가 탐지됐습니다.",
                "context_tags": ["계정 인증"],
                "why_risky": ["[URL] 사회공학 유도 키워드 포함(login)"],
                "recommended_actions": ["링크 클릭 및 첨부파일 실행을 중단하고 별도 채널로 발신자 확인을 진행하세요."],
            },
        }

        response = self.client.post(
            "/analyze/eml",
            files={"file": ("sample.eml", b"From: sender@example.com\n\nbody", "message/rfc822")},
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["input_type"], "eml")
        self.assertEqual(body["final_risk_score"], 72)
        self.assertEqual(body["severity"], "high")
        mock_analyze_eml_bytes.assert_called_once()


if __name__ == "__main__":
    unittest.main()
