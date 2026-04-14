from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPORT_HTML = ROOT / "app" / "static" / "report.html"
REPORT_GUIDE_DIR = ROOT / "app" / "static" / "public" / "report-guides"


class ReportPageContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = REPORT_HTML.read_text(encoding="utf-8")

    def test_report_page_includes_export_and_masking_guides(self):
        html = self.html

        self.assertIn("report-export-grid", html)
        self.assertIn("메시지 다운로드", html)
        self.assertIn("Google Takeout", html)
        self.assertIn(".eml", html)
        self.assertIn("zip", html)
        self.assertIn("Outlook", html)
        self.assertIn("공개 자료 원칙", html)
        self.assertNotIn("????", html)

    def test_report_page_uses_text_guides_without_screenshot_stepper(self):
        html = self.html

        self.assertIn("네이버 메일 요약", html)
        self.assertIn("Gmail 요약", html)
        self.assertNotIn("data-report-guide", html)
        self.assertNotIn("data-guide-step", html)

    def test_real_mail_screenshot_assets_are_not_public(self):
        screenshots = list(REPORT_GUIDE_DIR.glob("**/*.png")) if REPORT_GUIDE_DIR.exists() else []

        self.assertEqual(screenshots, [])


if __name__ == "__main__":
    unittest.main()
