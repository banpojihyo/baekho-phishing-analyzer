import os
import unittest
from unittest.mock import MagicMock, patch

from app.analyzers.url_probe_client import _remote_probe_result, resolve_probe_result


class UrlProbeClientTests(unittest.TestCase):
    @patch.dict(os.environ, {"PHISHSHIELD_URL_PROBE_MODE": "off"}, clear=False)
    def test_off_mode_returns_disabled_result(self):
        result = resolve_probe_result("https://example.com")

        self.assertFalse(result["performed"])
        self.assertEqual(result["probe_source"], "disabled")

    @patch.dict(os.environ, {"PHISHSHIELD_URL_PROBE_MODE": "local"}, clear=False)
    @patch("app.analyzers.url_probe_client.probe_url")
    def test_local_mode_uses_in_process_probe(self, mock_probe_url):
        mock_probe_url.return_value = {
            "performed": True,
            "blocked_reason": None,
            "error": None,
            "browser": {"title": "local"},
            "crawler": {},
        }

        result = resolve_probe_result("https://example.com")

        mock_probe_url.assert_called_once_with("https://example.com")
        self.assertEqual(result["probe_source"], "local")
        self.assertTrue(result["performed"])

    @patch.dict(os.environ, {"PHISHSHIELD_URL_PROBE_MODE": "remote"}, clear=False)
    @patch("app.analyzers.url_probe_client._remote_probe_result")
    def test_remote_mode_uses_worker_client(self, mock_remote_probe_result):
        mock_remote_probe_result.return_value = {
            "performed": True,
            "blocked_reason": None,
            "error": None,
            "browser": {"title": "remote"},
            "crawler": {},
            "probe_source": "remote",
        }

        result = resolve_probe_result("https://example.com")

        mock_remote_probe_result.assert_called_once_with("https://example.com")
        self.assertEqual(result["probe_source"], "remote")

    @patch.dict(
        os.environ,
        {
            "PHISHSHIELD_URL_PROBE_WORKER_URL": "http://worker.internal/probe-url",
            "PHISHSHIELD_URL_PROBE_SHARED_TOKEN": "shared-secret",
        },
        clear=False,
    )
    @patch("app.analyzers.url_probe_client_remote.Request")
    @patch("app.analyzers.url_probe_client_remote.urlopen")
    def test_remote_worker_request_includes_shared_token_header(self, mock_urlopen, mock_request):
        response = MagicMock()
        response.read.return_value = (
            b'{"performed": true, "blocked_reason": null, "error": null, "browser": {}, "crawler": {}}'
        )
        mock_urlopen.return_value.__enter__.return_value = response
        mock_request.return_value = object()

        result = _remote_probe_result("https://example.com")

        headers = mock_request.call_args.kwargs["headers"]
        self.assertEqual(mock_request.call_args.args[0], "http://worker.internal/probe-url")
        self.assertEqual(headers["X-PhishShield-Worker-Token"], "shared-secret")
        self.assertEqual(result["probe_source"], "remote")

    @patch.dict(os.environ, {"PHISHSHIELD_URL_PROBE_MODE": "remote"}, clear=False)
    @patch("app.analyzers.url_probe_client.fetch_remote_probe_payload", return_value={"performed": True, "browser": "oops"})
    def test_remote_mode_normalizes_non_dict_snapshots(self, _mock_fetch_remote_probe_payload):
        result = resolve_probe_result("https://example.com")

        self.assertTrue(result["performed"])
        self.assertEqual(result["probe_source"], "remote")
        self.assertEqual(result["browser"], {})
