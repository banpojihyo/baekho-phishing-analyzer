from __future__ import annotations

from urllib.error import URLError

from app.analyzers.types import UrlProbeResult, UrlProbeSnapshot
from app.analyzers.url_probe_fetch import BROWSER_USER_AGENT, CRAWLER_USER_AGENT, fetch_snapshot
from app.analyzers.url_probe_html import extract_html_signals as _extract_html_signals
from app.analyzers.url_probe_safety import (
    ProbeBlockedError,
    assert_safe_target as _assert_safe_target,
    clean_probe_text,
)


def probe_url(url: str) -> UrlProbeResult:
    result: UrlProbeResult = {
        "performed": False,
        "blocked_reason": None,
        "error": None,
        "browser": {},
        "crawler": {},
    }

    try:
        browser_snapshot = fetch_snapshot(url, user_agent=BROWSER_USER_AGENT)
    except ProbeBlockedError as exc:
        result["blocked_reason"] = str(exc)
        return result
    except URLError as exc:
        result["error"] = f"브라우저 프로브 실패({exc.reason})"
        return result

    result["performed"] = True
    result["browser"] = browser_snapshot

    try:
        result["crawler"] = fetch_snapshot(url, user_agent=CRAWLER_USER_AGENT)
    except (ProbeBlockedError, URLError) as exc:
        crawler_error: UrlProbeSnapshot = {"error": clean_probe_text(str(exc), limit=120)}
        result["crawler"] = crawler_error

    return result


__all__ = [
    "ProbeBlockedError",
    "_assert_safe_target",
    "_extract_html_signals",
    "probe_url",
]
