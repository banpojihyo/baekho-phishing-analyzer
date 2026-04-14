from __future__ import annotations

from urllib.error import HTTPError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

from app.analyzers.types import UrlProbeRedirectHop, UrlProbeSnapshot
from app.analyzers.url_probe_html import extract_html_signals
from app.analyzers.url_probe_safety import ProbeBlockedError, assert_safe_target


BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
)
CRAWLER_USER_AGENT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
MAX_REDIRECTS = 4
MAX_HTML_BYTES = 65536
FETCH_TIMEOUT_SECONDS = 5


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


NO_REDIRECT_OPENER = build_opener(NoRedirectHandler())


def open_without_redirect(url: str, *, user_agent: str):
    request = Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cache-Control": "no-cache",
        },
        method="GET",
    )
    try:
        return NO_REDIRECT_OPENER.open(request, timeout=FETCH_TIMEOUT_SECONDS)
    except HTTPError as exc:
        return exc


def fetch_snapshot(url: str, *, user_agent: str) -> UrlProbeSnapshot:
    current_url = url
    redirects: list[UrlProbeRedirectHop] = []

    for _ in range(MAX_REDIRECTS + 1):
        assert_safe_target(current_url)
        response = open_without_redirect(current_url, user_agent=user_agent)
        status_code = response.getcode()
        location = response.headers.get("Location")

        if location and status_code in {301, 302, 303, 307, 308}:
            next_url = urljoin(current_url, location)
            redirects.append(
                {
                    "status_code": status_code,
                    "from_url": current_url,
                    "to_url": next_url,
                }
            )
            current_url = next_url
            response.close()
            continue

        try:
            body = response.read(MAX_HTML_BYTES).decode("utf-8", errors="replace")
        finally:
            response.close()

        return {
            "http_status": status_code,
            "final_url": current_url,
            "redirect_hops": redirects,
            "redirect_hop_count": len(redirects),
            **extract_html_signals(body, base_url=current_url),
        }

    raise ProbeBlockedError("리다이렉트 횟수 제한 초과")
