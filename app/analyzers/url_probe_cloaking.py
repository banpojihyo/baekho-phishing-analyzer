from __future__ import annotations

from app.analyzers.types import UrlProbeSnapshot


def probe_indicates_cloaking(browser_snapshot: UrlProbeSnapshot, crawler_snapshot: UrlProbeSnapshot) -> bool:
    browser_robots = (browser_snapshot.get("meta_robots") or "").lower()
    crawler_robots = (crawler_snapshot.get("meta_robots") or "").lower()
    browser_title = (browser_snapshot.get("title") or "").strip()
    crawler_title = (crawler_snapshot.get("title") or "").strip()
    browser_redirect_url = browser_snapshot.get("client_redirect_url")

    browser_blocks_indexing = "noindex" in browser_robots or "nofollow" in browser_robots
    crawler_allows_indexing = "index" in crawler_robots or "follow" in crawler_robots

    if browser_blocks_indexing and crawler_allows_indexing:
        return True
    if browser_redirect_url and crawler_title and browser_title != crawler_title:
        return True
    if not browser_title and crawler_title and (browser_redirect_url or browser_blocks_indexing):
        return True
    return False
