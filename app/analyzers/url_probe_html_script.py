from __future__ import annotations

import re
from urllib.parse import urljoin


SUSPICIOUS_JS_FUNCTION_PATTERNS = {
    "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
    "unescape": re.compile(r"\bunescape\s*\(", re.IGNORECASE),
    "fromCharCode": re.compile(r"\bfromCharCode\s*\(", re.IGNORECASE),
    "document.write": re.compile(r"\bdocument\.write\s*\(", re.IGNORECASE),
    "atob": re.compile(r"\batob\s*\(", re.IGNORECASE),
}
META_REFRESH_URL_PATTERN = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)
JS_REDIRECT_PATTERNS = [
    re.compile(r"""window\.location\.href\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    re.compile(r"""location\.href\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    re.compile(r"""location\.replace\(\s*['"]([^'"]+)['"]\s*\)""", re.IGNORECASE),
    re.compile(r"""location\.assign\(\s*['"]([^'"]+)['"]\s*\)""", re.IGNORECASE),
]


def count_suspicious_js_functions(html: str) -> tuple[int, list[str]]:
    hits: list[str] = []
    total = 0
    for label, pattern in SUSPICIOUS_JS_FUNCTION_PATTERNS.items():
        count = len(pattern.findall(html))
        if count:
            total += count
            hits.append(f"{label} x{count}")
    return total, hits


def extract_client_redirect(html: str, base_url: str) -> tuple[str | None, str | None]:
    lower_html = html.lower()
    if "http-equiv" in lower_html and "refresh" in lower_html:
        match = META_REFRESH_URL_PATTERN.search(html)
        if match:
            return urljoin(base_url, match.group(1).strip()), "meta_refresh"

    for pattern in JS_REDIRECT_PATTERNS:
        match = pattern.search(html)
        if match:
            return urljoin(base_url, match.group(1).strip()), "javascript"

    return None, None
