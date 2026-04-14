from __future__ import annotations

from urllib.parse import urljoin, urlparse

from app.analyzers.url_probe_safety import ALLOWED_SCHEMES, site_key


def canonicalize_reference(reference: str, *, base_url: str) -> str | None:
    if not reference:
        return None
    if reference.strip().startswith("#"):
        return None

    joined = urljoin(base_url, reference.strip())
    parsed = urlparse(joined)
    if parsed.scheme not in {"", "http", "https"}:
        return None
    if parsed.scheme and parsed.scheme not in ALLOWED_SCHEMES:
        return None
    if not parsed.netloc and not parsed.path:
        return None
    return joined


def count_external_references(references: list[str], *, base_url: str) -> tuple[int, int]:
    base_host = (urlparse(base_url).hostname or "").lower()
    base_key = site_key(base_host)
    total = 0
    external = 0

    for reference in references:
        absolute = canonicalize_reference(reference, base_url=base_url)
        if not absolute:
            continue

        parsed = urlparse(absolute)
        if parsed.scheme and parsed.scheme not in ALLOWED_SCHEMES:
            continue

        total += 1
        ref_host = (parsed.hostname or "").lower()
        if ref_host and site_key(ref_host) != base_key:
            external += 1

    return total, external


def count_offdomain_form_actions(form_actions: list[str], *, base_url: str) -> int:
    base_host = (urlparse(base_url).hostname or "").lower()
    base_key = site_key(base_host)
    suspicious_count = 0

    for action in form_actions:
        if not action:
            continue

        absolute = urljoin(base_url, action)
        parsed = urlparse(absolute)
        if parsed.scheme and parsed.scheme not in ALLOWED_SCHEMES:
            suspicious_count += 1
            continue

        action_host = (parsed.hostname or "").lower()
        if action_host and site_key(action_host) != base_key:
            suspicious_count += 1

    return suspicious_count
