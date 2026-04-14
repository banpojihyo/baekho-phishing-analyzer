from __future__ import annotations

from urllib.parse import urlparse

from app.analyzers.context_detection import detect_business_contexts
from app.analyzers.rule_utils import severity_from_score
from app.analyzers.types import UrlAnalysisResult, UrlProbeResult
from app.analyzers.url_probe_client import resolve_probe_result
from app.analyzers.url_probe_rules import apply_probe_url_rules
from app.analyzers.url_scoring_support import (
    UrlScoreAccumulator,
    build_invalid_url_result,
    hostname_is_ip,
)
from app.analyzers.url_static_rules import apply_static_url_rules


def analyze_url(
    url: str,
    *,
    enable_probe: bool = False,
    probe_result: UrlProbeResult | None = None,
) -> UrlAnalysisResult:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except ValueError as exc:
        return build_invalid_url_result(url, str(exc))

    hostname = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path or ''}?{parsed.query or ''}".lower()
    hostname_uses_ip = hostname_is_ip(hostname) if hostname else False
    detected_contexts = detect_business_contexts(path_and_query)
    accumulator = UrlScoreAccumulator()

    apply_static_url_rules(
        accumulator=accumulator,
        original_url=url,
        parsed=parsed,
        hostname=hostname,
        hostname_is_ip=hostname_uses_ip,
        path_and_query=path_and_query,
        detected_contexts=detected_contexts,
    )

    if probe_result is None and enable_probe:
        probe_result = resolve_probe_result(url)

    if probe_result and probe_result.get("performed"):
        apply_probe_url_rules(
            accumulator=accumulator,
            hostname=hostname,
            probe_result=probe_result,
        )

    accumulator.finalize()
    return {
        "url": url,
        "normalized_url": parsed.geturl(),
        "host": hostname,
        "score": accumulator.score,
        "severity": severity_from_score(accumulator.score),
        "evidence": accumulator.evidence if accumulator.evidence else ["뚜렷한 의심 신호 없음"],
        "matched_rules": accumulator.matched_rules,
        "detected_contexts": detected_contexts,
        "probe": probe_result or {"performed": False},
    }
