from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import ParseResult, urlparse

from app.analyzers.rule_utils import build_rule_hit, severity_from_score
from app.analyzers.types import RuleHit, UrlAnalysisResult, UrlProbeResult


@dataclass
class UrlScoreAccumulator:
    score: int = 0
    evidence: list[str] = field(default_factory=list)
    matched_rules: list[RuleHit] = field(default_factory=list)

    def add_rule(
        self,
        *,
        rule_id: str,
        title: str,
        description: str,
        rule_score: int,
        evidence_text: str,
    ) -> None:
        self.score += rule_score
        self.evidence.append(evidence_text)
        self.matched_rules.append(
            build_rule_hit(
                rule_id=rule_id,
                title=title,
                description=description,
                score=rule_score,
                evidence=evidence_text,
            )
        )

    def finalize(self) -> None:
        self.score = min(100, self.score)


def hostname_parts(hostname: str) -> tuple[str, str]:
    parts = hostname.split(".")
    if len(parts) < 2:
        return hostname, ""
    return ".".join(parts[:-1]), parts[-1].lower()


def hostname_is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def has_suspicious_at_sign(parsed: ParseResult) -> bool:
    return bool(parsed.username or parsed.password or "@" in parsed.netloc)


def host_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def build_invalid_url_result(url: str, reason: str) -> UrlAnalysisResult:
    score = 18
    probe: UrlProbeResult = {"performed": False}
    return {
        "url": url,
        "normalized_url": url,
        "host": "",
        "score": score,
        "severity": severity_from_score(score),
        "evidence": [f"URL 파싱 실패({reason})"],
        "matched_rules": [
            build_rule_hit(
                rule_id="url.parse_failure",
                title="URL 파싱 실패",
                description="입력 URL을 정상적으로 파싱하지 못했습니다.",
                score=score,
                evidence=f"URL 파싱 실패({reason})",
            )
        ],
        "detected_contexts": [],
        "probe": probe,
    }
