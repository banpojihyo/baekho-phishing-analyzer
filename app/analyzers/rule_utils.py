from __future__ import annotations

from app.analyzers.types import RuleHit


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def build_rule_hit(
    *,
    rule_id: str,
    title: str,
    description: str,
    score: int,
    evidence: str,
) -> RuleHit:
    return {
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "score": score,
        "severity": severity_from_score(score),
        "evidence": evidence,
    }
