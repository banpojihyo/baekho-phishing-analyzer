from __future__ import annotations

from typing import TYPE_CHECKING

from app.analyzers.attachment_static_single import analyze_attachment
from app.analyzers.attachment_static_support import unique_items, unique_rule_hits
from app.analyzers.rule_utils import severity_from_score
from app.analyzers.types import AttachmentAnalysisAggregate, RuleHit

if TYPE_CHECKING:
    from app.analyzers.attachment_static import AttachmentArtifact


def analyze_attachments(artifacts: list["AttachmentArtifact"]) -> AttachmentAnalysisAggregate:
    if not artifacts:
        return {
            "attachment_count": 0,
            "risky_attachment_count": 0,
            "score": 0,
            "severity": "low",
            "evidence": ["첨부파일 없음"],
            "attachments": [],
            "matched_rules": [],
        }

    details = [analyze_attachment(artifact) for artifact in artifacts]
    risky_details = [detail for detail in details if detail["score"] > 0]
    risky_attachment_count = len(risky_details)

    if risky_details:
        top_score = max(detail["score"] for detail in risky_details)
        score = min(100, top_score + max(0, risky_attachment_count - 1) * 5)
        evidence: list[str] = []
        aggregated_rules: list[RuleHit] = []
        for detail in risky_details:
            for reason in detail["evidence"][:2]:
                evidence.append(f"{detail['filename']}: {reason}")
            for rule in detail.get("matched_rules", []):
                aggregated_rules.append(
                    {
                        **rule,
                        "evidence": f"{detail['filename']}: {rule['evidence']}",
                    }
                )
        merged_evidence = unique_items(evidence)
    else:
        score = 0
        merged_evidence = ["첨부파일은 있으나 뚜렷한 고위험 정적 신호는 제한적"]
        aggregated_rules = []

    return {
        "attachment_count": len(details),
        "risky_attachment_count": risky_attachment_count,
        "score": score,
        "severity": severity_from_score(score),
        "evidence": merged_evidence,
        "attachments": details,
        "matched_rules": unique_rule_hits(aggregated_rules),
    }
