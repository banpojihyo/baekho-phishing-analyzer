from __future__ import annotations

from app.analyzers.rule_utils import build_rule_hit
from app.analyzers.types import EmailHeaderAnalysisResult, EmailHeaderSignals, RuleHit


URGENT_TERMS = {
    "urgent",
    "immediately",
    "verify",
    "security alert",
    "긴급",
    "즉시",
    "인증",
    "reset",
}


def score_header_signals(signals: EmailHeaderSignals) -> EmailHeaderAnalysisResult:
    score = 0
    evidence: list[str] = []
    matched_rules: list[RuleHit] = []

    def add_rule(*, rule_id: str, title: str, description: str, rule_score: int, evidence_text: str) -> None:
        nonlocal score
        score += rule_score
        evidence.append(evidence_text)
        matched_rules.append(
            build_rule_hit(
                rule_id=rule_id,
                title=title,
                description=description,
                score=rule_score,
                evidence=evidence_text,
            )
        )

    if (
        signals["resolved_reply_org_domain"]
        and signals["resolved_from_org_domain"]
        and signals["resolved_reply_org_domain"] != signals["resolved_from_org_domain"]
    ):
        add_rule(
            rule_id="header.reply_to_mismatch",
            title="From/Reply-To 도메인 불일치",
            description=(
                "표시된 발신자와 실제 회신 유도 대상 조직 도메인이 다릅니다."
                if not signals["likely_legitimate_relay"]
                else "발송 대행 인프라와 실제 브랜드 회신 주소가 분리된 구조일 수 있습니다."
            ),
            rule_score=8 if signals["likely_legitimate_relay"] else 20,
            evidence_text=(
                "From 도메인과 Reply-To 도메인 불일치"
                if not signals["likely_legitimate_relay"]
                else "From 도메인과 Reply-To 도메인 불일치(발송 대행 가능성)"
            ),
        )

    if not signals["has_message_id"]:
        add_rule(
            rule_id="header.missing_message_id",
            title="Message-ID 누락",
            description="정상 메일에 일반적으로 포함되는 Message-ID 헤더가 없습니다.",
            rule_score=8,
            evidence_text="Message-ID 누락",
        )

    if signals["received_count"] <= 0:
        add_rule(
            rule_id="header.missing_received_chain",
            title="Received 헤더 정보 부족",
            description="전달 경로를 판단할 수 있는 Received 헤더가 부족합니다.",
            rule_score=5,
            evidence_text="Received 헤더 정보 부족",
        )

    hit_terms = [term for term in URGENT_TERMS if term in signals["normalized_subject"]]
    if hit_terms:
        add_rule(
            rule_id="header.urgent_subject_terms",
            title="제목 긴급/사회공학 표현",
            description="제목에 긴급 대응이나 인증·결제를 유도하는 표현이 포함되어 있습니다.",
            rule_score=min(18, len(hit_terms) * 6),
            evidence_text=f"제목에 긴급/사회공학 유도 표현 포함({', '.join(sorted(hit_terms))})",
        )

    if signals["detected_contexts"] and (hit_terms or signals["strong_auth_failure_detected"]):
        add_rule(
            rule_id="header.business_context_subject",
            title="업무형 사칭 제목 문맥",
            description="제목에 계정 인증, 결제, 배송, 발주/견적 같은 업무 문맥이 함께 나타납니다.",
            rule_score=min(10, 4 + len(signals["detected_contexts"]) * 2),
            evidence_text=f"제목에 업무형 사칭 문맥 포함({', '.join(signals['detected_contexts'])})",
        )

    if signals["has_auth_results"]:
        if signals["spf_fail"]:
            add_rule(
                rule_id="header.spf_fail",
                title="SPF 실패",
                description="발신 도메인 정책과 실제 SMTP 발신 정보가 맞지 않습니다.",
                rule_score=10 if signals["auth_failure_count"] == 1 else 25,
                evidence_text="SPF 실패",
            )
        if signals["dkim_fail"]:
            add_rule(
                rule_id="header.dkim_fail",
                title="DKIM 실패",
                description="서명 검증에 실패해 발신 무결성을 신뢰하기 어렵습니다.",
                rule_score=20,
                evidence_text="DKIM 실패",
            )
        if signals["dmarc_fail"]:
            add_rule(
                rule_id="header.dmarc_fail",
                title="DMARC 실패",
                description="도메인 정렬 정책을 만족하지 못했습니다.",
                rule_score=20,
                evidence_text="DMARC 실패",
            )
    else:
        add_rule(
            rule_id="header.missing_auth_results",
            title="Authentication-Results 헤더 부재",
            description="인증 결과 헤더가 없어 발신 검증 단서를 얻기 어렵습니다.",
            rule_score=5,
            evidence_text="Authentication-Results 헤더 부재",
        )

    score = min(100, score)
    return {
        "from": signals["from_value"],
        "reply_to": signals["reply_to_value"],
        "from_domain": signals["resolved_from_domain"],
        "reply_to_domain": signals["resolved_reply_domain"],
        "subject": signals["subject"],
        "score": score,
        "evidence": evidence if evidence else ["헤더 기준 뚜렷한 의심 신호 없음"],
        "matched_rules": matched_rules,
        "detected_contexts": signals["detected_contexts"],
    }
