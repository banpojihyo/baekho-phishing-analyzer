from __future__ import annotations

from app.analyzers.context_detection import detect_business_contexts
from app.analyzers.email_body_extraction import find_display_urls, hostname
from app.analyzers.rule_utils import build_rule_hit, severity_from_score
from app.analyzers.types import EmailBodyAnalysisResult, EmailBodyExtractionResult, RuleHit


BODY_HIGH_RISK_ACTION_TERMS = {
    "verify",
    "login",
    "password",
    "reset",
    "인증",
    "로그인",
    "비밀번호",
    "재설정",
    "즉시",
}


def _preview(items: list[str]) -> str:
    return ", ".join(list(dict.fromkeys(items))[:2])


def _append_rule(
    *,
    matched_rules: list[RuleHit],
    evidence: list[str],
    score_parts: list[int],
    rule_id: str,
    title: str,
    description: str,
    score: int,
    evidence_text: str,
) -> None:
    score_parts.append(score)
    evidence.append(evidence_text)
    matched_rules.append(
        build_rule_hit(
            rule_id=rule_id,
            title=title,
            description=description,
            score=score,
            evidence=evidence_text,
        )
    )


def score_email_body_signals(extraction: EmailBodyExtractionResult) -> EmailBodyAnalysisResult:
    combined_text = extraction["text"]
    urls = extraction["urls"]
    anchor_pairs = extraction["anchor_pairs"]
    form_actions = extraction["form_actions"]
    meta_refresh_urls = extraction["meta_refresh_urls"]
    script_redirect_urls = extraction["script_redirect_urls"]

    matched_rules: list[RuleHit] = []
    evidence: list[str] = []
    score_parts: list[int] = []

    mismatches: list[str] = []
    for href, visible_text in anchor_pairs:
        visible_urls = find_display_urls(visible_text)
        if not visible_urls:
            continue
        actual_host = hostname(href)
        for visible_url in visible_urls:
            visible_host = hostname(visible_url)
            if visible_host and actual_host and visible_host != actual_host:
                mismatches.append(f"{visible_host} -> {actual_host}")

    if mismatches:
        preview = _preview(mismatches)
        _append_rule(
            matched_rules=matched_rules,
            evidence=evidence,
            score_parts=score_parts,
            rule_id="body.anchor_domain_mismatch",
            title="링크 표시 텍스트와 실제 이동 도메인 불일치",
            description="본문에 보이는 링크 도메인과 실제 href 도메인이 다릅니다.",
            score=18,
            evidence_text=f"표시 링크와 실제 이동 도메인 불일치({preview})",
        )

    if form_actions:
        preview = _preview(form_actions)
        _append_rule(
            matched_rules=matched_rules,
            evidence=evidence,
            score_parts=score_parts,
            rule_id="body.form_action_external",
            title="HTML form action 존재",
            description="본문 또는 HTML 첨부에 외부 전송 대상 form action이 포함되어 있습니다.",
            score=16,
            evidence_text=f"본문/HTML에 외부 form action 존재({preview})",
        )

    if meta_refresh_urls:
        preview = _preview(meta_refresh_urls)
        _append_rule(
            matched_rules=matched_rules,
            evidence=evidence,
            score_parts=score_parts,
            rule_id="body.meta_refresh_redirect",
            title="Meta refresh 리다이렉트",
            description="HTML 본문에 meta refresh 기반 자동 이동이 포함되어 있습니다.",
            score=14,
            evidence_text=f"meta refresh 기반 자동 이동 포함({preview})",
        )

    if script_redirect_urls:
        preview = _preview(script_redirect_urls)
        _append_rule(
            matched_rules=matched_rules,
            evidence=evidence,
            score_parts=score_parts,
            rule_id="body.javascript_redirect",
            title="JavaScript 리다이렉트",
            description="HTML 본문에 JavaScript 기반 자동 이동 코드가 포함되어 있습니다.",
            score=14,
            evidence_text=f"JavaScript 리다이렉트 코드 포함({preview})",
        )

    lowered_text = combined_text.lower()
    matched_terms = [term for term in BODY_HIGH_RISK_ACTION_TERMS if term in lowered_text]
    matched_contexts = detect_business_contexts(combined_text)
    if matched_terms:
        term_score = min(12, len(matched_terms) * 3)
        _append_rule(
            matched_rules=matched_rules,
            evidence=evidence,
            score_parts=score_parts,
            rule_id="body.social_engineering_terms",
            title="본문에 사회공학 유도 표현 포함",
            description="본문에 인증, 로그인, 비밀번호 재설정처럼 계정 행동을 유도하는 표현이 포함되어 있습니다.",
            score=term_score,
            evidence_text=f"본문에 사회공학 유도 표현 포함({', '.join(sorted(matched_terms))})",
        )

    has_structural_signal = bool(mismatches or form_actions or meta_refresh_urls or script_redirect_urls)
    if matched_contexts and (matched_terms or has_structural_signal):
        context_score = min(12, 4 + len(matched_contexts) * 3)
        _append_rule(
            matched_rules=matched_rules,
            evidence=evidence,
            score_parts=score_parts,
            rule_id="body.business_context_lure",
            title="업무형 사칭 문맥 추정",
            description="본문에 계정 인증, 결제, 배송, 발주/견적 같은 실제 업무 문맥이 함께 나타납니다.",
            score=context_score,
            evidence_text=f"업무형 사칭 문맥 추정({', '.join(matched_contexts)})",
        )

    score = min(100, sum(score_parts))
    return {
        "text": combined_text,
        "urls": urls,
        "score": score,
        "severity": severity_from_score(score),
        "evidence": evidence if evidence else ["뚜렷한 본문/HTML 유도 신호 없음"],
        "matched_rules": matched_rules,
        "detected_contexts": matched_contexts,
        "html_present": extraction["html_present"],
    }
