from __future__ import annotations

from app.analyzers.types import UrlProbeResult
from app.analyzers.url_probe_cloaking import probe_indicates_cloaking
from app.analyzers.url_probe_rule_inputs import ProbeRuleSignals, extract_probe_rule_signals
from app.analyzers.url_scoring_support import UrlScoreAccumulator, host_from_url


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def _apply_redirect_rules(
    *,
    accumulator: UrlScoreAccumulator,
    hostname: str,
    signals: ProbeRuleSignals,
) -> None:
    if signals.client_redirect_url:
        redirect_label = "JavaScript" if signals.client_redirect_kind == "javascript" else "meta refresh"
        accumulator.add_rule(
            rule_id="url.client_side_redirect",
            title="클라이언트 리다이렉트 탐지",
            description="랜딩 페이지 본문에서 즉시 다른 주소로 보내는 스크립트 또는 meta refresh가 확인됐습니다.",
            rule_score=28,
            evidence_text=f"{redirect_label} 기반 클라이언트 리다이렉트 탐지",
        )

        redirect_host = host_from_url(signals.client_redirect_url)
        if redirect_host and redirect_host != hostname:
            accumulator.add_rule(
                rule_id="url.external_domain_redirect",
                title="다른 도메인으로 즉시 이동",
                description="현재 랜딩 페이지가 본문 스크립트나 meta refresh로 외부 도메인 이동을 유도합니다.",
                rule_score=20,
                evidence_text=f"클라이언트 리다이렉트가 다른 도메인({redirect_host})으로 이동",
            )

    if signals.redirect_hop_count >= 2:
        accumulator.add_rule(
            rule_id="url.multi_hop_redirect",
            title="리다이렉트 단계 과다",
            description="최종 랜딩 전까지 여러 번의 이동을 거치면 목적지 숨김 가능성이 커집니다.",
            rule_score=min(18, 8 + (signals.redirect_hop_count - 1) * 4),
            evidence_text=f"리다이렉트 단계 과다({signals.redirect_hop_count}회)",
        )


def _apply_content_rules(
    *,
    accumulator: UrlScoreAccumulator,
    signals: ProbeRuleSignals,
) -> None:
    if signals.offdomain_form_action_count:
        accumulator.add_rule(
            rule_id="url.offdomain_form_action",
            title="폼 제출 대상이 다른 사이트",
            description="랜딩 페이지의 입력 폼이 현재 사이트가 아닌 다른 도메인 또는 비표준 스킴으로 전송됩니다.",
            rule_score=min(36, 24 + (signals.offdomain_form_action_count - 1) * 6),
            evidence_text=f"다른 사이트로 전송되는 form action 탐지({signals.offdomain_form_action_count}건)",
        )

    if signals.hidden_iframe_count:
        accumulator.add_rule(
            rule_id="url.hidden_iframe",
            title="숨김 iframe 탐지",
            description="보이지 않는 iframe은 추가 랜딩 로드나 추적, 우회성 스크립트 삽입에 악용될 수 있습니다.",
            rule_score=min(24, 14 + signals.hidden_iframe_count * 4),
            evidence_text=f"숨김 iframe 탐지({signals.hidden_iframe_count}개)",
        )

    if signals.suspicious_js_function_count >= 2:
        functions_label = ", ".join(signals.suspicious_js_functions[:3]) or "eval/unescape 계열"
        accumulator.add_rule(
            rule_id="url.suspicious_js_functions",
            title="의심스러운 JavaScript 함수 사용",
            description="난독화나 클라이언트 측 우회를 위해 자주 쓰이는 JavaScript 함수 패턴이 다수 확인됐습니다.",
            rule_score=min(16, 8 + signals.suspicious_js_function_count * 2),
            evidence_text=f"의심 JS 함수 사용({functions_label})",
        )


def _apply_ratio_rules(
    *,
    accumulator: UrlScoreAccumulator,
    signals: ProbeRuleSignals,
) -> None:
    external_asset_ratio = _ratio(signals.external_asset_count, signals.asset_reference_count)
    if (
        signals.asset_reference_count >= 4
        and external_asset_ratio >= 0.75
        and (
            signals.offdomain_form_action_count
            or signals.hidden_iframe_count
            or signals.suspicious_js_function_count >= 2
        )
    ):
        accumulator.add_rule(
            rule_id="url.external_asset_ratio_high",
            title="외부 리소스 의존도 높음",
            description="랜딩 페이지의 주요 리소스가 다른 사이트에 과도하게 의존하면 위장 랜딩이나 임시 조립형 페이지일 수 있습니다.",
            rule_score=12,
            evidence_text=(
                "외부 리소스 비율 높음"
                f"({signals.external_asset_count}/{signals.asset_reference_count}, {external_asset_ratio:.0%})"
            ),
        )

    external_anchor_ratio = _ratio(signals.external_anchor_count, signals.anchor_count)
    if (
        signals.anchor_count >= 4
        and external_anchor_ratio >= 0.85
        and (
            signals.client_redirect_url
            or signals.redirect_hop_count >= 2
            or signals.suspicious_download_link_count
        )
    ):
        accumulator.add_rule(
            rule_id="url.external_anchor_ratio_high",
            title="외부 이동 링크 비율 과다",
            description="페이지 내 링크 대부분이 다른 사이트로 이어지면 중간 유도 페이지나 트래픽 분산 랜딩일 수 있습니다.",
            rule_score=10,
            evidence_text=(
                "외부 링크 비율 높음"
                f"({signals.external_anchor_count}/{signals.anchor_count}, {external_anchor_ratio:.0%})"
            ),
        )


def _apply_engagement_rules(
    *,
    accumulator: UrlScoreAccumulator,
    signals: ProbeRuleSignals,
) -> None:
    if signals.password_input_count and (
        signals.offdomain_form_action_count
        or signals.hidden_iframe_count
        or signals.suspicious_js_function_count >= 2
    ):
        accumulator.add_rule(
            rule_id="url.password_form_present",
            title="비밀번호 입력 폼과 다른 의심 신호 결합",
            description="로그인·인증 입력 필드가 다른 고위험 신호와 함께 발견돼 계정 탈취 랜딩 가능성이 높습니다.",
            rule_score=14,
            evidence_text=f"비밀번호 입력 필드 탐지({signals.password_input_count}개)",
        )

    if signals.suspicious_download_link_count and (
        signals.client_redirect_url
        or signals.hidden_iframe_count
        or signals.suspicious_js_function_count >= 2
    ):
        accumulator.add_rule(
            rule_id="url.suspicious_download_link",
            title="실행형 다운로드 유도 링크",
            description="페이지에 실행 파일 또는 설치형 확장자로 이어지는 다운로드 링크가 포함돼 있습니다.",
            rule_score=min(16, 10 + signals.suspicious_download_link_count * 2),
            evidence_text=f"실행형 다운로드 링크 탐지({signals.suspicious_download_link_count}건)",
        )


def _apply_cloaking_rule(
    *,
    accumulator: UrlScoreAccumulator,
    signals: ProbeRuleSignals,
) -> None:
    if signals.crawler_snapshot and probe_indicates_cloaking(signals.browser_snapshot, signals.crawler_snapshot):
        accumulator.add_rule(
            rule_id="url.search_result_cloaking",
            title="브라우저/크롤러 응답 차이",
            description="브라우저와 검색엔진 크롤러에 서로 다른 색인 정책 또는 랜딩 동작을 노출할 가능성이 있습니다.",
            rule_score=35,
            evidence_text="브라우저에는 리다이렉트, 크롤러에는 색인용 콘텐츠를 노출",
        )


def apply_probe_url_rules(
    *,
    accumulator: UrlScoreAccumulator,
    hostname: str,
    probe_result: UrlProbeResult,
) -> None:
    signals = extract_probe_rule_signals(probe_result)
    _apply_redirect_rules(
        accumulator=accumulator,
        hostname=hostname,
        signals=signals,
    )
    _apply_content_rules(
        accumulator=accumulator,
        signals=signals,
    )
    _apply_ratio_rules(
        accumulator=accumulator,
        signals=signals,
    )
    _apply_engagement_rules(
        accumulator=accumulator,
        signals=signals,
    )
    _apply_cloaking_rule(
        accumulator=accumulator,
        signals=signals,
    )
