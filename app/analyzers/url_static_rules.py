from __future__ import annotations

from urllib.parse import ParseResult

from app.analyzers.url_scoring_support import UrlScoreAccumulator, has_suspicious_at_sign, hostname_parts


SUSPICIOUS_TLDS = {"xyz", "top", "click", "gq", "ml", "cf", "tk", "work", "zip", "review"}
SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "shorturl.at",
    "is.gd",
    "goo.gl",
    "ow.ly",
    "buff.ly",
}
HIGH_RISK_ACTION_TERMS = {"verify", "update", "secure", "login", "password", "reset"}
HOSTNAME_AUTH_CLUSTER_TERMS = {"verify", "secure", "login", "password", "reset", "account", "portal", "auth"}


def apply_static_url_rules(
    *,
    accumulator: UrlScoreAccumulator,
    original_url: str,
    parsed: ParseResult,
    hostname: str,
    hostname_is_ip: bool,
    path_and_query: str,
    detected_contexts: list[str],
) -> None:
    if parsed.scheme != "https":
        accumulator.add_rule(
            rule_id="url.non_https",
            title="HTTPS 미사용",
            description="보안 연결 없이 평문 HTTP를 사용합니다.",
            rule_score=12,
            evidence_text="HTTPS 미사용",
        )

    if len(original_url) > 120:
        accumulator.add_rule(
            rule_id="url.length_excessive",
            title="URL 길이 과도",
            description="매우 긴 URL은 추적 파라미터나 위장 경로를 포함할 가능성이 높습니다.",
            rule_score=20,
            evidence_text="URL 길이 과도(120자 초과)",
        )
    elif len(original_url) > 75:
        accumulator.add_rule(
            rule_id="url.length_long",
            title="URL 길이 길음",
            description="비정상적으로 긴 URL은 위장 목적일 수 있습니다.",
            rule_score=10,
            evidence_text="URL 길이 길음(75자 초과)",
        )

    if has_suspicious_at_sign(parsed):
        accumulator.add_rule(
            rule_id="url.userinfo_at_sign",
            title="사용자정보 형태의 @ 포함",
            description="브랜드명처럼 보이는 앞부분으로 사용자를 속이기 위한 userinfo 패턴일 수 있습니다.",
            rule_score=20,
            evidence_text="사용자정보(userinfo) 형태의 '@' 포함 URL",
        )

    if hostname.startswith("xn--"):
        accumulator.add_rule(
            rule_id="url.punycode_hostname",
            title="Punycode 도메인 사용",
            description="유니코드 도메인을 ASCII로 표현한 Punycode가 포함되어 있습니다.",
            rule_score=25,
            evidence_text="Punycode(유니코드 도메인) 사용",
        )

    if hostname in SHORTENER_DOMAINS:
        accumulator.add_rule(
            rule_id="url.shortener_domain",
            title="단축 URL 도메인 사용",
            description="최종 목적지를 숨기기 쉬운 단축 URL 도메인을 사용합니다.",
            rule_score=15,
            evidence_text="단축 URL 도메인 사용",
        )

    if hostname_is_ip:
        accumulator.add_rule(
            rule_id="url.ip_host",
            title="IP 주소 호스트 사용",
            description="도메인 대신 IP 주소를 직접 호스트로 사용하는 링크입니다.",
            rule_score=30,
            evidence_text="도메인 대신 IP 주소 사용",
        )

    subdomain, tld = hostname_parts(hostname)
    if tld in SUSPICIOUS_TLDS:
        accumulator.add_rule(
            rule_id="url.suspicious_tld",
            title="의심 TLD 사용",
            description="피싱 악용 비중이 상대적으로 높은 TLD를 사용합니다.",
            rule_score=14,
            evidence_text=f"의심 TLD 사용(.{tld})",
        )

    if not hostname_is_ip and subdomain.count(".") >= 2:
        accumulator.add_rule(
            rule_id="url.deep_subdomain",
            title="서브도메인 깊이 과도",
            description="긴 서브도메인 구조로 정상 브랜드처럼 위장할 수 있습니다.",
            rule_score=8,
            evidence_text="서브도메인 깊이 과도",
        )

    if hostname.count("-") >= 3:
        accumulator.add_rule(
            rule_id="url.hyphen_heavy_domain",
            title="하이픈이 많은 도메인",
            description="하이픈이 과도한 도메인은 위장형 랜딩 페이지에서 자주 보입니다.",
            rule_score=8,
            evidence_text="하이픈이 많은 도메인",
        )

    hostname_term_hits = [term for term in HOSTNAME_AUTH_CLUSTER_TERMS if term in hostname]
    if len(hostname_term_hits) >= 2:
        accumulator.add_rule(
            rule_id="url.hostname_auth_cluster",
            title="호스트명에 인증 유도 키워드 다수 포함",
            description="호스트명 자체가 secure, login, verify 같은 인증 유도 키워드를 여러 개 포함합니다.",
            rule_score=12,
            evidence_text=f"호스트명에 인증 유도 키워드 다수 포함({', '.join(sorted(hostname_term_hits))})",
        )

    hit_terms = [term for term in HIGH_RISK_ACTION_TERMS if term in path_and_query]
    if hit_terms:
        accumulator.add_rule(
            rule_id="url.social_engineering_terms",
            title="사회공학 유도 키워드 포함",
            description="인증, 로그인, 비밀번호 재설정처럼 계정 행동을 유도하는 경로 또는 쿼리 문자열을 포함합니다.",
            rule_score=min(18, len(hit_terms) * 6),
            evidence_text=f"사회공학 유도 키워드 포함({', '.join(sorted(hit_terms))})",
        )

    if detected_contexts and accumulator.score > 0:
        accumulator.add_rule(
            rule_id="url.business_context_path",
            title="업무형 유도 문맥 포함",
            description="URL 경로 또는 쿼리에 계정 인증, 결제, 배송, 발주/견적 같은 문맥이 포함되어 있습니다.",
            rule_score=min(10, 4 + len(detected_contexts) * 2),
            evidence_text=f"URL에 업무형 유도 문맥 포함({', '.join(detected_contexts)})",
        )
