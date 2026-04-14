from __future__ import annotations

from typing import TypedDict


class RuleHit(TypedDict):
    rule_id: str
    title: str
    description: str
    score: int
    severity: str
    evidence: str


class ExplainableReport(TypedDict):
    summary: str
    risk_snapshot: str
    context_tags: list[str]
    why_risky: list[str]
    recommended_actions: list[str]


class UrlProbeRedirectHop(TypedDict):
    status_code: int
    from_url: str
    to_url: str


class UrlProbeSnapshot(TypedDict, total=False):
    error: str
    http_status: int
    final_url: str
    redirect_hops: list[UrlProbeRedirectHop]
    meta_robots: str
    meta_description: str
    title: str
    client_redirect_url: str | None
    client_redirect_kind: str | None
    redirect_hop_count: int
    form_count: int
    offdomain_form_action_count: int
    password_input_count: int
    iframe_count: int
    hidden_iframe_count: int
    asset_reference_count: int
    external_asset_count: int
    anchor_count: int
    external_anchor_count: int
    suspicious_js_function_count: int
    suspicious_js_functions: list[str]
    suspicious_download_link_count: int


class UrlProbeResult(TypedDict, total=False):
    performed: bool
    blocked_reason: str | None
    error: str | None
    probe_source: str
    browser: UrlProbeSnapshot
    crawler: UrlProbeSnapshot


class UrlAnalysisResult(TypedDict):
    url: str
    normalized_url: str
    host: str
    score: int
    severity: str
    evidence: list[str]
    matched_rules: list[RuleHit]
    detected_contexts: list[str]
    probe: UrlProbeResult


class EmailBodyExtractionResult(TypedDict):
    text: str
    urls: list[str]
    anchor_pairs: list[tuple[str, str]]
    form_actions: list[str]
    meta_refresh_urls: list[str]
    script_redirect_urls: list[str]
    html_present: bool


class EmailBodyAnalysisResult(TypedDict):
    text: str
    urls: list[str]
    score: int
    severity: str
    evidence: list[str]
    matched_rules: list[RuleHit]
    detected_contexts: list[str]
    html_present: bool


class EmailHeaderSignals(TypedDict):
    from_value: str
    reply_to_value: str
    subject: str
    resolved_from_domain: str
    resolved_reply_domain: str
    resolved_from_org_domain: str
    resolved_reply_org_domain: str
    resolved_from_display: str
    resolved_reply_display: str
    normalized_subject: str
    normalized_auth_results: str
    has_message_id: bool
    received_count: int
    has_auth_results: bool
    spf_fail: bool
    dkim_fail: bool
    dmarc_fail: bool
    auth_failure_count: int
    strong_auth_failure_detected: bool
    likely_legitimate_relay: bool
    detected_contexts: list[str]


EmailHeaderAnalysisResult = TypedDict(
    "EmailHeaderAnalysisResult",
    {
        "from": str,
        "reply_to": str,
        "from_domain": str,
        "reply_to_domain": str,
        "subject": str,
        "score": int,
        "evidence": list[str],
        "matched_rules": list[RuleHit],
        "detected_contexts": list[str],
    },
)


class AttachmentAnalysisDetail(TypedDict):
    filename: str
    content_type: str
    size: int
    detected_type: str
    score: int
    severity: str
    evidence: list[str]
    matched_rules: list[RuleHit]


class AttachmentAnalysisAggregate(TypedDict):
    attachment_count: int
    risky_attachment_count: int
    score: int
    severity: str
    evidence: list[str]
    attachments: list[AttachmentAnalysisDetail]
    matched_rules: list[RuleHit]


class UrlScoringOutput(TypedDict):
    top_risky_url: str | None
    top_risky_score: int
    url_results: list[UrlAnalysisResult]


class UrlAnalysisMvpOutputs(TypedDict):
    url_suspicion_scoring: UrlAnalysisResult
    explainable_report_output: ExplainableReport


class UrlAnalysisResponse(TypedDict):
    input_type: str
    url: str
    final_risk_score: int
    severity: str
    summary: str
    mvp_outputs: UrlAnalysisMvpOutputs
    explainable_report: ExplainableReport


class EMLMvpOutputs(TypedDict):
    email_header_risk_check: EmailHeaderAnalysisResult
    email_body_risk_check: EmailBodyAnalysisResult
    url_suspicion_scoring: UrlScoringOutput
    attachment_static_guard: AttachmentAnalysisAggregate
    explainable_report_output: ExplainableReport


class EMLAnalysisResult(TypedDict):
    input_type: str
    filename: str
    extracted_urls: list[str]
    final_risk_score: int
    severity: str
    summary: str
    mvp_outputs: EMLMvpOutputs
    explainable_report: ExplainableReport
