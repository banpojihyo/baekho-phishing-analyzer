from __future__ import annotations

from pydantic import BaseModel, Field


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="분석할 URL")


class RuleHitModel(BaseModel):
    rule_id: str = ""
    title: str = ""
    description: str = ""
    score: int = 0
    severity: str = "low"
    evidence: str = ""


class ExplainableReportModel(BaseModel):
    summary: str = ""
    risk_snapshot: str = ""
    context_tags: list[str] = Field(default_factory=list)
    why_risky: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class UrlProbeRedirectHopModel(BaseModel):
    status_code: int = 0
    from_url: str = ""
    to_url: str = ""


class UrlProbeSnapshotModel(BaseModel):
    error: str | None = None
    http_status: int | None = None
    final_url: str | None = None
    redirect_hops: list[UrlProbeRedirectHopModel] = Field(default_factory=list)
    redirect_hop_count: int | None = None
    meta_robots: str | None = None
    meta_description: str | None = None
    title: str | None = None
    client_redirect_url: str | None = None
    client_redirect_kind: str | None = None
    form_count: int | None = None
    offdomain_form_action_count: int | None = None
    password_input_count: int | None = None
    iframe_count: int | None = None
    hidden_iframe_count: int | None = None
    asset_reference_count: int | None = None
    external_asset_count: int | None = None
    anchor_count: int | None = None
    external_anchor_count: int | None = None
    suspicious_js_function_count: int | None = None
    suspicious_js_functions: list[str] = Field(default_factory=list)
    suspicious_download_link_count: int | None = None


class UrlProbeResultModel(BaseModel):
    performed: bool = False
    blocked_reason: str | None = None
    error: str | None = None
    probe_source: str | None = None
    browser: UrlProbeSnapshotModel = Field(default_factory=UrlProbeSnapshotModel)
    crawler: UrlProbeSnapshotModel = Field(default_factory=UrlProbeSnapshotModel)


class UrlAnalysisResultModel(BaseModel):
    url: str = ""
    normalized_url: str = ""
    host: str = ""
    score: int = 0
    severity: str = "low"
    evidence: list[str] = Field(default_factory=list)
    matched_rules: list[RuleHitModel] = Field(default_factory=list)
    detected_contexts: list[str] = Field(default_factory=list)
    probe: UrlProbeResultModel = Field(default_factory=UrlProbeResultModel)


class EmailBodyAnalysisModel(BaseModel):
    text: str = ""
    urls: list[str] = Field(default_factory=list)
    score: int = 0
    severity: str = "low"
    evidence: list[str] = Field(default_factory=list)
    matched_rules: list[RuleHitModel] = Field(default_factory=list)
    detected_contexts: list[str] = Field(default_factory=list)
    html_present: bool = False


class EmailHeaderAnalysisModel(BaseModel):
    from_: str = Field(default="", alias="from")
    reply_to: str = ""
    from_domain: str = ""
    reply_to_domain: str = ""
    subject: str = ""
    score: int = 0
    evidence: list[str] = Field(default_factory=list)
    matched_rules: list[RuleHitModel] = Field(default_factory=list)
    detected_contexts: list[str] = Field(default_factory=list)


class AttachmentAnalysisDetailModel(BaseModel):
    filename: str = ""
    content_type: str = "unknown"
    size: int = 0
    detected_type: str = "unknown"
    score: int = 0
    severity: str = "low"
    evidence: list[str] = Field(default_factory=list)
    matched_rules: list[RuleHitModel] = Field(default_factory=list)


class AttachmentAnalysisAggregateModel(BaseModel):
    attachment_count: int = 0
    risky_attachment_count: int = 0
    score: int = 0
    severity: str = "low"
    evidence: list[str] = Field(default_factory=list)
    attachments: list[AttachmentAnalysisDetailModel] = Field(default_factory=list)
    matched_rules: list[RuleHitModel] = Field(default_factory=list)


class UrlScoringOutputModel(BaseModel):
    top_risky_url: str | None = None
    top_risky_score: int = 0
    url_results: list[UrlAnalysisResultModel] = Field(default_factory=list)


class URLAnalysisMvpOutputsModel(BaseModel):
    url_suspicion_scoring: UrlAnalysisResultModel = Field(default_factory=UrlAnalysisResultModel)
    explainable_report_output: ExplainableReportModel = Field(default_factory=ExplainableReportModel)


class EMLMvpOutputsModel(BaseModel):
    email_header_risk_check: EmailHeaderAnalysisModel = Field(default_factory=EmailHeaderAnalysisModel)
    email_body_risk_check: EmailBodyAnalysisModel = Field(default_factory=EmailBodyAnalysisModel)
    url_suspicion_scoring: UrlScoringOutputModel = Field(default_factory=UrlScoringOutputModel)
    attachment_static_guard: AttachmentAnalysisAggregateModel = Field(default_factory=AttachmentAnalysisAggregateModel)
    explainable_report_output: ExplainableReportModel = Field(default_factory=ExplainableReportModel)


class URLAnalysisResponse(BaseModel):
    input_type: str = "url"
    url: str = ""
    final_risk_score: int = 0
    severity: str = "low"
    summary: str = ""
    mvp_outputs: URLAnalysisMvpOutputsModel = Field(default_factory=URLAnalysisMvpOutputsModel)
    explainable_report: ExplainableReportModel = Field(default_factory=ExplainableReportModel)


class EMLAnalysisResponse(BaseModel):
    input_type: str = "eml"
    filename: str = ""
    extracted_urls: list[str] = Field(default_factory=list)
    final_risk_score: int = 0
    severity: str = "low"
    summary: str = ""
    mvp_outputs: EMLMvpOutputsModel = Field(default_factory=EMLMvpOutputsModel)
    explainable_report: ExplainableReportModel = Field(default_factory=ExplainableReportModel)
