from __future__ import annotations

from app.analyzers.explainable_report import build_explainable_report, to_severity
from app.analyzers.risk_fusion import combine_component_scores
from app.analyzers.types import (
    AttachmentAnalysisAggregate,
    EMLAnalysisResult,
    EmailBodyAnalysisResult,
    EmailHeaderAnalysisResult,
    ExplainableReport,
    UrlAnalysisResult,
    UrlScoringOutput,
)


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def build_url_scoring_output(url_results: list[UrlAnalysisResult]) -> UrlScoringOutput:
    top_url_result = max(url_results, key=lambda item: item["score"]) if url_results else None
    return {
        "top_risky_url": top_url_result["url"] if top_url_result else None,
        "top_risky_score": top_url_result["score"] if top_url_result else 0,
        "url_results": url_results,
    }


def collect_eml_evidence(
    *,
    header_result: EmailHeaderAnalysisResult,
    body_result: EmailBodyAnalysisResult,
    top_url_result: UrlAnalysisResult | None,
    attachment_result: AttachmentAnalysisAggregate,
) -> list[str]:
    evidence = [f"[Header] {item}" for item in header_result["evidence"]]
    if body_result["score"] > 0:
        evidence.extend(f"[Body] {item}" for item in body_result["evidence"])
    if top_url_result:
        evidence.extend(f"[URL] {item}" for item in top_url_result["evidence"])
    if attachment_result["risky_attachment_count"]:
        evidence.extend(f"[Attachment] {item}" for item in attachment_result["evidence"])
    return _unique(evidence)


def collect_eml_context_tags(
    *,
    header_result: EmailHeaderAnalysisResult,
    body_result: EmailBodyAnalysisResult,
    top_url_result: UrlAnalysisResult | None,
) -> list[str]:
    return _unique(
        [
            *header_result.get("detected_contexts", []),
            *body_result.get("detected_contexts", []),
            *(top_url_result.get("detected_contexts", []) if top_url_result else []),
        ]
    )


def build_eml_analysis_response(
    *,
    filename: str,
    extracted_urls: list[str],
    header_result: EmailHeaderAnalysisResult,
    body_result: EmailBodyAnalysisResult,
    url_results: list[UrlAnalysisResult],
    attachment_result: AttachmentAnalysisAggregate,
) -> EMLAnalysisResult:
    url_output = build_url_scoring_output(url_results)
    top_url_result = max(url_results, key=lambda item: item["score"]) if url_results else None
    final_score = combine_component_scores(
        header_score=header_result["score"],
        body_score=body_result["score"],
        url_score=top_url_result["score"] if top_url_result else None,
        attachment_score=attachment_result["score"] if attachment_result["attachment_count"] else None,
    )
    severity = to_severity(final_score)
    evidence = collect_eml_evidence(
        header_result=header_result,
        body_result=body_result,
        top_url_result=top_url_result,
        attachment_result=attachment_result,
    )
    context_tags = collect_eml_context_tags(
        header_result=header_result,
        body_result=body_result,
        top_url_result=top_url_result,
    )
    explainable: ExplainableReport = build_explainable_report(final_score, evidence, context_tags=context_tags)

    return {
        "input_type": "eml",
        "filename": filename,
        "extracted_urls": extracted_urls,
        "final_risk_score": final_score,
        "severity": severity,
        "summary": explainable["summary"],
        "mvp_outputs": {
            "email_header_risk_check": header_result,
            "email_body_risk_check": body_result,
            "url_suspicion_scoring": url_output,
            "attachment_static_guard": attachment_result,
            "explainable_report_output": explainable,
        },
        "explainable_report": explainable,
    }
