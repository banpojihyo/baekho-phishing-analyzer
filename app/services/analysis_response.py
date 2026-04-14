from __future__ import annotations

from app.analyzers.explainable_report import build_explainable_report, to_severity
from app.analyzers.risk_fusion import combine_component_scores
from app.analyzers.types import UrlAnalysisResponse, UrlAnalysisResult


def build_url_analysis_response(result: UrlAnalysisResult) -> UrlAnalysisResponse:
    final_score = combine_component_scores(url_score=result["score"])
    explainable = build_explainable_report(
        final_score,
        [f"[URL] {e}" for e in result["evidence"]],
        context_tags=result.get("detected_contexts", []),
    )
    return {
        "input_type": "url",
        "url": result["url"],
        "final_risk_score": final_score,
        "severity": to_severity(final_score),
        "summary": explainable["summary"],
        "mvp_outputs": {
            "url_suspicion_scoring": result,
            "explainable_report_output": explainable,
        },
        "explainable_report": explainable,
    }
