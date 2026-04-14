from __future__ import annotations

from email.message import EmailMessage

from app.analyzers.email_body_extraction import extract_email_body_signals
from app.analyzers.email_body_rules import score_email_body_signals
from app.analyzers.types import EmailBodyAnalysisResult, EmailBodyExtractionResult


def analyze_email_body_content(
    *,
    text: str,
    urls: list[str] | None = None,
    html_present: bool = False,
    anchor_pairs: list[tuple[str, str]] | None = None,
    form_actions: list[str] | None = None,
    meta_refresh_urls: list[str] | None = None,
    script_redirect_urls: list[str] | None = None,
) -> EmailBodyAnalysisResult:
    extraction: EmailBodyExtractionResult = {
        "text": text or "",
        "urls": list(urls or []),
        "anchor_pairs": list(anchor_pairs or []),
        "form_actions": list(form_actions or []),
        "meta_refresh_urls": list(meta_refresh_urls or []),
        "script_redirect_urls": list(script_redirect_urls or []),
        "html_present": html_present,
    }
    return score_email_body_signals(extraction)


def analyze_email_body(message: EmailMessage) -> EmailBodyAnalysisResult:
    extraction = extract_email_body_signals(message)
    return score_email_body_signals(extraction)
