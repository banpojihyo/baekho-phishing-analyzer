from __future__ import annotations

from email.message import EmailMessage

from app.analyzers.email_header_extraction import extract_header_signals, extract_message_header_signals
from app.analyzers.email_header_rules import score_header_signals
from app.analyzers.types import EmailHeaderAnalysisResult


def analyze_header_fields(
    *,
    from_value: str = "",
    reply_to_value: str = "",
    from_domain: str = "",
    reply_domain: str = "",
    subject: str = "",
    auth_results: str = "",
    has_message_id: bool = True,
    received_count: int = 0,
    has_auth_results: bool | None = None,
    spf_fail: bool | None = None,
    dkim_fail: bool | None = None,
    dmarc_fail: bool | None = None,
) -> EmailHeaderAnalysisResult:
    signals = extract_header_signals(
        from_value=from_value,
        reply_to_value=reply_to_value,
        from_domain=from_domain,
        reply_domain=reply_domain,
        subject=subject,
        auth_results=auth_results,
        has_message_id=has_message_id,
        received_count=received_count,
        has_auth_results=has_auth_results,
        spf_fail=spf_fail,
        dkim_fail=dkim_fail,
        dmarc_fail=dmarc_fail,
    )
    return score_header_signals(signals)


def analyze_email_headers(message: EmailMessage) -> EmailHeaderAnalysisResult:
    return score_header_signals(extract_message_header_signals(message))

