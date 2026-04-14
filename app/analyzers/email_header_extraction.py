from __future__ import annotations

from email.message import EmailMessage
from email.utils import parseaddr

from app.analyzers.context_detection import detect_business_contexts
from app.analyzers.types import EmailHeaderSignals


COMMON_MULTI_LEVEL_SUFFIXES = {
    "co.kr",
    "or.kr",
    "go.kr",
    "ac.kr",
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.jp",
}
KNOWN_SENDING_INFRASTRUCTURE_DOMAINS = {
    "stripe.com",
    "sendgrid.net",
    "amazonses.com",
    "mailgun.org",
    "sparkpostmail.com",
    "mailchimpapp.net",
    "mandrillapp.com",
    "customeriomail.com",
    "hubspotemail.net",
}


def extract_domain(address: str) -> str:
    _, raw = parseaddr(address or "")
    if "@" not in raw:
        return ""
    return raw.split("@")[-1].strip().lower()


def extract_display_name(address: str) -> str:
    name, _ = parseaddr(address or "")
    return " ".join((name or "").strip().lower().split())


def registrable_domain(domain: str) -> str:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return ""

    parts = normalized.split(".")
    if len(parts) < 2:
        return normalized

    suffix = ".".join(parts[-2:])
    if suffix in COMMON_MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix


def is_known_sending_infrastructure(domain: str) -> bool:
    return registrable_domain(domain) in KNOWN_SENDING_INFRASTRUCTURE_DOMAINS


def read_auth_results(message: EmailMessage) -> str:
    values = message.get_all("Authentication-Results", [])
    return " ".join(values).lower()


def extract_header_signals(
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
) -> EmailHeaderSignals:
    normalized_subject = (subject or "").lower()
    resolved_from_domain = (from_domain or extract_domain(from_value)).strip().lower()
    resolved_reply_domain = (reply_domain or extract_domain(reply_to_value)).strip().lower()
    resolved_from_org_domain = registrable_domain(resolved_from_domain)
    resolved_reply_org_domain = registrable_domain(resolved_reply_domain)
    resolved_from_display = extract_display_name(from_value)
    resolved_reply_display = extract_display_name(reply_to_value)
    normalized_auth_results = (auth_results or "").lower()
    detected_contexts = detect_business_contexts(subject)

    if has_auth_results is None:
        has_auth_results = bool(normalized_auth_results)
    if spf_fail is None:
        spf_fail = "spf=fail" in normalized_auth_results
    if dkim_fail is None:
        dkim_fail = "dkim=fail" in normalized_auth_results
    if dmarc_fail is None:
        dmarc_fail = "dmarc=fail" in normalized_auth_results

    auth_failure_count = sum(1 for value in (spf_fail, dkim_fail, dmarc_fail) if value)
    strong_auth_failure_detected = bool(dkim_fail or dmarc_fail)
    likely_legitimate_relay = (
        resolved_from_display
        and resolved_from_display == resolved_reply_display
        and is_known_sending_infrastructure(resolved_from_domain)
    )

    return {
        "from_value": from_value,
        "reply_to_value": reply_to_value,
        "subject": subject,
        "resolved_from_domain": resolved_from_domain,
        "resolved_reply_domain": resolved_reply_domain,
        "resolved_from_org_domain": resolved_from_org_domain,
        "resolved_reply_org_domain": resolved_reply_org_domain,
        "resolved_from_display": resolved_from_display,
        "resolved_reply_display": resolved_reply_display,
        "normalized_subject": normalized_subject,
        "normalized_auth_results": normalized_auth_results,
        "has_message_id": has_message_id,
        "received_count": received_count,
        "has_auth_results": has_auth_results,
        "spf_fail": spf_fail,
        "dkim_fail": dkim_fail,
        "dmarc_fail": dmarc_fail,
        "auth_failure_count": auth_failure_count,
        "strong_auth_failure_detected": strong_auth_failure_detected,
        "likely_legitimate_relay": likely_legitimate_relay,
        "detected_contexts": detected_contexts,
    }


def extract_message_header_signals(message: EmailMessage) -> EmailHeaderSignals:
    return extract_header_signals(
        from_value=message.get("From", ""),
        reply_to_value=message.get("Reply-To", ""),
        subject=message.get("Subject", "") or "",
        auth_results=read_auth_results(message),
        has_message_id=bool(message.get("Message-ID")),
        received_count=len(message.get_all("Received") or []),
    )
