from __future__ import annotations

from email import policy
from email.parser import BytesParser

from app.analyzers.attachment_static import analyze_attachments, extract_attachments
from app.analyzers.email_body import analyze_email_body
from app.analyzers.email_header import analyze_email_headers
from app.analyzers.types import EMLAnalysisResult
from app.analyzers.url_scoring import analyze_url
from app.services.eml_analysis_response import build_eml_analysis_response


def analyze_eml_bytes(filename: str, eml_bytes: bytes) -> EMLAnalysisResult:
    message = BytesParser(policy=policy.default).parsebytes(eml_bytes)

    header_result = analyze_email_headers(message)
    body_result = analyze_email_body(message)
    urls = body_result["urls"]
    url_results = [analyze_url(url) for url in urls]
    attachments = extract_attachments(message)
    attachment_result = analyze_attachments(attachments)
    return build_eml_analysis_response(
        filename=filename,
        extracted_urls=urls,
        header_result=header_result,
        body_result=body_result,
        url_results=url_results,
        attachment_result=attachment_result,
    )

