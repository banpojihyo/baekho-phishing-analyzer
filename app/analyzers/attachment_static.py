from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage

from app.analyzers.attachment_static_aggregate import analyze_attachments
from app.analyzers.attachment_static_single import analyze_attachment


@dataclass(slots=True)
class AttachmentArtifact:
    filename: str = ""
    content_type: str = ""
    size: int = 0
    payload: bytes = b""


def _read_part_payload(part: EmailMessage) -> bytes:
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload

    try:
        content = part.get_content()
    except Exception:
        return b""

    if isinstance(content, str):
        charset = part.get_content_charset() or "utf-8"
        return content.encode(charset, errors="ignore")
    if isinstance(content, bytes):
        return content
    return b""


def extract_attachments(message: EmailMessage) -> list[AttachmentArtifact]:
    attachments: list[AttachmentArtifact] = []
    for part in message.iter_attachments():
        payload = _read_part_payload(part)
        attachments.append(
            AttachmentArtifact(
                filename=part.get_filename() or "",
                content_type=part.get_content_type() or "",
                size=len(payload),
                payload=payload,
            )
        )
    return attachments


__all__ = [
    "AttachmentArtifact",
    "analyze_attachment",
    "analyze_attachments",
    "extract_attachments",
]
