from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from app.analyzers.attachment_rule_catalog import (
    ARCHIVE_EXTENSIONS,
    BENIGN_LOOKING_EXTENSIONS,
    CONTENT_TYPE_SCORES,
    EXECUTABLE_EXTENSIONS,
    HTML_EXTENSIONS,
    HTML_PAYLOAD_MARKERS,
    MACRO_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    SUSPICIOUS_FILENAME_TERMS,
    detect_payload_kind,
    is_expected_zip_container,
)
from app.analyzers.attachment_static_support import unique_items, unique_rule_hits
from app.analyzers.rule_utils import build_rule_hit, severity_from_score
from app.analyzers.types import AttachmentAnalysisDetail, RuleHit

if TYPE_CHECKING:
    from app.analyzers.attachment_static import AttachmentArtifact


def analyze_attachment(artifact: "AttachmentArtifact") -> AttachmentAnalysisDetail:
    filename = artifact.filename or "(이름 없음)"
    filename_lower = filename.lower()
    content_type = (artifact.content_type or "").lower()
    suffixes = [suffix.lower() for suffix in Path(filename_lower).suffixes]
    last_suffix = suffixes[-1] if suffixes else ""
    payload_kind = detect_payload_kind(artifact.payload)

    score = 0
    evidence: list[str] = []
    matched_rules: list[RuleHit] = []

    def add_rule(*, rule_id: str, title: str, description: str, rule_score: int, evidence_text: str) -> None:
        nonlocal score
        score += rule_score
        evidence.append(evidence_text)
        matched_rules.append(
            build_rule_hit(
                rule_id=rule_id,
                title=title,
                description=description,
                score=rule_score,
                evidence=evidence_text,
            )
        )

    if last_suffix in EXECUTABLE_EXTENSIONS:
        add_rule(
            rule_id="attachment.executable_extension",
            title="실행형 첨부파일",
            description="직접 실행 가능한 첨부파일 확장자를 포함합니다.",
            rule_score=EXECUTABLE_EXTENSIONS[last_suffix],
            evidence_text=f"실행형 첨부파일({last_suffix})",
        )
    if last_suffix in SCRIPT_EXTENSIONS:
        add_rule(
            rule_id="attachment.script_extension",
            title="스크립트 첨부파일",
            description="스크립트 실행을 유도할 수 있는 첨부파일 확장자입니다.",
            rule_score=SCRIPT_EXTENSIONS[last_suffix],
            evidence_text=f"스크립트 첨부파일({last_suffix})",
        )
    if last_suffix in MACRO_EXTENSIONS:
        add_rule(
            rule_id="attachment.macro_office_extension",
            title="매크로 가능 Office 문서",
            description="매크로 실행이 가능한 Office 확장자를 포함합니다.",
            rule_score=MACRO_EXTENSIONS[last_suffix],
            evidence_text=f"매크로 가능 Office 문서({last_suffix})",
        )
    if last_suffix in ARCHIVE_EXTENSIONS:
        add_rule(
            rule_id="attachment.archive_extension",
            title="압축파일 첨부",
            description="압축파일은 내부 악성 파일을 숨기기 쉬운 전달 형식입니다.",
            rule_score=ARCHIVE_EXTENSIONS[last_suffix],
            evidence_text=f"압축파일 첨부({last_suffix})",
        )
    if last_suffix in HTML_EXTENSIONS:
        add_rule(
            rule_id="attachment.html_extension",
            title="HTML 첨부파일",
            description="브라우저에서 직접 열리는 HTML 첨부파일입니다.",
            rule_score=HTML_EXTENSIONS[last_suffix],
            evidence_text=f"HTML 첨부파일({last_suffix})",
        )

    if len(suffixes) >= 2 and suffixes[-2] in BENIGN_LOOKING_EXTENSIONS:
        dangerous_suffixes = set(EXECUTABLE_EXTENSIONS) | set(SCRIPT_EXTENSIONS) | set(HTML_EXTENSIONS)
        if last_suffix in dangerous_suffixes:
            add_rule(
                rule_id="attachment.disguised_double_extension",
                title="문서/이미지로 위장한 이중 확장자",
                description="앞부분은 문서처럼 보이지만 실제 끝 확장자는 더 위험한 형식입니다.",
                rule_score=18,
                evidence_text="문서/이미지로 위장한 이중 확장자",
            )

    matched_terms = [term for term in SUSPICIOUS_FILENAME_TERMS if term in filename_lower]
    if matched_terms:
        add_rule(
            rule_id="attachment.social_engineering_filename",
            title="첨부파일명 사회공학 표현",
            description="첨부파일명에 결제/송금/인증 같은 민감 행위를 유도하는 표현이 있습니다.",
            rule_score=min(10, len(matched_terms) * 3),
            evidence_text=f"첨부파일명에 사회공학 유도 표현 포함({', '.join(sorted(matched_terms))})",
        )

    if content_type in CONTENT_TYPE_SCORES:
        add_rule(
            rule_id="attachment.suspicious_mime_type",
            title="MIME 타입 기준 의심 신호",
            description="MIME 타입만으로도 실행형 또는 위험 문서로 분류되는 첨부파일입니다.",
            rule_score=CONTENT_TYPE_SCORES[content_type],
            evidence_text=f"MIME 타입 기준 의심 신호({content_type})",
        )

    if payload_kind == "portable_executable" and last_suffix not in EXECUTABLE_EXTENSIONS:
        add_rule(
            rule_id="attachment.executable_signature_mismatch",
            title="실행 파일 시그니처와 확장자 불일치",
            description="실제 바이너리 시그니처는 실행 파일인데 확장자가 다릅니다.",
            rule_score=24,
            evidence_text="실행 파일 시그니처와 확장자 불일치",
        )
    elif payload_kind == "zip_archive" and last_suffix not in ARCHIVE_EXTENSIONS and not is_expected_zip_container(last_suffix, content_type):
        add_rule(
            rule_id="attachment.archive_signature_mismatch",
            title="압축파일 시그니처와 확장자 불일치",
            description="실제 파일 시그니처는 압축파일인데 확장자가 다릅니다.",
            rule_score=10,
            evidence_text="압축파일 시그니처와 확장자 불일치",
        )
    elif payload_kind == "html" and last_suffix not in HTML_EXTENSIONS:
        add_rule(
            rule_id="attachment.html_content_mismatch",
            title="내용상 HTML/로그인 페이지로 추정",
            description="확장자는 다르지만 실제 내용은 HTML 페이지처럼 보입니다.",
            rule_score=14,
            evidence_text="내용상 HTML/로그인 페이지로 추정",
        )

    lowered_payload = artifact.payload[:4096].lower()
    if lowered_payload and any(marker in lowered_payload for marker in HTML_PAYLOAD_MARKERS):
        add_rule(
            rule_id="attachment.html_payload_marker",
            title="첨부 내부 로그인/리다이렉트 코드 흔적",
            description="첨부 내부에 로그인 폼 또는 자동 이동을 유도하는 HTML 코드가 있습니다.",
            rule_score=12,
            evidence_text="첨부 내부에 로그인/리다이렉트 유도 코드 흔적",
        )

    score = min(100, score)
    return {
        "filename": filename,
        "content_type": content_type or "unknown",
        "size": artifact.size,
        "detected_type": payload_kind or "unknown",
        "score": score,
        "severity": severity_from_score(score),
        "evidence": unique_items(evidence) if evidence else ["뚜렷한 의심 신호 없음"],
        "matched_rules": unique_rule_hits(matched_rules),
    }
