from __future__ import annotations


EXECUTABLE_EXTENSIONS = {
    ".exe": 38,
    ".scr": 38,
    ".com": 38,
    ".dll": 38,
    ".msi": 36,
    ".jar": 34,
    ".iso": 30,
    ".img": 30,
    ".lnk": 30,
    ".chm": 28,
}
SCRIPT_EXTENSIONS = {
    ".js": 30,
    ".jse": 30,
    ".vbs": 30,
    ".vbe": 30,
    ".wsf": 30,
    ".wsh": 30,
    ".ps1": 28,
    ".psm1": 28,
    ".bat": 28,
    ".cmd": 28,
    ".hta": 28,
    ".reg": 24,
}
MACRO_EXTENSIONS = {
    ".docm": 24,
    ".xlsm": 24,
    ".pptm": 24,
    ".xlam": 24,
}
ARCHIVE_EXTENSIONS = {
    ".zip": 14,
    ".rar": 14,
    ".7z": 14,
    ".gz": 12,
    ".tar": 12,
}
OPENXML_CONTAINER_EXTENSIONS = {
    ".docx",
    ".xlsx",
    ".pptx",
    ".ppsx",
    ".potx",
}
HTML_EXTENSIONS = {
    ".html": 18,
    ".htm": 18,
    ".shtml": 18,
}
BENIGN_LOOKING_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".jpg",
    ".jpeg",
    ".png",
    ".txt",
}
SUSPICIOUS_FILENAME_TERMS = {
    "invoice",
    "payment",
    "remit",
    "confirm",
    "verify",
    "secure",
    "account",
    "password",
    "세금",
    "인증",
    "송금",
    "결제",
    "견적",
    "발주",
    "배송",
}
CONTENT_TYPE_SCORES = {
    "application/x-msdownload": 38,
    "application/x-msdos-program": 38,
    "application/x-dosexec": 38,
    "application/java-archive": 34,
    "application/javascript": 30,
    "text/javascript": 30,
    "application/x-javascript": 30,
    "application/x-sh": 28,
    "application/x-powershell": 28,
    "text/html": 18,
    "application/zip": 14,
    "application/x-zip-compressed": 14,
    "application/vnd.ms-excel.sheet.macroenabled.12": 24,
    "application/vnd.ms-word.document.macroenabled.12": 24,
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": 24,
}
HTML_PAYLOAD_MARKERS = (
    b"<form",
    b"<script",
    b"window.location",
    b"document.location",
    b"http-equiv",
    b"type=\"password\"",
    b"type='password'",
)


def is_expected_zip_container(last_suffix: str, content_type: str) -> bool:
    if last_suffix in OPENXML_CONTAINER_EXTENSIONS:
        return True
    if content_type.startswith("application/vnd.openxmlformats-officedocument."):
        return True
    return False


def detect_payload_kind(payload: bytes) -> str:
    if not payload:
        return ""

    head = payload[:2048]
    lowered = head.lower()
    if head.startswith(b"MZ"):
        return "portable_executable"
    if head.startswith(b"PK\x03\x04"):
        return "zip_archive"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "office_compound"
    if head.startswith(b"%PDF"):
        return "pdf"
    if b"<html" in lowered or b"<form" in lowered or b"<script" in lowered:
        return "html"
    return ""
