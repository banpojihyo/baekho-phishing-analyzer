from __future__ import annotations

from typing import Any

from app.analyzers.types import UrlProbeResult, UrlProbeSnapshot


def _normalize_probe_snapshot(payload: Any) -> UrlProbeSnapshot:
    return payload if isinstance(payload, dict) else {}


def build_probe_error_result(error: str, *, probe_source: str) -> UrlProbeResult:
    return {
        "performed": False,
        "blocked_reason": None,
        "error": error,
        "browser": {},
        "crawler": {},
        "probe_source": probe_source,
    }


def build_disabled_probe_result() -> UrlProbeResult:
    return build_probe_error_result("URL 프로브 비활성화", probe_source="disabled")


def normalize_probe_result(payload: Any, *, probe_source: str) -> UrlProbeResult:
    if not isinstance(payload, dict):
        return build_probe_error_result("URL 프로브 응답 형식 오류", probe_source=probe_source)

    blocked_reason = payload.get("blocked_reason")
    error = payload.get("error")
    return {
        "performed": bool(payload.get("performed")),
        "blocked_reason": blocked_reason if isinstance(blocked_reason, str) or blocked_reason is None else str(blocked_reason),
        "error": error if isinstance(error, str) or error is None else str(error),
        "browser": _normalize_probe_snapshot(payload.get("browser")),
        "crawler": _normalize_probe_snapshot(payload.get("crawler")),
        "probe_source": probe_source,
    }
