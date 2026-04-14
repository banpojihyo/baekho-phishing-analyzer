from __future__ import annotations

from time import monotonic

from fastapi import HTTPException, Request

from app.ops_guard import audit_log_store, normalize_client_ip, rate_limiter


def client_key_from_request(request: Request) -> str:
    client_host = request.client.host if request.client else None
    return normalize_client_ip(request.headers.get("x-forwarded-for"), client_host)


def enforce_rate_limit(
    request: Request,
    *,
    bucket: str,
    limit: int,
    window_minutes: int,
) -> str:
    client_key = client_key_from_request(request)
    decision = rate_limiter.check(
        bucket=bucket,
        client_key=client_key,
        limit=limit,
        now=monotonic(),
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail=f"요청이 너무 많습니다. {window_minutes}분 동안 잠시 기다린 뒤 다시 시도해 주세요.",
        )
    return client_key


def record_audit_event(
    *,
    client_key: str,
    route: str,
    input_type: str,
    outcome: str,
    filename: str | None = None,
    size_bytes: int | None = None,
    score: int | None = None,
    severity: str | None = None,
    note: str | None = None,
) -> None:
    audit_log_store.record(
        {
            "client_key": client_key,
            "route": route,
            "input_type": input_type,
            "outcome": outcome,
            "filename": filename,
            "size_bytes": size_bytes,
            "score": score,
            "severity": severity,
            "note": note,
        }
    )
