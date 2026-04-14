from __future__ import annotations

import os
import secrets

from fastapi import FastAPI
from fastapi import Header, HTTPException

from app.analyzers.url_probe import probe_url
from app.schemas import URLAnalysisRequest


app = FastAPI(
    title="PhishShield URL Probe Worker",
    version="0.1.0",
    description="직접 URL 분석을 별도 컨테이너에서 수행하는 저권한 프로브 워커",
)


def _shared_token() -> str | None:
    raw = (os.getenv("PHISHSHIELD_URL_PROBE_SHARED_TOKEN") or "").strip()
    return raw or None


def _enforce_worker_token(worker_token: str | None) -> None:
    expected = _shared_token()
    if not expected:
        return
    if not worker_token or not secrets.compare_digest(worker_token, expected):
        raise HTTPException(status_code=403, detail="URL 프로브 워커 인증 실패")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "auth_required": bool(_shared_token())}


@app.post("/probe-url")
def probe_url_endpoint(
    payload: URLAnalysisRequest,
    worker_token: str | None = Header(default=None, alias="X-PhishShield-Worker-Token"),
) -> dict:
    _enforce_worker_token(worker_token)
    return probe_url(payload.url)
