from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from app.analyzers.pipeline import analyze_eml_bytes
from app.analyzers.url_scoring import analyze_url
from app.ops_guard import (
    EML_RATE_LIMIT_REQUESTS,
    MAX_EML_UPLOAD_BYTES,
    RATE_LIMIT_WINDOW_SECONDS,
    URL_RATE_LIMIT_REQUESTS,
    humanize_bytes,
)
from app.services.analysis_response import build_url_analysis_response
from app.services.request_guard import enforce_rate_limit, record_audit_event
from app.schemas import EMLAnalysisResponse, URLAnalysisRequest, URLAnalysisResponse


MAX_EML_UPLOAD_LABEL = humanize_bytes(MAX_EML_UPLOAD_BYTES)
RATE_LIMIT_WINDOW_MINUTES = max(1, RATE_LIMIT_WINDOW_SECONDS // 60)

router = APIRouter()


def _reject_eml_upload(
    *,
    client_key: str,
    filename: str,
    note: str,
    status_code: int,
    detail: str,
    size_bytes: int | None = None,
) -> None:
    record_audit_event(
        client_key=client_key,
        route="/analyze/eml",
        input_type="eml",
        outcome="rejected",
        filename=filename,
        size_bytes=size_bytes,
        note=note,
    )
    raise HTTPException(status_code=status_code, detail=detail)


@router.post("/analyze/url", response_model=URLAnalysisResponse)
def analyze_single_url(payload: URLAnalysisRequest, request: Request) -> URLAnalysisResponse:
    client_key = enforce_rate_limit(
        request,
        bucket="url-analysis",
        limit=URL_RATE_LIMIT_REQUESTS,
        window_minutes=RATE_LIMIT_WINDOW_MINUTES,
    )
    response = build_url_analysis_response(analyze_url(payload.url, enable_probe=True))
    record_audit_event(
        client_key=client_key,
        route="/analyze/url",
        input_type="url",
        outcome="accepted",
        score=response["final_risk_score"],
        severity=response["severity"],
    )
    return URLAnalysisResponse(**response)


@router.post("/analyze/eml", response_model=EMLAnalysisResponse)
async def analyze_eml(request: Request, file: UploadFile = File(...)) -> EMLAnalysisResponse:
    client_key = enforce_rate_limit(
        request,
        bucket="eml-analysis",
        limit=EML_RATE_LIMIT_REQUESTS,
        window_minutes=RATE_LIMIT_WINDOW_MINUTES,
    )
    filename = file.filename or "unknown.eml"
    if not filename.lower().endswith(".eml"):
        _reject_eml_upload(
            client_key=client_key,
            filename=filename,
            note="invalid_extension",
            status_code=400,
            detail=".eml 파일만 업로드할 수 있습니다.",
        )

    eml_bytes = await file.read()
    if not eml_bytes:
        _reject_eml_upload(
            client_key=client_key,
            filename=filename,
            note="empty_file",
            status_code=400,
            detail="빈 파일입니다.",
        )

    if len(eml_bytes) > MAX_EML_UPLOAD_BYTES:
        _reject_eml_upload(
            client_key=client_key,
            filename=filename,
            note="file_too_large",
            status_code=413,
            detail=f"파일 크기 제한({MAX_EML_UPLOAD_LABEL})을 초과했습니다.",
            size_bytes=len(eml_bytes),
        )

    result = analyze_eml_bytes(filename=filename, eml_bytes=eml_bytes)
    record_audit_event(
        client_key=client_key,
        route="/analyze/eml",
        input_type="eml",
        outcome="accepted",
        filename=filename,
        size_bytes=len(eml_bytes),
        score=result["final_risk_score"],
        severity=result["severity"],
    )
    return EMLAnalysisResponse(**result)
