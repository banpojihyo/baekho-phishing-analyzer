from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.routes.analysis import router as analysis_router
from app.routes.site import STATIC_DIR, router as site_router

NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

NO_CACHE_PATHS = frozenset(
    {
        "/",
        "/demo",
        "/phishshield",
        "/tech",
        "/updates",
        "/team",
        "/report",
        "/contact",
        "/favicon.ico",
        "/apple-touch-icon.png",
        "/site.webmanifest",
        "/manifest.json",
        "/browserconfig.xml",
    }
)


def _should_disable_cache(path: str) -> bool:
    return path.startswith("/demo-assets/") or path in NO_CACHE_PATHS


def create_app() -> FastAPI:
    application = FastAPI(
        title="PhishShield-Analyzer API",
        version="0.1.0",
        description="정보보호종합설계 MVP API: 헤더 점검, URL 점수화, 첨부파일 정적 가드, 설명형 리포트",
    )

    @application.middleware("http")
    async def add_no_cache_headers(request: Request, call_next):
        response = await call_next(request)
        if _should_disable_cache(request.url.path):
            response.headers.update(NO_CACHE_HEADERS)
        return response

    application.mount("/demo-assets", StaticFiles(directory=STATIC_DIR), name="demo-assets")
    application.include_router(site_router)
    application.include_router(analysis_router)
    return application


app = create_app()

