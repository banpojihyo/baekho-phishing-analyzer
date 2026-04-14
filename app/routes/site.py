from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, RedirectResponse


BASE_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = BASE_DIR / "static"
FAVICON_DIR = STATIC_DIR / "assets" / "branding" / "favicons"
FAVICON_FILE = FAVICON_DIR / "favicon.ico"
APPLE_TOUCH_ICON_FILE = FAVICON_DIR / "apple-icon-180x180.png"
WEB_MANIFEST_FILE = FAVICON_DIR / "manifest.json"
BROWSERCONFIG_FILE = FAVICON_DIR / "browserconfig.xml"
SITE_PAGES = {
    "home": STATIC_DIR / "home.html",
    "demo": STATIC_DIR / "index.html",
    "phishshield": STATIC_DIR / "phishshield.html",
    "updates": STATIC_DIR / "updates.html",
    "team": STATIC_DIR / "team.html",
    "report": STATIC_DIR / "report.html",
    "contact": STATIC_DIR / "contact.html",
}

router = APIRouter()


def _file_response(path: Path, *, media_type: str | None = None) -> FileResponse:
    return FileResponse(path, media_type=media_type)


def _site_page(name: str) -> FileResponse:
    return _file_response(SITE_PAGES[name])


@router.get("/", include_in_schema=False)
def site_home() -> FileResponse:
    return _site_page("home")


@router.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    return _file_response(FAVICON_FILE)


@router.head("/favicon.ico", include_in_schema=False)
def favicon_head() -> FileResponse:
    return _file_response(FAVICON_FILE)


@router.get("/apple-touch-icon.png", include_in_schema=False)
def apple_touch_icon() -> FileResponse:
    return _file_response(APPLE_TOUCH_ICON_FILE)


@router.head("/apple-touch-icon.png", include_in_schema=False)
def apple_touch_icon_head() -> FileResponse:
    return _file_response(APPLE_TOUCH_ICON_FILE)


@router.get("/site.webmanifest", include_in_schema=False)
def site_webmanifest() -> FileResponse:
    return _file_response(WEB_MANIFEST_FILE, media_type="application/manifest+json")


@router.head("/site.webmanifest", include_in_schema=False)
def site_webmanifest_head() -> FileResponse:
    return _file_response(WEB_MANIFEST_FILE, media_type="application/manifest+json")


@router.get("/manifest.json", include_in_schema=False)
def manifest_json() -> FileResponse:
    return _file_response(WEB_MANIFEST_FILE, media_type="application/manifest+json")


@router.head("/manifest.json", include_in_schema=False)
def manifest_json_head() -> FileResponse:
    return _file_response(WEB_MANIFEST_FILE, media_type="application/manifest+json")


@router.get("/browserconfig.xml", include_in_schema=False)
def browserconfig() -> FileResponse:
    return _file_response(BROWSERCONFIG_FILE, media_type="application/xml")


@router.head("/browserconfig.xml", include_in_schema=False)
def browserconfig_head() -> FileResponse:
    return _file_response(BROWSERCONFIG_FILE, media_type="application/xml")


@router.get("/demo", include_in_schema=False)
def demo_home() -> FileResponse:
    return _site_page("demo")


@router.get("/phishshield", include_in_schema=False)
def phishshield_page() -> FileResponse:
    return _site_page("phishshield")


@router.get("/tech", include_in_schema=False)
def tech_page() -> RedirectResponse:
    return RedirectResponse(url="/#tech", status_code=308)


@router.get("/updates", include_in_schema=False)
def updates_page() -> FileResponse:
    return _site_page("updates")


@router.get("/team", include_in_schema=False)
def team_page() -> FileResponse:
    return _site_page("team")


@router.get("/report", include_in_schema=False)
def report_page() -> FileResponse:
    return _site_page("report")


@router.get("/contact", include_in_schema=False)
def contact_page() -> FileResponse:
    return _site_page("contact")


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}
