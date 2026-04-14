from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_PROBE_MODE = "local"
DEFAULT_WORKER_URL = "http://url-probe-worker:8081/probe-url"
DEFAULT_WORKER_TIMEOUT_SECONDS = 8.0
WORKER_TOKEN_HEADER = "X-PhishShield-Worker-Token"


@dataclass(frozen=True, slots=True)
class UrlProbeClientConfig:
    mode: str
    worker_url: str
    worker_timeout_seconds: float
    shared_token: str | None


def probe_mode() -> str:
    return (os.getenv("PHISHSHIELD_URL_PROBE_MODE", DEFAULT_PROBE_MODE) or DEFAULT_PROBE_MODE).strip().lower()


def worker_url() -> str:
    return (os.getenv("PHISHSHIELD_URL_PROBE_WORKER_URL", DEFAULT_WORKER_URL) or DEFAULT_WORKER_URL).strip()


def worker_timeout_seconds() -> float:
    raw = os.getenv("PHISHSHIELD_URL_PROBE_WORKER_TIMEOUT_SECONDS")
    if not raw:
        return DEFAULT_WORKER_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_WORKER_TIMEOUT_SECONDS
    return value if value > 0 else DEFAULT_WORKER_TIMEOUT_SECONDS


def shared_token() -> str | None:
    raw = (os.getenv("PHISHSHIELD_URL_PROBE_SHARED_TOKEN") or "").strip()
    return raw or None


def load_probe_client_config() -> UrlProbeClientConfig:
    return UrlProbeClientConfig(
        mode=probe_mode(),
        worker_url=worker_url(),
        worker_timeout_seconds=worker_timeout_seconds(),
        shared_token=shared_token(),
    )
