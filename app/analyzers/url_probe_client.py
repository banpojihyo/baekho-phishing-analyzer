from __future__ import annotations

from app.analyzers.url_probe import probe_url
from app.analyzers.types import UrlProbeResult
from app.analyzers.url_probe_client_config import (
    DEFAULT_PROBE_MODE,
    DEFAULT_WORKER_TIMEOUT_SECONDS,
    DEFAULT_WORKER_URL,
    WORKER_TOKEN_HEADER,
    load_probe_client_config,
    probe_mode,
    shared_token,
    worker_timeout_seconds,
    worker_url,
)
from app.analyzers.url_probe_client_remote import RemoteProbeTransportError, fetch_remote_probe_payload
from app.analyzers.url_probe_client_result import (
    build_disabled_probe_result,
    build_probe_error_result,
    normalize_probe_result,
)


def _probe_mode() -> str:
    return probe_mode()


def _worker_url() -> str:
    return worker_url()


def _worker_timeout_seconds() -> float:
    return worker_timeout_seconds()


def _shared_token() -> str | None:
    return shared_token()


def _disabled_probe_result() -> UrlProbeResult:
    return build_disabled_probe_result()


def _local_probe_result(url: str) -> UrlProbeResult:
    return normalize_probe_result(probe_url(url), probe_source="local")


def _remote_probe_result(url: str) -> UrlProbeResult:
    config = load_probe_client_config()
    try:
        payload = fetch_remote_probe_payload(
            url,
            worker_url=config.worker_url,
            timeout_seconds=config.worker_timeout_seconds,
            shared_token=config.shared_token,
        )
    except RemoteProbeTransportError as exc:
        return build_probe_error_result(str(exc), probe_source="remote")
    return normalize_probe_result(payload, probe_source="remote")


def resolve_probe_result(url: str) -> UrlProbeResult:
    mode = _probe_mode()
    if mode == "off":
        return _disabled_probe_result()
    if mode == "remote":
        return _remote_probe_result(url)
    return _local_probe_result(url)
