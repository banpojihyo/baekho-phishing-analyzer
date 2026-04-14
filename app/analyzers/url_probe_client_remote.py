from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.analyzers.url_probe_client_config import WORKER_TOKEN_HEADER


class RemoteProbeTransportError(ValueError):
    pass


def fetch_remote_probe_payload(
    url: str,
    *,
    worker_url: str,
    timeout_seconds: float,
    shared_token: str | None,
) -> dict:
    headers = {"Content-Type": "application/json"}
    if shared_token:
        headers[WORKER_TOKEN_HEADER] = shared_token

    request = Request(
        worker_url,
        data=json.dumps({"url": url}).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RemoteProbeTransportError(f"원격 URL 프로브 워커 오류(HTTP {exc.code})") from exc
    except URLError as exc:
        raise RemoteProbeTransportError(f"원격 URL 프로브 워커 연결 실패({exc.reason})") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RemoteProbeTransportError(f"원격 URL 프로브 응답 파싱 실패({exc})") from exc

    if not isinstance(payload, dict):
        raise RemoteProbeTransportError("원격 URL 프로브 응답 형식 오류")

    return payload
