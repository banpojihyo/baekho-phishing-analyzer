from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


ALLOWED_SCHEMES = {"http", "https"}
COMMON_SECOND_LEVEL_SUFFIXES = {"ac", "co", "com", "edu", "go", "gov", "net", "or", "org"}


class ProbeBlockedError(ValueError):
    pass


def ip_is_public(ip_text: str) -> bool:
    try:
        return ipaddress.ip_address(ip_text).is_global
    except ValueError:
        return False


def assert_safe_target(url: str) -> None:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").strip().lower()

    if scheme not in ALLOWED_SCHEMES:
        raise ProbeBlockedError("허용되지 않는 URL 스킴")
    if not hostname:
        raise ProbeBlockedError("호스트가 없는 URL")

    if ip_is_public(hostname):
        return

    try:
        addrinfo = socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ProbeBlockedError(f"DNS 해석 실패({exc})") from exc

    resolved_ips = {sockaddr[0] for *_, sockaddr in addrinfo if sockaddr and sockaddr[0]}
    if not resolved_ips:
        raise ProbeBlockedError("공개 IP를 확인할 수 없는 호스트")

    if any(not ip_is_public(ip_text) for ip_text in resolved_ips):
        raise ProbeBlockedError("비공개 또는 내부 IP로 해석되는 호스트")


def clean_probe_text(value: str, *, limit: int = 240) -> str:
    compact = " ".join((value or "").split()).strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"


def hostname_is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def site_key(hostname: str) -> str:
    if not hostname:
        return ""
    lowered = hostname.lower().strip(".")
    if hostname_is_ip(lowered):
        return lowered

    parts = lowered.split(".")
    if len(parts) <= 2:
        return lowered
    if len(parts[-1]) == 2 and parts[-2] in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
