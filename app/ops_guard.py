from __future__ import annotations

import hashlib
import json
import math
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock


ROOT_DIR = Path(__file__).resolve().parents[1]


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


MAX_EML_UPLOAD_BYTES = _env_int("PHISHSHIELD_MAX_EML_UPLOAD_BYTES", 5 * 1024 * 1024)
URL_RATE_LIMIT_REQUESTS = _env_int("PHISHSHIELD_URL_RATE_LIMIT_REQUESTS", 30)
EML_RATE_LIMIT_REQUESTS = _env_int("PHISHSHIELD_EML_RATE_LIMIT_REQUESTS", 8)
RATE_LIMIT_WINDOW_SECONDS = _env_int("PHISHSHIELD_RATE_LIMIT_WINDOW_SECONDS", 300)
AUDIT_LOG_RETENTION_DAYS = _env_int("PHISHSHIELD_AUDIT_LOG_RETENTION_DAYS", 14)
AUDIT_LOG_PATH = Path(
    os.getenv(
        "PHISHSHIELD_AUDIT_LOG_PATH",
        str(ROOT_DIR / "runtime_logs" / "analysis_audit.jsonl"),
    )
)
AUDIT_LOG_SALT = os.getenv("PHISHSHIELD_AUDIT_LOG_SALT", "phishshield-local")


def humanize_bytes(num_bytes: int) -> str:
    megabytes = num_bytes / (1024 * 1024)
    if megabytes.is_integer():
        return f"{int(megabytes)}MB"
    return f"{megabytes:.1f}MB"


def normalize_client_ip(x_forwarded_for: str | None, client_host: str | None) -> str:
    if x_forwarded_for:
        first = x_forwarded_for.split(",")[0].strip()
        if first:
            return first
    if client_host:
        return client_host
    return "unknown"


def anonymize_client_key(client_key: str, *, salt: str = AUDIT_LOG_SALT) -> str:
    material = f"{salt}:{client_key}".encode("utf-8", "ignore")
    return hashlib.sha256(material).hexdigest()[:16]


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int


class SlidingWindowRateLimiter:
    def __init__(self, *, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self._state: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(
        self,
        *,
        bucket: str,
        client_key: str,
        limit: int,
        now: float,
    ) -> RateLimitDecision:
        state_key = f"{bucket}:{client_key}"
        with self._lock:
            queue = self._state[state_key]
            while queue and now - queue[0] >= self.window_seconds:
                queue.popleft()

            if len(queue) >= limit:
                retry_after = max(1, math.ceil(self.window_seconds - (now - queue[0])))
                return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)

            queue.append(now)
            return RateLimitDecision(allowed=True, retry_after_seconds=0)


class AuditLogStore:
    def __init__(
        self,
        *,
        path: Path,
        retention_days: int,
        salt: str = AUDIT_LOG_SALT,
    ) -> None:
        self.path = path
        self.retention_days = retention_days
        self.salt = salt
        self._lock = Lock()

    def record(self, event: dict, *, now: datetime | None = None) -> None:
        current = now or datetime.now(timezone.utc)
        payload = dict(event)
        payload["recorded_at"] = current.isoformat()
        payload["client_fingerprint"] = anonymize_client_key(
            str(payload.pop("client_key", "unknown")),
            salt=self.salt,
        )

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self._prune_locked(current=current)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _prune_locked(self, *, current: datetime) -> None:
        if not self.path.exists():
            return

        cutoff = current - timedelta(days=self.retention_days)
        kept_lines: list[str] = []

        with self.path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    recorded_at = datetime.fromisoformat(payload["recorded_at"])
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

                if recorded_at >= cutoff:
                    kept_lines.append(json.dumps(payload, ensure_ascii=False))

        with self.path.open("w", encoding="utf-8") as handle:
            if kept_lines:
                handle.write("\n".join(kept_lines) + "\n")


rate_limiter = SlidingWindowRateLimiter(window_seconds=RATE_LIMIT_WINDOW_SECONDS)
audit_log_store = AuditLogStore(
    path=AUDIT_LOG_PATH,
    retention_days=AUDIT_LOG_RETENTION_DAYS,
    salt=AUDIT_LOG_SALT,
)
