"""VirusTotal API wrapper with free-tier rate limiting and cache hooks.

Never hardcode the API key. It is read from VIRUSTOTAL_API_KEY.

Free-tier limit implemented here: max 4 requests per rolling 60 seconds.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.models.scan_result import ScanResult

VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
MAX_CALLS_PER_MINUTE = 4
WINDOW_SECONDS = 60.0


class RollingRateLimiter:
    """In-memory limiter: at most ``max_calls`` in any ``window_seconds`` period."""

    def __init__(self, max_calls: int = MAX_CALLS_PER_MINUTE, window_seconds: float = WINDOW_SECONDS):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                while self._timestamps and now - self._timestamps[0] >= self.window_seconds:
                    self._timestamps.popleft()
                if len(self._timestamps) < self.max_calls:
                    self._timestamps.append(now)
                    return
                wait_for = self.window_seconds - (now - self._timestamps[0]) + 0.05
                await asyncio.sleep(max(wait_for, 0.05))


_url_limiter = RollingRateLimiter()


async def check_url(url: str, db: Session | None = None) -> dict[str, Any]:
    """Check a URL against VirusTotal v3.

    Cache placeholder: if ``db`` is provided, reuse the latest stored
    ``vt_details`` for the same URL instead of calling the API again.
    """
    cached = _cache_lookup(url, db)
    if cached is not None:
        return cached

    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        return {
            "source": "virustotal",
            "skipped": True,
            "reason": "VIRUSTOTAL_API_KEY is not set",
            "stats": None,
        }

    await _url_limiter.acquire()

    headers = {"x-apikey": api_key, "accept": "application/json"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        # VT identifies URLs by an identifier derived from a POST to /urls.
        submit = await client.post(VT_URL_ENDPOINT, headers=headers, data={"url": url})
        if submit.status_code >= 400:
            return {
                "source": "virustotal",
                "error": True,
                "status_code": submit.status_code,
                "body": _safe_json(submit),
                "stats": None,
            }
        submit_payload = _safe_json(submit)
        analysis_id = (
            (submit_payload.get("data") or {}).get("id")
            if isinstance(submit_payload, dict)
            else None
        )
        # Placeholder: a production client should poll /analyses/{id} then GET
        # /urls/{url_id}. For scaffolding we return the submit payload shape.
        stats = _extract_stats(submit_payload)
        return {
            "source": "virustotal",
            "skipped": False,
            "analysis_id": analysis_id,
            "raw": submit_payload,
            "stats": stats,
            "note": (
                "Placeholder VT client: teammates should poll the analysis until "
                "completed and persist last_analysis_stats into vt_details."
            ),
        }


def _cache_lookup(url: str, db: Session | None) -> dict[str, Any] | None:
    """Return a previously stored VirusTotal payload for this URL, if any."""
    if db is None:
        return None
    row = (
        db.query(ScanResult)
        .filter(
            ScanResult.scan_type == "url",
            ScanResult.input_value == url,
            ScanResult.vt_details.isnot(None),
        )
        .order_by(ScanResult.created_at.desc())
        .first()
    )
    if row is None or not row.vt_details:
        return None
    cached = dict(row.vt_details)
    cached["cached"] = True
    return cached


def _extract_stats(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or attributes.get("stats")
    if not isinstance(stats, dict):
        return None
    positives = int(stats.get("malicious", 0) or 0) + int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))
    return {"malicious": positives, "total": total, "raw_stats": stats}


def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except Exception:  # noqa: BLE001
        return {"text": response.text[:500]}
