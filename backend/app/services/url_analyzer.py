"""URL analysis service.

Placeholder: teammates will plug in lexical features, ML phishing models
(under ``app/ml``), and live VirusTotal lookups. The function already returns
the signal shape expected by ``risk_scoring.compute_risk_score``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.services.risk_scoring import compute_risk_score
from app.services.virustotal_client import check_url as vt_check_url


async def analyze_url(url: str, db: Session | None = None) -> dict[str, Any]:
    """Analyze a URL and return risk score, verdict, and raw details.

    Planned real pipeline (replace the heuristics below):
        1. Normalize the URL (scheme, IDN, tracking-param stripping).
        2. Extract lexical / host features for the URL ML model.
        3. Query VirusTotal (cached + rate-limited) via ``virustotal_client``.
        4. Feed ML confidence, VT stats, and red flags into ``compute_risk_score``.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    red_flags: list[dict[str, Any]] = []

    # --- placeholder heuristics (replace with ML + richer static checks) ---
    suspicious_tlds = {".xyz", ".top", ".click", ".country", ".zip"}
    if any(host.endswith(tld) for tld in suspicious_tlds):
        red_flags.append(
            {
                "name": "suspicious_tld",
                "severity": 4,
                "detail": f"Host uses a commonly abused TLD: {host}",
            }
        )
    if parsed.scheme == "http":
        red_flags.append(
            {
                "name": "insecure_scheme",
                "severity": 2,
                "detail": "URL is served over plaintext HTTP.",
            }
        )
    if "@" in (parsed.netloc or "") or url.count(".") > 5:
        red_flags.append(
            {
                "name": "obfuscated_url",
                "severity": 5,
                "detail": "URL structure looks obfuscated (embedded credentials or many dots).",
            }
        )

    # Placeholder ML confidence until the URL model is trained and loaded.
    ml_confidence = 0.15 if red_flags else 0.05
    ml_details = {
        "model": "url_phishing_placeholder",
        "confidence": ml_confidence,
        "note": "Replace with the real model under app/ml once trained.",
    }

    vt_details = await vt_check_url(url, db=db)
    vt_stats = (vt_details or {}).get("stats") or {}
    vt_positives = vt_stats.get("malicious")
    vt_total = vt_stats.get("total")

    scored = compute_risk_score(
        ml_confidence=ml_confidence,
        vt_positives=vt_positives,
        vt_total=vt_total,
        red_flags=red_flags,
    )
    return {
        "input_value": url,
        "verdict": scored.verdict,
        "risk_score": scored.risk_score,
        "ml_details": ml_details,
        "vt_details": vt_details,
        "details": {
            "host": host,
            "scheme": parsed.scheme,
            "risk_breakdown": scored.breakdown,
        },
    }
