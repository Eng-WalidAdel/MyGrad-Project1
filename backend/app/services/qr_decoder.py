"""QR decoding service.

Placeholder: teammates will harden image preprocessing (OpenCV) and decoding
(``pyzbar``). Decoded payloads that look like URLs should be handed to
``url_analyzer.analyze_url``.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.services.risk_scoring import compute_risk_score
from app.services.url_analyzer import analyze_url


async def decode_and_analyze_qr(image_bytes: bytes, db: Session | None = None) -> dict[str, Any]:
    """Decode a QR image and score the payload.

    Planned real pipeline:
        1. Load the image with OpenCV (``cv2.imdecode``).
        2. Optional grayscale / threshold / morph ops for hard-to-read codes.
        3. Decode with ``pyzbar.pyzbar.decode``.
        4. If the payload is a URL, call ``analyze_url``; otherwise score the
           raw payload (e.g. wifi strings, payment URIs) with red flags.
    """
    payload, decode_error = _try_decode(image_bytes)
    red_flags: list[dict[str, Any]] = []

    if not payload:
        red_flags.append(
            {
                "name": "qr_decode_failed",
                "severity": 2,
                "detail": decode_error or "No QR code detected in the image.",
            }
        )
        scored = compute_risk_score(ml_confidence=0.0, red_flags=red_flags)
        return {
            "input_value": "(undecoded QR)",
            "verdict": scored.verdict,
            "risk_score": scored.risk_score,
            "ml_details": None,
            "vt_details": None,
            "details": {
                "decoded": False,
                "error": decode_error,
                "risk_breakdown": scored.breakdown,
            },
        }

    looks_like_url = payload.lower().startswith(("http://", "https://"))
    if looks_like_url:
        url_result = await analyze_url(payload, db=db)
        url_result["details"] = {
            **url_result.get("details", {}),
            "decoded_from_qr": True,
            "raw_payload": payload,
        }
        return url_result

    red_flags.append(
        {
            "name": "non_url_qr_payload",
            "severity": 1,
            "detail": "QR decoded successfully but payload is not an HTTP(S) URL.",
        }
    )
    scored = compute_risk_score(ml_confidence=0.05, red_flags=red_flags)
    return {
        "input_value": payload,
        "verdict": scored.verdict,
        "risk_score": scored.risk_score,
        "ml_details": None,
        "vt_details": None,
        "details": {
            "decoded": True,
            "raw_payload": payload,
            "risk_breakdown": scored.breakdown,
        },
    }


def _try_decode(image_bytes: bytes) -> tuple[str | None, str | None]:
    """Best-effort QR decode; never raises so the API can still return a verdict."""
    try:
        import cv2
        import numpy as np
        from pyzbar.pyzbar import decode as zbar_decode
    except ImportError as exc:
        return None, f"QR libraries not available ({exc}). Install opencv-python and pyzbar."

    try:
        array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(array, cv2.IMREAD_COLOR)
        if image is None:
            # Some environments prefer a PIL-less numpy path only; try from buffer again.
            return None, "OpenCV could not decode the image bytes."
        results = zbar_decode(image)
        if not results:
            return None, "No QR code found in the image."
        payload = results[0].data.decode("utf-8", errors="replace")
        return payload, None
    except Exception as exc:  # noqa: BLE001 — decoder must not take down the request
        return None, f"QR decode error: {exc}"
