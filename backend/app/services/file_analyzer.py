"""File static-analysis service.

Placeholder: teammates will add PE parsing (``pefile``), hashes, strings,
and an ML classifier. ``analyze_file`` already returns the signal shape
expected by ``risk_scoring.compute_risk_score``.
"""

from __future__ import annotations

import hashlib
from typing import Any


from app.services.risk_scoring import compute_risk_score

# Common executable / script extensions used only for placeholder red flags.
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs"}


async def analyze_file(
    content: bytes,
    filename: str,
    content_type: str | None = None,
) -> dict[str, Any]:
    """Run static analysis on an uploaded file.

    Planned real pipeline (replace the heuristics below):
        1. Compute SHA-256 / SHA-1 / MD5 and look up known-bad hashes.
        2. If PE/ELF, parse headers and imports with ``pefile`` (or equivalent).
        3. Extract strings, packer indicators, and macro presence.
        4. Run the file ML model from ``app/ml`` and optional VirusTotal file hash API.
        5. Feed signals into ``compute_risk_score``.
    """
    sha256 = hashlib.sha256(content).hexdigest()
    suffix = _extension(filename)
    red_flags: list[dict[str, Any]] = []

    if suffix in EXECUTABLE_EXTENSIONS:
        red_flags.append(
            {
                "name": "executable_file",
                "severity": 4,
                "detail": f"Uploaded file has an executable/script extension ({suffix}).",
            }
        )
    if len(content) == 0:
        red_flags.append(
            {
                "name": "empty_file",
                "severity": 1,
                "detail": "File has zero bytes.",
            }
        )

    # Placeholder ML confidence — swap for scikit-learn / custom model output.
    ml_confidence = 0.2 if suffix in EXECUTABLE_EXTENSIONS else 0.08
    ml_details = {
        "model": "file_malware_placeholder",
        "confidence": ml_confidence,
        "features": {
            "size_bytes": len(content),
            "extension": suffix,
            "content_type": content_type,
        },
        "note": "Replace with real static-feature ML once models land in app/ml.",
    }

    scored = compute_risk_score(ml_confidence=ml_confidence, red_flags=red_flags)
    return {
        "input_value": sha256,
        "filename": filename,
        "verdict": scored.verdict,
        "risk_score": scored.risk_score,
        "ml_details": ml_details,
        "vt_details": None,
        "details": {
            "sha256": sha256,
            "size_bytes": len(content),
            "content_type": content_type,
            "risk_breakdown": scored.breakdown,
        },
    }


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()
