"""Unified risk scoring engine.

This module is the single place that turns heterogeneous analyzer signals into
a 0–100 score and a human-facing verdict. Teammates should pass raw signals
here instead of inventing per-analyzer thresholds.

Placeholder weighting (tune later against labeled data):
    score = 100 * (
        0.40 * ml_component
        + 0.40 * vt_component
        + 0.20 * red_flag_component
    )

Where:
    ml_component       = ML malware/phishing confidence in [0, 1]
    vt_component       = VT positives / VT total engines (0 if VT unused)
    red_flag_component = min(sum(flag severities) / 10.0, 1.0)

Severity of each red flag is expected in [0, 10]. Ten “full-severity” flags
saturate the red-flag term.

Verdict bands (inclusive of the lower bound except at 0):
    0–30   -> "safe"
    31–70  -> "suspicious"
    71–100 -> "malicious"
"""

from __future__ import annotations

from typing import Any

from app.schemas.risk_schema import RiskScoreResult

ML_WEIGHT = 0.40
VT_WEIGHT = 0.40
RED_FLAG_WEIGHT = 0.20
RED_FLAG_SEVERITY_CAP = 10.0

SAFE_MAX = 30
SUSPICIOUS_MAX = 70


def verdict_from_score(risk_score: float) -> str:
    """Map a 0–100 score onto the project’s three verdict labels."""
    if risk_score <= SAFE_MAX:
        return "safe"
    if risk_score <= SUSPICIOUS_MAX:
        return "suspicious"
    return "malicious"


def compute_risk_score(
    *,
    ml_confidence: float | None = None,
    vt_positives: int | None = None,
    vt_total: int | None = None,
    red_flags: list[dict[str, Any]] | None = None,
) -> RiskScoreResult:
    """Aggregate analyzer signals into a unified risk score and verdict.

    Parameters
    ----------
    ml_confidence:
        Optional model probability that the sample is malicious, in [0, 1].
        When omitted, that term is treated as 0 and its weight is redistributed
        across the signals that *were* provided (so a VT-only scan is not
        artificially capped at 40).
    vt_positives / vt_total:
        VirusTotal detection counts. Ignored unless ``vt_total`` is > 0.
    red_flags:
        List of dicts with at least ``{"name": str, "severity": float}``.
        Severity should be 0–10. Extra keys are preserved in the breakdown
        for the AI assistant and frontend.

    Returns
    -------
    RiskScoreResult
        ``risk_score`` in [0, 100], ``verdict``, and a ``breakdown`` dict
        explaining each component so the formula can be inspected / tuned.
    """
    flags = red_flags or []
    severity_sum = sum(float(flag.get("severity", 0) or 0) for flag in flags)
    red_flag_component = min(severity_sum / RED_FLAG_SEVERITY_CAP, 1.0)

    has_ml = ml_confidence is not None
    ml_component = _clamp01(float(ml_confidence)) if has_ml else 0.0

    has_vt = vt_total is not None and vt_total > 0
    if has_vt:
        vt_component = _clamp01(float(vt_positives or 0) / float(vt_total))
    else:
        vt_component = 0.0

    weights = {
        "ml": ML_WEIGHT if has_ml else 0.0,
        "vt": VT_WEIGHT if has_vt else 0.0,
        "red_flags": RED_FLAG_WEIGHT if flags else 0.0,
    }
    weight_total = sum(weights.values())
    if weight_total == 0:
        # No signals at all — remain neutral/safe until analyzers are wired up.
        risk_score = 0.0
        normalized_weights = weights
    else:
        normalized_weights = {k: v / weight_total for k, v in weights.items()}
        raw = (
            normalized_weights["ml"] * ml_component
            + normalized_weights["vt"] * vt_component
            + normalized_weights["red_flags"] * red_flag_component
        )
        risk_score = round(_clamp(raw * 100.0, 0.0, 100.0), 2)

    verdict = verdict_from_score(risk_score)
    breakdown = {
        "ml_component": round(ml_component, 4),
        "vt_component": round(vt_component, 4),
        "red_flag_component": round(red_flag_component, 4),
        "weights_used": normalized_weights,
        "formula": (
            "score = 100 * (w_ml * ml_confidence + w_vt * (positives/total) "
            "+ w_flags * min(severity_sum/10, 1)); unused signals drop out "
            "and remaining weights are renormalized."
        ),
        "red_flags": flags,
        "vt_positives": vt_positives,
        "vt_total": vt_total,
        "ml_confidence": ml_confidence,
    }
    return RiskScoreResult(risk_score=risk_score, verdict=verdict, breakdown=breakdown)


def _clamp01(value: float) -> float:
    return _clamp(value, 0.0, 1.0)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
