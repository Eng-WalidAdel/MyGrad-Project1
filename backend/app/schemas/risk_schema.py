"""Pydantic models for unified risk scoring and shared scan views."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RiskScoreResult(BaseModel):
    """Output of the unified risk scoring engine."""

    risk_score: float = Field(..., ge=0, le=100)
    verdict: str = Field(..., description='One of "safe", "suspicious", or "malicious".')
    breakdown: dict[str, Any] = Field(default_factory=dict)


class ScanHistoryItem(BaseModel):
    """Compact row for GET /scan/history."""

    id: int
    scan_type: str
    input_value: str
    verdict: str
    risk_score: float
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanDetailResponse(BaseModel):
    """Full record for GET /scan/{scan_id}."""

    id: int
    scan_type: str
    input_value: str
    verdict: str
    risk_score: float
    ml_details: dict[str, Any] | None = None
    vt_details: dict[str, Any] | None = None
    related_scans: list[Any] | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AssistantExplainRequest(BaseModel):
    """POST /assistant/explain — provide a stored scan id and/or raw result JSON."""

    scan_id: int | None = Field(None, description="ID of a persisted scan to explain.")
    scan_result: dict[str, Any] | None = Field(
        None,
        description="Raw scan result JSON if explaining without looking up the database.",
    )


class AssistantExplainResponse(BaseModel):
    """Plain-language explanation produced by the AI assistant."""

    explanation: str
    scan_id: int | None = None
    verdict: str | None = None
    risk_score: float | None = None
