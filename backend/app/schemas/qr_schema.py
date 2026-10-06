"""Pydantic models for QR scan responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class QRScanResponse(BaseModel):
    """Result returned after a QR image scan."""

    id: int
    scan_type: str = "qr"
    input_value: str = Field(..., description="Decoded QR payload (usually a URL).")
    verdict: str
    risk_score: float
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
