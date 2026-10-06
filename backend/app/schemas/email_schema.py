"""Pydantic models for email / phishing scan responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NestedScanSummary(BaseModel):
    """A child URL or file scan triggered while inspecting an email."""

    id: int
    scan_type: str
    input_value: str
    verdict: str
    risk_score: float


class EmailScanResponse(BaseModel):
    """Result returned after an email scan, including nested URL/file scans."""

    id: int
    scan_type: str = "email"
    input_value: str = Field(..., description="Sender and/or subject used as the scan label.")
    verdict: str
    risk_score: float
    details: dict[str, Any] = Field(default_factory=dict)
    nested_scans: list[NestedScanSummary] = Field(default_factory=list)
    created_at: datetime
