"""Pydantic models for URL scan requests and responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class URLScanRequest(BaseModel):
    """Incoming payload for POST /scan/url."""

    url: HttpUrl = Field(..., description="The URL to analyze.")


class URLScanResponse(BaseModel):
    """Result returned after a URL scan."""

    id: int
    scan_type: str = "url"
    input_value: str
    verdict: str
    risk_score: float
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
