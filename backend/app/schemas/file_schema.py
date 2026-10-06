"""Pydantic models for file scan responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FileScanResponse(BaseModel):
    """Result returned after a file scan (multipart upload)."""

    id: int
    scan_type: str = "file"
    input_value: str = Field(..., description="SHA-256 hash (or filename) of the uploaded file.")
    filename: str
    verdict: str
    risk_score: float
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
