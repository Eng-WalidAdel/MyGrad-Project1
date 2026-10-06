"""ORM model for persisted scan results."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanResult(Base):
    """A single scan produced by any analyzer (URL, file, QR, or email)."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, index=True)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    input_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    ml_details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    vt_details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    related_scans: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
