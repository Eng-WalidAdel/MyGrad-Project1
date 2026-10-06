"""API routers.

GET /scan/history and GET /scan/{scan_id} live here so every scan type shares
one history API without an extra module outside the requested tree.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_result import ScanResult
from app.schemas.risk_schema import ScanDetailResponse, ScanHistoryItem

history_router = APIRouter(prefix="/scan", tags=["Scan History"])


@history_router.get("/history", response_model=list[ScanHistoryItem])
async def list_scan_history(db: Session = Depends(get_db)) -> list[ScanResult]:
    """Return past scans, newest first."""
    return db.query(ScanResult).order_by(ScanResult.created_at.desc()).all()


@history_router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanResult:
    """Return a single persisted scan, including ML/VT/related-scan payloads."""
    row = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return row


def persist_scan(
    db: Session,
    *,
    scan_type: str,
    input_value: str,
    verdict: str,
    risk_score: float,
    ml_details: dict | None = None,
    vt_details: dict | None = None,
    related_scans: list | None = None,
) -> ScanResult:
    """Store a scan row and refresh so callers receive a database id."""
    row = ScanResult(
        scan_type=scan_type,
        input_value=input_value,
        verdict=verdict,
        risk_score=risk_score,
        ml_details=ml_details,
        vt_details=vt_details,
        related_scans=related_scans,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
