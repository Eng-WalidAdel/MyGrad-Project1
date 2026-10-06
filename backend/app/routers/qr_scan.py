"""QR scan routes."""

from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers import persist_scan
from app.schemas.qr_schema import QRScanResponse
from app.services.qr_decoder import decode_and_analyze_qr

router = APIRouter(prefix="/scan", tags=["QR Scan"])


@router.post("/qr", response_model=QRScanResponse)
async def scan_qr(
    file: UploadFile = File(..., description="Image containing a QR code."),
    db: Session = Depends(get_db),
) -> QRScanResponse:
    """Decode a QR image, score the payload (and nested URL if present), persist."""
    image_bytes = await file.read()
    result = await decode_and_analyze_qr(image_bytes, db=db)
    row = persist_scan(
        db,
        scan_type="qr",
        input_value=result["input_value"],
        verdict=result["verdict"],
        risk_score=result["risk_score"],
        ml_details=result.get("ml_details"),
        vt_details=result.get("vt_details"),
    )
    return QRScanResponse(
        id=row.id,
        input_value=row.input_value,
        verdict=row.verdict,
        risk_score=row.risk_score,
        details=result.get("details") or {},
        created_at=row.created_at,
    )
