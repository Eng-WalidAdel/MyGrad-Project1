"""File scan routes."""

from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers import persist_scan
from app.schemas.file_schema import FileScanResponse
from app.services.file_analyzer import analyze_file

router = APIRouter(prefix="/scan", tags=["File Scan"])


@router.post("/file", response_model=FileScanResponse)
async def scan_file(
    file: UploadFile = File(..., description="File to analyze (any type)."),
    db: Session = Depends(get_db),
) -> FileScanResponse:
    """Accept a multipart file upload, run static analysis, and persist the result."""
    content = await file.read()
    filename = file.filename or "uploaded-file"
    result = await analyze_file(content, filename, file.content_type)
    row = persist_scan(
        db,
        scan_type="file",
        input_value=result["input_value"],
        verdict=result["verdict"],
        risk_score=result["risk_score"],
        ml_details=result.get("ml_details"),
        vt_details=result.get("vt_details"),
    )
    return FileScanResponse(
        id=row.id,
        input_value=row.input_value,
        filename=filename,
        verdict=row.verdict,
        risk_score=row.risk_score,
        details=result.get("details") or {},
        created_at=row.created_at,
    )
