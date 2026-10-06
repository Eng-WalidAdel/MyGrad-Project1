"""URL scan routes."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers import persist_scan
from app.schemas.url_schema import URLScanRequest, URLScanResponse
from app.services.url_analyzer import analyze_url

router = APIRouter(prefix="/scan", tags=["URL Scan"])


@router.post("/url", response_model=URLScanResponse)
async def scan_url(payload: URLScanRequest, db: Session = Depends(get_db)) -> URLScanResponse:
    """Analyze a URL and persist the unified risk result."""
    url = str(payload.url)
    result = await analyze_url(url, db=db)
    row = persist_scan(
        db,
        scan_type="url",
        input_value=result["input_value"],
        verdict=result["verdict"],
        risk_score=result["risk_score"],
        ml_details=result.get("ml_details"),
        vt_details=result.get("vt_details"),
    )
    return URLScanResponse(
        id=row.id,
        input_value=row.input_value,
        verdict=row.verdict,
        risk_score=row.risk_score,
        details=result.get("details") or {},
        created_at=row.created_at,
    )
