"""AI assistant routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_result import ScanResult
from app.schemas.risk_schema import AssistantExplainRequest, AssistantExplainResponse
from app.services.ai_assistant import explain_scan_result

router = APIRouter(prefix="/assistant", tags=["AI Assistant"])


@router.post("/explain", response_model=AssistantExplainResponse)
async def explain(
    payload: AssistantExplainRequest,
    db: Session = Depends(get_db),
) -> AssistantExplainResponse:
    """Explain a stored scan (by id) or a raw scan-result JSON blob."""
    if payload.scan_id is None and not payload.scan_result:
        raise HTTPException(
            status_code=400,
            detail="Provide scan_id and/or scan_result JSON.",
        )

    scan_id = payload.scan_id
    verdict = None
    risk_score = None
    details = {}
    scan_type = None
    input_value = None

    if payload.scan_id is not None:
        row = db.query(ScanResult).filter(ScanResult.id == payload.scan_id).first()
        if row is None:
            raise HTTPException(status_code=404, detail=f"Scan {payload.scan_id} not found.")
        scan_id = row.id
        verdict = row.verdict
        risk_score = row.risk_score
        scan_type = row.scan_type
        input_value = row.input_value
        details = {
            "ml_details": row.ml_details,
            "vt_details": row.vt_details,
            "related_scans": row.related_scans,
        }

    if payload.scan_result:
        raw = payload.scan_result
        verdict = raw.get("verdict", verdict)
        risk_score = raw.get("risk_score", risk_score)
        scan_type = raw.get("scan_type", scan_type)
        input_value = raw.get("input_value", input_value)
        extra = raw.get("details") or {}
        details = {**details, **extra, "raw_scan_result": raw}

    if verdict is None or risk_score is None:
        raise HTTPException(
            status_code=400,
            detail="Could not determine verdict and risk_score from the request.",
        )

    explanation = await explain_scan_result(
        verdict=verdict,
        risk_score=float(risk_score),
        details=details,
        scan_type=scan_type,
        input_value=input_value,
    )
    return AssistantExplainResponse(
        explanation=explanation,
        scan_id=scan_id,
        verdict=verdict,
        risk_score=float(risk_score),
    )
