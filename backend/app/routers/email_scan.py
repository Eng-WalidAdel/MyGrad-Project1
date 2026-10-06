"""Email / phishing scan routes."""

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers import persist_scan
from app.schemas.email_schema import EmailScanResponse, NestedScanSummary
from app.services.email_analyzer import analyze_email

router = APIRouter(prefix="/scan", tags=["Email Scan"])


@router.post("/email", response_model=EmailScanResponse)
async def scan_email(
    file: UploadFile | None = File(None, description="Optional .eml upload."),
    raw_text: str | None = Form(None, description="Optional raw RFC-822 email text."),
    db: Session = Depends(get_db),
) -> EmailScanResponse:
    """Scan an email from an .eml upload or pasted text.

    Nested URL and attachment scans are persisted as child rows; their IDs are
    stored on the parent in ``related_scans``.
    """
    if file is None and not (raw_text and raw_text.strip()):
        raise HTTPException(
            status_code=400,
            detail="Provide an .eml file upload or raw_text form field.",
        )

    eml_bytes = await file.read() if file is not None else None
    source_name = file.filename if file is not None else "pasted-email"

    result = await analyze_email(
        raw_text=raw_text,
        eml_bytes=eml_bytes,
        source_name=source_name or "email",
        db=db,
    )

    nested_summaries: list[NestedScanSummary] = []
    related_ids: list[int] = []

    for child in result.get("nested_url_results") or []:
        child_row = persist_scan(
            db,
            scan_type="url",
            input_value=child["input_value"],
            verdict=child["verdict"],
            risk_score=child["risk_score"],
            ml_details=child.get("ml_details"),
            vt_details=child.get("vt_details"),
        )
        related_ids.append(child_row.id)
        nested_summaries.append(
            NestedScanSummary(
                id=child_row.id,
                scan_type="url",
                input_value=child_row.input_value,
                verdict=child_row.verdict,
                risk_score=child_row.risk_score,
            )
        )

    for child in result.get("nested_file_results") or []:
        child_row = persist_scan(
            db,
            scan_type="file",
            input_value=child["input_value"],
            verdict=child["verdict"],
            risk_score=child["risk_score"],
            ml_details=child.get("ml_details"),
            vt_details=child.get("vt_details"),
        )
        related_ids.append(child_row.id)
        nested_summaries.append(
            NestedScanSummary(
                id=child_row.id,
                scan_type="file",
                input_value=child_row.input_value,
                verdict=child_row.verdict,
                risk_score=child_row.risk_score,
            )
        )

    row = persist_scan(
        db,
        scan_type="email",
        input_value=result["input_value"],
        verdict=result["verdict"],
        risk_score=result["risk_score"],
        ml_details=result.get("ml_details"),
        vt_details=result.get("vt_details"),
        related_scans=related_ids or None,
    )
    return EmailScanResponse(
        id=row.id,
        input_value=row.input_value,
        verdict=row.verdict,
        risk_score=row.risk_score,
        details=result.get("details") or {},
        nested_scans=nested_summaries,
        created_at=row.created_at,
    )
