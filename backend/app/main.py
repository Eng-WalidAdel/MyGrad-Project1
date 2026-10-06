"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.models.scan_result import ScanResult  # noqa: F401 — register metadata
from app.routers import assistant, email_scan, file_scan, history_router, qr_scan, url_scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup so a fresh clone can run immediately."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Multi-Vector Malicious Content Scanner API",
    description=(
        "Detects malicious content from URLs, files, QR codes, and emails, "
        "then aggregates signals into a unified risk score with an AI assistant "
        "that explains results to the user."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Frontend is a separate app during development; allow all origins for now.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(history_router)
app.include_router(url_scan.router)
app.include_router(file_scan.router)
app.include_router(qr_scan.router)
app.include_router(email_scan.router)
app.include_router(assistant.router)


@app.get("/", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Simple liveness probe for local development and deployment checks."""
    return {"status": "running"}
