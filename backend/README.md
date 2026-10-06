# Multi-Vector Malicious Content Scanner — Backend

This FastAPI service is the backend for a graduation project that detects malicious content from **URLs**, **files**, **QR codes**, and **emails/phishing attempts**. Each analyzer produces raw signals that a unified **risk scoring** engine turns into a 0–100 score and a verdict (`safe`, `suspicious`, or `malicious`). An **AI assistant** then explains the result in plain language and suggests practical next steps for the user.

## Setup

```bash
cd backend
python -m venv venv
```

Activate the virtual environment:

- Windows (PowerShell): `.\venv\Scripts\Activate.ps1`
- macOS / Linux: `source venv/bin/activate`

Install dependencies:

```bash
pip install -r requirements.txt
```

Copy the environment template and add your API keys:

```bash
cp .env.example .env
```

On Windows you can use `copy .env.example .env`. Edit `.env` and set `VIRUSTOTAL_API_KEY` and `ANTHROPIC_API_KEY`. `DATABASE_URL` defaults to a local SQLite file (`scanner.db`) if you leave it unchanged.

## How to run

From the `backend/` directory (with the venv active):

```bash
uvicorn app.main:app --reload
```

The API listens on [http://127.0.0.1:8000](http://127.0.0.1:8000). Interactive **Swagger docs** are available at `/docs` (ReDoc at `/redoc`). A health check at `GET /` returns `{"status": "running"}`.

## Team structure

Four people own these tracks (they overlap at the API contracts in this repo):

1. **ML models** — train and load models under `app/ml/` for URL, file, and email classification.
2. **QR / file / email parsing** — decode QR images, static-analyze files, and parse `.eml` messages (headers, body, attachments, auth results).
3. **Backend / risk scoring** — FastAPI routes, persistence, VirusTotal client, and the unified 0–100 scoring formula.
4. **Frontend / AI assistant integration** — client UI plus wiring scan results into `POST /assistant/explain`.
