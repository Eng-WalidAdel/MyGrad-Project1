"""Email / phishing analysis service.

Uses the Python standard-library ``email`` package to parse RFC-822 / ``.eml``
messages. Auth checks (SPF/DKIM/DMARC) are placeholders until a teammate
wires a real verifier.

Extracted URLs are passed to ``url_analyzer.analyze_url``. Attachment bytes
are passed to ``file_analyzer.analyze_file``.
"""

from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser, Parser
from typing import Any

from sqlalchemy.orm import Session

from app.services.file_analyzer import analyze_file
from app.services.risk_scoring import compute_risk_score
from app.services.url_analyzer import analyze_url

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


async def analyze_email(
    *,
    raw_text: str | None = None,
    eml_bytes: bytes | None = None,
    source_name: str = "email",
    db: Session | None = None,
) -> dict[str, Any]:
    """Parse an email, score phishing signals, and fan out nested URL/file scans.

    Provide either ``raw_text`` (paste) or ``eml_bytes`` (uploaded ``.eml``).
    """
    message = _parse_message(raw_text=raw_text, eml_bytes=eml_bytes)
    headers = _extract_headers(message)
    body_text = _extract_body(message)
    attachments = _extract_attachments(message)

    auth = check_email_authentication(headers)
    urls = extract_urls(body_text, attachments)

    red_flags: list[dict[str, Any]] = []
    if auth.get("spf") != "pass":
        red_flags.append({"name": "spf_not_pass", "severity": 4, "detail": f"SPF={auth.get('spf')}"})
    if auth.get("dkim") != "pass":
        red_flags.append({"name": "dkim_not_pass", "severity": 3, "detail": f"DKIM={auth.get('dkim')}"})
    if auth.get("dmarc") != "pass":
        red_flags.append({"name": "dmarc_not_pass", "severity": 4, "detail": f"DMARC={auth.get('dmarc')}"})
    if not headers.get("from"):
        red_flags.append({"name": "missing_from", "severity": 3, "detail": "No From header present."})

    nested_url_results: list[dict[str, Any]] = []
    # Hand each extracted link to the URL analyzer (same pipeline as POST /scan/url).
    for url in urls:
        nested_url_results.append(await analyze_url(url, db=db))

    nested_file_results: list[dict[str, Any]] = []
    # Hand each attachment to the file analyzer (same pipeline as POST /scan/file).
    for attachment in attachments:
        nested_file_results.append(
            await analyze_file(
                attachment["content"],
                attachment["filename"],
                attachment.get("content_type"),
            )
        )

    child_scores = [item["risk_score"] for item in nested_url_results + nested_file_results]
    if child_scores:
        # Nested malicious objects escalate the parent email score.
        max_child = max(child_scores)
        if max_child >= 71:
            red_flags.append(
                {
                    "name": "malicious_nested_content",
                    "severity": 8,
                    "detail": "A linked URL or attachment scored as malicious.",
                }
            )
        elif max_child >= 31:
            red_flags.append(
                {
                    "name": "suspicious_nested_content",
                    "severity": 5,
                    "detail": "A linked URL or attachment scored as suspicious.",
                }
            )

    # Placeholder phishing-intent model until the email ML model exists.
    ml_confidence = 0.25 if red_flags else 0.07
    ml_details = {
        "model": "email_phishing_placeholder",
        "confidence": ml_confidence,
        "note": "Replace with header+body ML features once the model is trained.",
    }

    scored = compute_risk_score(ml_confidence=ml_confidence, red_flags=red_flags)
    subject = headers.get("subject") or "(no subject)"
    sender = headers.get("from") or "(unknown sender)"
    input_value = f"{sender} | {subject}"

    return {
        "input_value": input_value[:2048],
        "verdict": scored.verdict,
        "risk_score": scored.risk_score,
        "ml_details": ml_details,
        "vt_details": None,
        "nested_url_results": nested_url_results,
        "nested_file_results": nested_file_results,
        "details": {
            "source_name": source_name,
            "headers": headers,
            "authentication": auth,
            "extracted_urls": urls,
            "attachment_names": [item["filename"] for item in attachments],
            "body_preview": body_text[:500],
            "risk_breakdown": scored.breakdown,
        },
    }


def parse_eml_bytes(eml_bytes: bytes) -> EmailMessage:
    """Parse a ``.eml`` file with the stdlib ``email`` package (BytesParser)."""
    return BytesParser(policy=policy.default).parsebytes(eml_bytes)


def parse_raw_text(raw_text: str) -> EmailMessage:
    """Parse pasted RFC-822 text with the stdlib ``email`` package (Parser)."""
    return Parser(policy=policy.default).parsestr(raw_text)


def check_email_authentication(headers: dict[str, str]) -> dict[str, str]:
    """Placeholder SPF/DKIM/DMARC extraction from Authentication-Results.

    A later implementation should:
        * Parse ``Authentication-Results`` / ``Received-SPF`` headers properly.
        * Optionally re-query DNS (SPF records, DKIM public keys, DMARC TXT).
        * Never treat missing headers as a pass.

    Mock behavior: look for obvious tokens in Authentication-Results; otherwise
    return ``neutral`` so the risk engine still has a signal to work with.
    """
    auth_header = (headers.get("authentication-results") or "").lower()
    received_spf = (headers.get("received-spf") or "").lower()

    def _status(method: str, fallback: str = "neutral") -> str:
        for token in ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"):
            if f"{method}={token}" in auth_header:
                return token
        return fallback

    spf = _status("spf")
    if spf == "neutral" and received_spf:
        for token in ("pass", "fail", "softfail", "neutral"):
            if token in received_spf:
                spf = token
                break

    return {
        "spf": spf,
        "dkim": _status("dkim"),
        "dmarc": _status("dmarc"),
        "source": "placeholder_header_parse",
    }


def extract_urls(body_text: str, attachments: list[dict[str, Any]]) -> list[str]:
    """Collect http(s) URLs from the body and attachment metadata/filenames.

    These strings should be passed to ``url_analyzer.analyze_url``.
    """
    found = URL_RE.findall(body_text or "")
    for attachment in attachments:
        name = attachment.get("filename") or ""
        found.extend(URL_RE.findall(name))
        ctype = attachment.get("content_type") or ""
        found.extend(URL_RE.findall(ctype))
    # Preserve order, drop duplicates.
    unique: list[str] = []
    seen: set[str] = set()
    for url in found:
        cleaned = url.rstrip(").,];")
        if cleaned not in seen:
            seen.add(cleaned)
            unique.append(cleaned)
    return unique


def _parse_message(*, raw_text: str | None, eml_bytes: bytes | None) -> EmailMessage:
    if eml_bytes:
        return parse_eml_bytes(eml_bytes)
    if raw_text:
        return parse_raw_text(raw_text)
    raise ValueError("Provide raw_text or eml_bytes.")


def _extract_headers(message: EmailMessage) -> dict[str, str]:
    keys = [
        "from",
        "to",
        "subject",
        "date",
        "reply-to",
        "return-path",
        "authentication-results",
        "received-spf",
        "dkim-signature",
    ]
    return {key: str(message.get(key, "") or "") for key in keys}


def _extract_body(message: EmailMessage) -> str:
    if message.is_multipart():
        parts: list[str] = []
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            if ctype in {"text/plain", "text/html"}:
                try:
                    parts.append(part.get_content())
                except Exception:  # noqa: BLE001
                    payload = part.get_payload(decode=True) or b""
                    parts.append(payload.decode("utf-8", errors="replace"))
        return "\n".join(parts)
    try:
        return str(message.get_content())
    except Exception:  # noqa: BLE001
        payload = message.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _extract_attachments(message: EmailMessage) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for part in message.walk():
        if part.get_content_disposition() != "attachment":
            continue
        filename = part.get_filename() or "unnamed-attachment"
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            {
                "filename": filename,
                "content": payload,
                "content_type": part.get_content_type(),
            }
        )
    return attachments
