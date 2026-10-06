"""Anthropic-backed security-awareness assistant.

The system prompt MUST instruct the model to act as a security awareness
assistant, not a general chatbot. Do not hardcode API keys — they are loaded
from ANTHROPIC_API_KEY via ``app.config.settings``.
"""

from __future__ import annotations

import json
from typing import Any

from app.config import settings

# System prompt: security awareness assistant only — not a general chatbot.
SYSTEM_PROMPT = (
    "You are a security awareness assistant for a Multi-Vector Malicious "
    "Content Scanner. You are NOT a general-purpose chatbot. Stay strictly "
    "on explaining scan verdicts, risk scores, and practical safety steps. "
    "Do not answer unrelated questions, do not provide exploit instructions, "
    "and do not help a user bypass security controls. Use clear, non-technical "
    "language suitable for students and non-expert users. Always include 2–3 "
    "concrete next steps the user should take based on the verdict."
)

MODEL_NAME = "claude-sonnet-4-6"


async def explain_scan_result(
    *,
    verdict: str,
    risk_score: float,
    details: dict[str, Any] | None = None,
    scan_type: str | None = None,
    input_value: str | None = None,
) -> str:
    """Build a prompt from a scan result and return a plain-language explanation.

    Calls Anthropic Messages API when ANTHROPIC_API_KEY is set. If the key is
    missing (typical in local scaffolding), returns a deterministic fallback
    so the rest of the API still works for teammates without LLM access.
    """
    user_prompt = _build_user_prompt(
        verdict=verdict,
        risk_score=risk_score,
        details=details or {},
        scan_type=scan_type,
        input_value=input_value,
    )

    api_key = settings.ANTHROPIC_API_KEY
    if not api_key:
        return _fallback_explanation(verdict=verdict, risk_score=risk_score, scan_type=scan_type)

    from anthropic import AsyncAnthropic

    client = AsyncAnthropic(api_key=api_key)
    message = await client.messages.create(
        model=MODEL_NAME,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return message.content[0].text


def _build_user_prompt(
    *,
    verdict: str,
    risk_score: float,
    details: dict[str, Any],
    scan_type: str | None,
    input_value: str | None,
) -> str:
    payload = {
        "scan_type": scan_type,
        "input_value": input_value,
        "verdict": verdict,
        "risk_score": risk_score,
        "details": details,
    }
    return (
        "Explain the following malicious-content scan result in plain language. "
        "Then suggest 2-3 concrete next steps for the user (what to click, "
        "what not to open, who to report it to, whether to delete the file, etc.).\n\n"
        f"{json.dumps(payload, default=str, indent=2)}"
    )


def _fallback_explanation(*, verdict: str, risk_score: float, scan_type: str | None) -> str:
    """Used when ANTHROPIC_API_KEY is not configured."""
    kind = scan_type or "item"
    if verdict == "malicious":
        steps = (
            "1. Do not open, click, or forward the content.\n"
            "2. Disconnect the download or close the tab if it is still active.\n"
            "3. Report the item to your administrator or instructor and delete it."
        )
    elif verdict == "suspicious":
        steps = (
            "1. Avoid interacting with the content until it is reviewed.\n"
            "2. Compare the sender or URL with a known-good source.\n"
            "3. Ask a trusted reviewer before opening attachments or scanning the QR again."
        )
    else:
        steps = (
            "1. You can treat this as low risk, but stay cautious with unexpected prompts.\n"
            "2. Keep your browser and OS updated.\n"
            "3. Re-scan if the same source starts behaving unusually."
        )
    return (
        f"This {kind} scan scored {risk_score}/100 and was labeled '{verdict}'. "
        "A live LLM explanation is unavailable because ANTHROPIC_API_KEY is not set. "
        "Recommended next steps:\n"
        f"{steps}"
    )
