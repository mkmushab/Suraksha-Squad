"""
ASI:One LLM Client (`https://api.asi1.ai/v1/chat/completions`, model `asi1-mini`).
STRICT RULE: The verdict (`HIGH_RISK_SCAM`, `SUSPICIOUS_CAUTION`, `LOOKS_OK`) is NEVER decided by the LLM.
Deterministic specialist tools + Skeptic Agent lock the verdict first; `asi1-mini` only translates
the verified tool evidence into a clear, empathetic Hinglish/English summary when `ASI1_API_KEY` is active.
"""

from __future__ import annotations
import os
from typing import List, Optional
import requests


def get_asi1_api_key() -> str:
    return os.getenv("ASI1_API_KEY", "").strip()


def explain_verdict_with_asi1(
    verdict: str,
    evidence_lines: List[str],
    skeptic_note: str,
    timeout_sec: float = 2.5,
) -> dict:
    """
    Generates a concise citizen-friendly explanation from deterministic tool evidence.
    Never alters `verdict` and never invents confidence percentages.
    """
    default_explanation = (
        f"Suraksha Squad's 12 agents audited your submission using deterministic passive tools "
        f"(DNS/RDAP/SSRF domain forensics, DOM form inspection, Hindi/Hinglish coercion patterns, "
        f"NPCI UPI/IFSC registries, Modulo-36 GSTIN math, and TRAI helpline rules). "
        f"Verdict `{verdict}` is grounded strictly in tool evidence — never LLM guesses."
    )

    api_key = get_asi1_api_key()
    base_url = os.getenv("ASI1_BASE_URL", "https://api.asi1.ai/v1").rstrip("/")
    model = os.getenv("ASI1_MODEL", "asi1-mini").strip()

    if not api_key or api_key.startswith("asi1_demo_"):
        return {
            "explanation": default_explanation,
            "llm_used": False,
            "model": model,
            "key_configured": bool(api_key),
        }

    prompt = (
        "You are explaining a locked, deterministic fraud investigation verdict to an Indian user.\n"
        f"LOCKED VERDICT (DO NOT CHANGE): {verdict}\n"
        "Verified Tool Evidence:\n"
        + "\n".join(f"- {e}" for e in evidence_lines[:5])
        + f"\nSkeptic Cross-Check: {skeptic_note}\n"
        "Write a 2-sentence explanation in clear English/Hinglish. Do NOT invent any percentage score."
    )

    try:
        resp = requests.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 140,
            },
            timeout=timeout_sec,
        )
        if resp.status_code == 200:
            data = resp.json()
            text = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )
            if text:
                return {
                    "explanation": text,
                    "llm_used": True,
                    "model": model,
                    "key_configured": True,
                }
    except Exception:
        pass

    return {
        "explanation": default_explanation,
        "llm_used": False,
        "model": model,
        "key_configured": True,
    }
