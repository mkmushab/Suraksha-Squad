"""
ASI:One Interactive Cards v1 & Agent Chat Protocol v0.3.0 payload builders.
Supports the 4-card live demo flow:
1. Form Card (Intake)
2. Progress Card (12-Agent Parallel Fan-Out)
3. Verdict Card (5 Evidence Lines + Skeptic Audit Note + Unverifiable Boundaries)
4. Action Card (1930 Cybercrime Draft, Bank Dispute Email, Family WhatsApp Alert)
"""

from __future__ import annotations
from typing import Any, Dict, List
from .models import FinalVerdictBundle, SpecialistReport


def build_intake_form_card() -> Dict[str, Any]:
    """Card 1: ASI:One Interactive Intake Form Card."""
    return {
        "version": "1.0",
        "type": "asi_interactive_card",
        "card_type": "form_card",
        "title": "Suraksha Squad — Paste Any Suspicious Message, Link, UPI, or Bill",
        "subtitle": "12 specialist agents inspect domains, pages, UPI handles, IFSC, GSTIN, phone numbers, and scam scripts in parallel.",
        "fields": [
            {
                "id": "raw_text",
                "label": "Suspicious SMS / WhatsApp / UPI / Link / Invoice Text",
                "type": "textarea",
                "required": True,
                "placeholder": "e.g., Dear consumer your electricity power will be disconnected tonight 9:30 PM...",
            },
            {
                "id": "channel_hint",
                "label": "Source Channel",
                "type": "select",
                "options": ["auto", "sms", "whatsapp", "upi", "email", "invoice", "call"],
                "default": "auto",
            },
            {
                "id": "raw_email_headers",
                "label": "Optional Email Headers (Authentication-Results / Reply-To)",
                "type": "textarea",
                "required": False,
            },
        ],
        "actions": [
            {"id": "investigate_now", "label": "Run 12-Agent Investigation", "style": "primary"},
            {"id": "try_safe_sample", "label": "Test Official Safe Link (Looks OK)", "style": "secondary"},
        ],
    }


def build_progress_card(request_id: str, reports: List[SpecialistReport]) -> Dict[str, Any]:
    """Card 2: ASI:One Live Multi-Agent Progress Card."""
    steps = []
    for rep in reports:
        steps.append({
            "agent_id": rep.agent_id,
            "agent_name": rep.agent_name,
            "agent_address": rep.agent_address,
            "tool": rep.tool_name,
            "status": rep.status,
            "findings_count": len(rep.findings),
            "latency_ms": round(rep.execution_ms, 2),
        })
    return {
        "version": "1.0",
        "type": "asi_interactive_card",
        "card_type": "progress_card",
        "request_id": request_id,
        "title": "12-Agent Parallel Investigation Complete",
        "subtitle": "All checks executed in passive, read-only mode with strict SSRF protection.",
        "steps": steps,
    }


def build_verdict_card(bundle: FinalVerdictBundle) -> Dict[str, Any]:
    """Card 3: ASI:One Evidence-Backed Verdict Card (5 evidence lines + Skeptic note + Honest boundaries)."""
    color_map = {
        "HIGH_RISK_SCAM": "danger",
        "SUSPICIOUS_CAUTION": "warning",
        "LOOKS_OK": "success",
        "INSUFFICIENT_DATA": "neutral",
    }
    return {
        "version": "1.0",
        "type": "asi_interactive_card",
        "card_type": "verdict_card",
        "request_id": bundle.request_id,
        "verdict": bundle.verdict,
        "badge": bundle.verdict_badge,
        "theme": color_map.get(bundle.verdict, "neutral"),
        "title": bundle.headline,
        "explanation": bundle.concise_explanation,
        "evidence_lines": bundle.top_evidence_lines[:5],
        "skeptic_note": bundle.skeptic_audit.skeptic_note,
        "contradictions_caught": bundle.skeptic_audit.contradictions_found,
        "cannot_verify_offline": bundle.skeptic_audit.unverifiable_boundaries,
        "epistemic_policy": "Verdict derived 100% from deterministic tool evidence (no fabricated LLM confidence percentages).",
    }


def build_action_card(bundle: FinalVerdictBundle) -> Dict[str, Any]:
    """Card 4: ASI:One Citizen Protective Action Card (1930 report, Bank email, Family WhatsApp alert)."""
    return {
        "version": "1.0",
        "type": "asi_interactive_card",
        "card_type": "action_card",
        "request_id": bundle.request_id,
        "title": "Protective Action Drafts (User-Controlled — Nothing Sent Automatically)",
        "disclaimer": bundle.action_drafts.safety_disclaimer,
        "drafts": {
            "cybercrime_1930_portal": bundle.action_drafts.cybercrime_1930_report,
            "bank_nodal_email": {
                "subject": bundle.action_drafts.bank_dispute_email_subject,
                "body": bundle.action_drafts.bank_dispute_email_body,
            },
            "family_whatsapp_alert": bundle.action_drafts.family_whatsapp_alert_hi_en,
        },
        "buttons": [
            {"id": "copy_1930_draft", "label": "Copy 1930 / cybercrime.gov.in Complaint", "style": "primary"},
            {"id": "copy_bank_email", "label": "Copy Bank Dispute Email", "style": "secondary"},
            {"id": "copy_family_alert", "label": "Copy Hinglish Family Alert", "style": "secondary"},
        ],
    }


def to_asi_wire_metadata(card_kind: str, payload: Dict[str, Any], terminal: bool = False, drawer_width: int = 540) -> Dict[str, str]:
    """
    Formats an Interactive Card into the exact Fetch.ai Innovation Lab ASI:One wire metadata dictionary:
    `card_protocol_version="1"`, `requires_card_interaction`, `card_kind`, `card_payload` (JSON string <= 64 KB).
    """
    import json
    body = json.dumps(payload, ensure_ascii=False)
    if len(body.encode("utf-8")) > 64 * 1024:
        raise ValueError("card_payload exceeds 64 KB limit")
    meta = {
        "card_protocol_version": "1",
        "requires_card_interaction": "false" if terminal else "true",
        "card_kind": card_kind,
        "card_payload": body,
        "preferred_drawer_width_px": str(drawer_width),
    }
    if terminal:
        meta["is_terminal"] = "true"
    return meta
