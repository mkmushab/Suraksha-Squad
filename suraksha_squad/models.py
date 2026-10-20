"""
Typed uAgents message models for Suraksha Squad's 12 agents + ASI:One Chat Protocol v0.3.0.
Every specialist returns structured, deterministic tool evidence and explicit verification boundaries.
"""

from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional
from .uagents_compat import Model

# uAgents' Model is pydantic v1 on recent releases (uagents-core 0.4+), pydantic v2 elsewhere.
# Nested models and Field() must come from the SAME pydantic flavour as Model, or import fails.
try:
    from pydantic.v1 import BaseModel as _V1Base
    _IS_V1 = issubclass(Model, _V1Base)
except ImportError:  # pragma: no cover
    _IS_V1 = False
if _IS_V1:
    from pydantic.v1 import Field
else:  # pragma: no cover
    from pydantic import Field


VerdictLevel = Literal["HIGH_RISK_SCAM", "SUSPICIOUS_CAUTION", "LOOKS_OK", "INSUFFICIENT_DATA"]
SignalSeverity = Literal["CRITICAL", "WARN", "SAFE", "INFO", "UNVERIFIABLE"]


class EvidenceItem(Model):
    agent_id: str
    agent_name: str
    tool_used: str
    severity: SignalSeverity
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
    verifiable: bool = True
    unverifiable_reason: Optional[str] = None


class InvestigationRequest(Model):
    request_id: str
    raw_text: str
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_upis: List[str] = Field(default_factory=list)
    extracted_ifsccodes: List[str] = Field(default_factory=list)
    extracted_gstins: List[str] = Field(default_factory=list)
    extracted_phones: List[str] = Field(default_factory=list)
    raw_email_headers: Optional[str] = None
    channel_hint: Optional[str] = None  # sms, whatsapp, email, upi, call, invoice, web


class SpecialistReport(Model):
    request_id: str
    agent_id: str
    agent_name: str
    agent_address: str
    tool_name: str
    status: Literal["COMPLETED", "SKIPPED", "BLOCKED_BY_SSRF", "ERROR"] = "COMPLETED"
    risk_points: int = 0       # Deterministic risk contribution (never displayed as fake % probability)
    trust_points: int = 0      # Deterministic positive verification contribution
    findings: List[EvidenceItem] = Field(default_factory=list)
    unverifiable_notes: List[str] = Field(default_factory=list)
    execution_ms: float = 0.0


class SkepticAuditReport(Model):
    request_id: str
    agent_id: str = "agent_11_skeptic"
    agent_name: str = "suraksha_skeptic"
    agent_address: str
    contradictions_found: List[str] = Field(default_factory=list)
    unverifiable_boundaries: List[str] = Field(default_factory=list)
    adjusted_verdict: VerdictLevel
    skeptic_note: str
    execution_ms: float = 0.0


class ActionDraftsReport(Model):
    request_id: str
    agent_id: str = "agent_12_action"
    agent_name: str = "suraksha_action_agent"
    agent_address: str
    cybercrime_1930_report: str
    bank_dispute_email_subject: str
    bank_dispute_email_body: str
    family_whatsapp_alert_hi_en: str
    safety_disclaimer: str = (
        "Passive Draft Mode: Suraksha Squad never auto-submits complaints, calls numbers, "
        "or sends emails on your behalf. Review and file directly via 1930 or cybercrime.gov.in."
    )
    execution_ms: float = 0.0


class FinalVerdictBundle(Model):
    request_id: str
    verdict: VerdictLevel
    verdict_badge: str
    headline: str
    concise_explanation: str
    top_evidence_lines: List[str]
    skeptic_audit: SkepticAuditReport
    action_drafts: ActionDraftsReport
    specialist_reports: List[SpecialistReport]
    interactive_cards: Dict[str, Dict[str, Any]]
    context_dev_enrichment: Dict[str, Any] = Field(default_factory=dict)
    asi1_llm_metadata: Dict[str, Any] = Field(default_factory=dict)
    total_execution_ms: float
