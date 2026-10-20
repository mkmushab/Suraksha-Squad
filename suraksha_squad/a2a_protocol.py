"""
Real Inter-Agent uAgents Protocol (`suraksha-forensics-a2a v1.0.0`) for Suraksha Squad.

Implements genuine `await ctx.send_and_receive(...)` communication between:
1. `suraksha_concierge` (`:8001` — ASI:One Front Door Orchestrator)
2. `suraksha_domain_forensics` (`:8002` — Domain, Page, Reputation & Context.dev Specialist uAgent)
3. `suraksha_message_analyst` (`:8004` — Coercion Lexicon, Phone, Email SPF/DKIM/DMARC & Pattern Specialist uAgent)
4. `suraksha_upi_verifier` (`:8005` — NPCI UPI VPA, Collect Trap, IFSC & Modulo-36 GSTIN Specialist uAgent)
5. `suraksha_action_agent` (`:8012` — Epistemic Skeptic Cross-Check & 1930 / Bank / Family Alert Specialist uAgent)

If any specialist uAgent process is unreachable (e.g., in `--degraded` mode), `suraksha_concierge`
logs the failure, executes the deterministic specialist pipeline locally, and explicitly marks
`degraded = True` in the provenance trail.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .agents import (
    AGENT_SPECS,
    build_action_card,
    build_intake_form_card,
    build_progress_card,
    build_verdict_card,
    enrich_with_context_dev,
    explain_verdict_with_asi1,
    run_action_agent,
    run_domain_forensics_agent,
    run_email_auditor_agent,
    run_gst_verifier_agent,
    run_message_analyst_agent,
    run_page_analyst_agent,
    run_pattern_matcher_agent,
    run_phone_checker_agent,
    run_reputation_agent,
    run_skeptic_agent,
    run_upi_verifier_agent,
)
from .extractors import build_investigation_request
from .models import (
    ActionDraftsReport,
    EvidenceItem,
    FinalVerdictBundle,
    InvestigationRequest,
    SkepticAuditReport,
    SpecialistReport,
    VerdictLevel,
)
from .uagents_compat import Agent, Context, Model, Protocol, derive_agent_address

A2A_TIMEOUT = 15


# ── Typed uAgents Models for Real `ctx.send_and_receive` Exchange ──

class ForensicSpecialistRequest(Model):
    request_id: str
    raw_text: str
    channel_hint: str = "auto"
    raw_email_headers: str = ""


class ForensicSpecialistResponse(Model):
    request_id: str
    specialist_group: str
    agent_name: str
    agent_address: str
    ok: bool = True
    error: str = ""
    reports_json: str = "[]"


class SkepticActionRequest(Model):
    request_id: str
    raw_text: str
    channel_hint: str = "auto"
    raw_email_headers: str = ""
    reports_json: str = "[]"


class SkepticActionResponse(Model):
    request_id: str
    agent_name: str
    agent_address: str
    ok: bool = True
    error: str = ""
    skeptic_json: str = "{}"
    action_json: str = "{}"
    top_evidence_json: str = "[]"


# ── Deterministic Address Helpers for the 5 Core Live uAgents ──

def _spec_by_id(agent_id: str) -> Dict[str, Any]:
    return next(s for s in AGENT_SPECS if s["id"] == agent_id)


def get_seed_for(agent_id: str) -> str:
    spec = _spec_by_id(agent_id)
    return os.getenv(spec["seed_env"], spec["default_seed"]).strip() or spec["default_seed"]


def concierge_address() -> str:
    return derive_agent_address(get_seed_for("agent_01_concierge"))


def domain_specialist_address() -> str:
    return derive_agent_address(get_seed_for("agent_02_domain"))


def message_specialist_address() -> str:
    return derive_agent_address(get_seed_for("agent_04_message"))


def upi_gst_specialist_address() -> str:
    return derive_agent_address(get_seed_for("agent_05_upi"))


def action_specialist_address() -> str:
    return derive_agent_address(get_seed_for("agent_12_action"))


def short_addr(addr: str) -> str:
    return f"{addr[:12]}…{addr[-6:]}" if addr and len(addr) > 20 else addr


def _dump_model(m: Any) -> Dict[str, Any]:
    return m.model_dump() if hasattr(m, "model_dump") else m.dict()


# ── Specialist Execution Helpers (Used by Specialist uAgents & Degraded Fallback) ──

def execute_domain_group(req: InvestigationRequest) -> List[SpecialistReport]:
    """Runs Domain Forensics + Page Analyst + Threat Reputation."""
    return [
        run_domain_forensics_agent(req),
        run_page_analyst_agent(req),
        run_reputation_agent(req),
    ]


def execute_message_group(req: InvestigationRequest) -> List[SpecialistReport]:
    """Runs Message Coercion Analyst + Phone Checker + Email SPF/DKIM/DMARC Auditor + Scam Pattern Matcher."""
    return [
        run_message_analyst_agent(req),
        run_phone_checker_agent(req),
        run_email_auditor_agent(req),
        run_pattern_matcher_agent(req),
    ]


def execute_upi_gst_group(req: InvestigationRequest) -> List[SpecialistReport]:
    """Runs NPCI UPI/IFSC Verifier + Modulo-36 GSTIN Verifier."""
    return [
        run_upi_verifier_agent(req),
        run_gst_verifier_agent(req),
    ]


def execute_skeptic_and_action_group(
    req: InvestigationRequest,
    specialist_reports: List[SpecialistReport],
) -> tuple[SkepticAuditReport, ActionDraftsReport, List[str]]:
    """Runs Epistemic Skeptic Cross-Check + 1930 / Bank / Family WhatsApp Action Generator."""
    skeptic_audit = run_skeptic_agent(req, specialist_reports)
    verdict = skeptic_audit.adjusted_verdict
    severity_rank = {"CRITICAL": 0, "WARN": 1, "SAFE": 2, "INFO": 3, "UNVERIFIABLE": 4}
    all_findings: List[EvidenceItem] = [f for rep in specialist_reports for f in rep.findings]
    all_findings.sort(key=lambda x: severity_rank.get(x.severity, 9))
    top_evidence_lines = [
        f"[{f.severity}] {f.agent_name} ({f.tool_used}): {f.summary}"
        for f in all_findings[:5]
    ]
    action_drafts = run_action_agent(req, verdict, top_evidence_lines)
    return skeptic_audit, action_drafts, top_evidence_lines


# ── Protocol Builders for the 4 Specialist uAgents ──

def build_domain_specialist_protocol() -> Protocol:
    proto = Protocol(name="suraksha-domain-a2a", version="1.0.0")

    @proto.on_message(model=ForensicSpecialistRequest, replies={ForensicSpecialistResponse})
    async def on_domain_req(ctx: Context, sender: str, msg: ForensicSpecialistRequest) -> None:
        ctx.logger.info(f"[suraksha_domain_forensics] A2A request {msg.request_id} from {short_addr(sender)}")
        req = build_investigation_request(
            raw_text=msg.raw_text,
            request_id=msg.request_id,
            channel_hint=msg.channel_hint or None,
            raw_email_headers=msg.raw_email_headers or None,
        )
        reports = await asyncio.to_thread(execute_domain_group, req)
        await ctx.send(
            sender,
            ForensicSpecialistResponse(
                request_id=msg.request_id,
                specialist_group="domain_page_reputation",
                agent_name="suraksha_domain_forensics",
                agent_address=domain_specialist_address(),
                ok=True,
                reports_json=json.dumps([_dump_model(r) for r in reports], ensure_ascii=False),
            ),
        )

    return proto


def build_message_specialist_protocol() -> Protocol:
    proto = Protocol(name="suraksha-message-a2a", version="1.0.0")

    @proto.on_message(model=ForensicSpecialistRequest, replies={ForensicSpecialistResponse})
    async def on_message_req(ctx: Context, sender: str, msg: ForensicSpecialistRequest) -> None:
        ctx.logger.info(f"[suraksha_message_analyst] A2A request {msg.request_id} from {short_addr(sender)}")
        req = build_investigation_request(
            raw_text=msg.raw_text,
            request_id=msg.request_id,
            channel_hint=msg.channel_hint or None,
            raw_email_headers=msg.raw_email_headers or None,
        )
        reports = await asyncio.to_thread(execute_message_group, req)
        await ctx.send(
            sender,
            ForensicSpecialistResponse(
                request_id=msg.request_id,
                specialist_group="message_phone_email_pattern",
                agent_name="suraksha_message_analyst",
                agent_address=message_specialist_address(),
                ok=True,
                reports_json=json.dumps([_dump_model(r) for r in reports], ensure_ascii=False),
            ),
        )

    return proto


def build_upi_gst_specialist_protocol() -> Protocol:
    proto = Protocol(name="suraksha-upi-gst-a2a", version="1.0.0")

    @proto.on_message(model=ForensicSpecialistRequest, replies={ForensicSpecialistResponse})
    async def on_upi_req(ctx: Context, sender: str, msg: ForensicSpecialistRequest) -> None:
        ctx.logger.info(f"[suraksha_upi_verifier] A2A request {msg.request_id} from {short_addr(sender)}")
        req = build_investigation_request(
            raw_text=msg.raw_text,
            request_id=msg.request_id,
            channel_hint=msg.channel_hint or None,
            raw_email_headers=msg.raw_email_headers or None,
        )
        reports = await asyncio.to_thread(execute_upi_gst_group, req)
        await ctx.send(
            sender,
            ForensicSpecialistResponse(
                request_id=msg.request_id,
                specialist_group="upi_ifsc_gstin",
                agent_name="suraksha_upi_verifier",
                agent_address=upi_gst_specialist_address(),
                ok=True,
                reports_json=json.dumps([_dump_model(r) for r in reports], ensure_ascii=False),
            ),
        )

    return proto


def build_action_specialist_protocol() -> Protocol:
    proto = Protocol(name="suraksha-action-a2a", version="1.0.0")

    @proto.on_message(model=SkepticActionRequest, replies={SkepticActionResponse})
    async def on_action_req(ctx: Context, sender: str, msg: SkepticActionRequest) -> None:
        ctx.logger.info(f"[suraksha_action_agent] A2A request {msg.request_id} from {short_addr(sender)}")
        req = build_investigation_request(
            raw_text=msg.raw_text,
            request_id=msg.request_id,
            channel_hint=msg.channel_hint or None,
            raw_email_headers=msg.raw_email_headers or None,
        )
        raw_reports = json.loads(msg.reports_json or "[]")
        specialist_reports = [SpecialistReport(**r) for r in raw_reports]
        skeptic_audit, action_drafts, top_evidence_lines = await asyncio.to_thread(
            execute_skeptic_and_action_group, req, specialist_reports
        )
        await ctx.send(
            sender,
            SkepticActionResponse(
                request_id=msg.request_id,
                agent_name="suraksha_action_agent",
                agent_address=action_specialist_address(),
                ok=True,
                skeptic_json=json.dumps(_dump_model(skeptic_audit), ensure_ascii=False),
                action_json=json.dumps(_dump_model(action_drafts), ensure_ascii=False),
                top_evidence_json=json.dumps(top_evidence_lines, ensure_ascii=False),
            ),
        )

    return proto


# ── Real `await ctx.send_and_receive(...)` Orchestration from `suraksha_concierge` ──

async def investigate_via_uagents(
    ctx: Context,
    raw_text: str,
    request_id: Optional[str] = None,
    channel_hint: Optional[str] = None,
    raw_email_headers: Optional[str] = None,
) -> tuple[FinalVerdictBundle, Dict[str, Any]]:
    """
    Executes the Suraksha Squad investigation using REAL `await ctx.send_and_receive(...)`
    calls from `suraksha_concierge` to the 4 specialist uAgents (`domain`, `message`, `upi`, `action`),
    with graceful local fallback if any specialist agent is offline.
    """
    t_start = time.perf_counter()
    req_id = request_id or f"a2a_{uuid4().hex[:8]}"
    req = build_investigation_request(
        raw_text=raw_text,
        request_id=req_id,
        channel_hint=channel_hint,
        raw_email_headers=raw_email_headers,
    )
    f_req = ForensicSpecialistRequest(
        request_id=req_id,
        raw_text=raw_text,
        channel_hint=channel_hint or "auto",
        raw_email_headers=raw_email_headers or "",
    )

    can_a2a = hasattr(ctx, "send_and_receive") and callable(getattr(ctx, "send_and_receive"))
    provenance: List[str] = []
    degraded_any = False

    async def _call_specialist(target_addr: str, label: str, fallback_fn) -> List[SpecialistReport]:
        nonlocal degraded_any
        if can_a2a:
            try:
                reply, _ = await ctx.send_and_receive(
                    target_addr,
                    f_req,
                    response_type=ForensicSpecialistResponse,
                    timeout=A2A_TIMEOUT,
                )
                if isinstance(reply, ForensicSpecialistResponse) and reply.ok:
                    provenance.append(f"{reply.agent_name} ({short_addr(reply.agent_address)})")
                    raw_list = json.loads(reply.reports_json or "[]")
                    return [SpecialistReport(**r) for r in raw_list]
            except Exception as exc:
                if hasattr(ctx, "logger"):
                    ctx.logger.warning(f"A2A call to {label} ({short_addr(target_addr)}) failed: {exc}")
        degraded_any = True
        provenance.append(f"{label} (local fallback — specialist offline)")
        return await asyncio.to_thread(fallback_fn, req)

    # 1. Parallel Fan-Out across the 3 forensic specialist uAgents via `ctx.send_and_receive`
    dom_reports, msg_reports, upi_reports = await asyncio.gather(
        _call_specialist(domain_specialist_address(), "suraksha_domain_forensics", execute_domain_group),
        _call_specialist(message_specialist_address(), "suraksha_message_analyst", execute_message_group),
        _call_specialist(upi_gst_specialist_address(), "suraksha_upi_verifier", execute_upi_gst_group),
    )
    specialist_reports: List[SpecialistReport] = [*dom_reports, *msg_reports, *upi_reports]

    # 2. Call `suraksha_action_agent` (Skeptic + Action Drafts) via `ctx.send_and_receive`
    skeptic_audit: Optional[SkepticAuditReport] = None
    action_drafts: Optional[ActionDraftsReport] = None
    top_evidence_lines: List[str] = []

    if can_a2a:
        try:
            act_addr = action_specialist_address()
            act_reply, _ = await ctx.send_and_receive(
                act_addr,
                SkepticActionRequest(
                    request_id=req_id,
                    raw_text=raw_text,
                    channel_hint=channel_hint or "auto",
                    raw_email_headers=raw_email_headers or "",
                    reports_json=json.dumps([_dump_model(r) for r in specialist_reports], ensure_ascii=False),
                ),
                response_type=SkepticActionResponse,
                timeout=A2A_TIMEOUT,
            )
            if isinstance(act_reply, SkepticActionResponse) and act_reply.ok:
                provenance.append(f"{act_reply.agent_name} ({short_addr(act_reply.agent_address)})")
                skeptic_audit = SkepticAuditReport(**json.loads(act_reply.skeptic_json))
                action_drafts = ActionDraftsReport(**json.loads(act_reply.action_json))
                top_evidence_lines = json.loads(act_reply.top_evidence_json)
        except Exception as exc:
            if hasattr(ctx, "logger"):
                ctx.logger.warning(f"A2A call to suraksha_action_agent failed: {exc}")

    if skeptic_audit is None or action_drafts is None:
        degraded_any = True
        provenance.append("suraksha_action_agent (local fallback — specialist offline)")
        skeptic_audit, action_drafts, top_evidence_lines = await asyncio.to_thread(
            execute_skeptic_and_action_group, req, specialist_reports
        )

    verdict: VerdictLevel = skeptic_audit.adjusted_verdict
    badge_map = {
        "HIGH_RISK_SCAM": "🚨 HIGH RISK SCAM — DO NOT PAY OR CLICK",
        "SUSPICIOUS_CAUTION": "⚠️ SUSPICIOUS — VERIFY INDEPENDENTLY",
        "LOOKS_OK": "✅ LOOKS OK — DETERMINISTIC CHECKS PASSED",
        "INSUFFICIENT_DATA": "ℹ️ INSUFFICIENT DATA — MORE DETAILS NEEDED",
    }
    headline_map = {
        "HIGH_RISK_SCAM": "Multiple Deterministic Forensic Red Flags Confirmed",
        "SUSPICIOUS_CAUTION": "Caution Indicators Found — Independent Verification Advised",
        "LOOKS_OK": "Verified Official / Safe Indicators — Zero Scam Signatures Triggered",
        "INSUFFICIENT_DATA": "No Actionable Fraud Indicators Detected in Snippet",
    }

    ctx_data = await asyncio.to_thread(
        enrich_with_context_dev,
        req.raw_text,
        {
            "urls": req.extracted_urls,
            "upis": req.extracted_upis,
            "gstins": req.extracted_gstins,
            "phones": req.extracted_phones,
        },
    )
    asi1_meta = await asyncio.to_thread(
        explain_verdict_with_asi1, verdict, top_evidence_lines, skeptic_audit.skeptic_note
    )
    total_ms = (time.perf_counter() - t_start) * 1000

    bundle = FinalVerdictBundle(
        request_id=req_id,
        verdict=verdict,
        verdict_badge=badge_map[verdict],
        headline=headline_map[verdict],
        concise_explanation=asi1_meta["explanation"],
        top_evidence_lines=top_evidence_lines,
        skeptic_audit=skeptic_audit,
        action_drafts=action_drafts,
        specialist_reports=specialist_reports,
        interactive_cards={},
        context_dev_enrichment=ctx_data,
        asi1_llm_metadata=asi1_meta,
        total_execution_ms=round(total_ms, 2),
    )
    bundle.interactive_cards = {
        "form_card": build_intake_form_card(),
        "progress_card": build_progress_card(req_id, specialist_reports),
        "verdict_card": build_verdict_card(bundle),
        "action_card": build_action_card(bundle),
    }
    a2a_meta = {
        "degraded": degraded_any,
        "via": " · ".join(provenance),
        "provenance_list": provenance,
    }
    return bundle, a2a_meta
