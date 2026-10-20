"""
Official Fetch.ai `uagents_core.contrib.protocols.chat` (`AgentChatProtocol v0.3.0`) &
`uagents_core.contrib.protocols.payment` (`AgentPaymentProtocol v0.1.0`) handler for `suraksha_concierge`.

Orchestrates real `await ctx.send_and_receive(...)` calls from `suraksha_concierge` (`:8001`)
to the live specialist uAgents (`suraksha_domain_forensics` `:8002`, `suraksha_message_analyst` `:8004`,
`suraksha_upi_verifier` `:8005`, and `suraksha_action_agent` `:8012`) via `suraksha_squad.a2a_protocol`.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .a2a_protocol import investigate_via_uagents
from .cards import to_asi_wire_metadata
from .payment_protocol import build_b2b_shield_payment_request, build_seller_payment_protocol
from .uagents_compat import Context, Model, Protocol

try:
    from uagents_core.contrib.protocols.chat import (
        ChatAcknowledgement,
        ChatMessage,
        MetadataContent,
        StartSessionContent,
        TextContent,
        chat_protocol_spec,
    )
    HAS_OFFICIAL_ACP = True
except ImportError:
    HAS_OFFICIAL_ACP = False
    chat_protocol_spec = None

    class TextContent(Model):  # type: ignore
        type: str = "text"
        text: str = ""

    class MetadataContent(Model):  # type: ignore
        type: str = "metadata"
        metadata: dict = {}

    class StartSessionContent(Model):  # type: ignore
        type: str = "start-session"

    class ChatMessage(Model):  # type: ignore
        timestamp: Any = ""
        msg_id: Any = ""
        content: list = []

    class ChatAcknowledgement(Model):  # type: ignore
        timestamp: Any = ""
        acknowledged_msg_id: Any = ""


class PaymentCommitMessage(Model):
    tx_hash: str
    expected_recipient: str
    actual_recipient: str
    expected_amount: str
    committed_amount: str
    currency: str = "FET"
    ledger_verified: bool = False


def _extract_user_text(msg: ChatMessage) -> str:
    parts = []
    for item in getattr(msg, "content", []) or []:
        if isinstance(item, TextContent) or getattr(item, "type", None) == "text":
            txt = getattr(item, "text", None) or (item.get("text", "") if isinstance(item, dict) else "")
            if txt:
                parts.append(str(txt))
        elif isinstance(item, dict) and item.get("type") == "text":
            parts.append(str(item.get("text", "")))
        elif isinstance(item, str):
            parts.append(item)
    text = "\n".join(parts).strip()
    if not text and any(isinstance(c, StartSessionContent) or getattr(c, "type", None) == "start-session" for c in (getattr(msg, "content", []) or [])):
        return "hi"
    return text


def _build_official_review_card_payload(bundle: Any, via_str: str) -> dict[str, Any]:
    """Formats the Suraksha Squad verdict into the official ASI:One `review` card schema."""
    rows = [
        {"label": "Verdict", "value": f"{bundle.verdict} ({bundle.verdict_badge})"},
        {"label": "Headline", "value": bundle.headline[:160]},
    ]
    for idx, line in enumerate(bundle.top_evidence_lines[:4], start=1):
        rows.append({"label": f"Evidence #{idx}", "value": line[:180]})
    if bundle.skeptic_audit.contradictions_found:
        rows.append({"label": "Skeptic Cross-Check", "value": bundle.skeptic_audit.contradictions_found[0][:180]})
    if bundle.skeptic_audit.unverifiable_boundaries:
        rows.append({"label": "Cannot Verify Offline", "value": bundle.skeptic_audit.unverifiable_boundaries[0][:180]})
    rows.append({"label": "Forensics executed by", "value": via_str[:200]})
    return {
        "title": f"Suraksha Squad Verdict: {bundle.verdict}",
        "summary_rows": rows,
        "approve_cta": {
            "label": "Show 1930 & Bank Action Drafts",
            "primary": True,
            "selection": {"action": "show_action_drafts", "request_id": bundle.request_id},
        },
        "reject_cta": {
            "label": "New Scan",
            "selection": {"action": "new_scan"},
        },
    }


def build_asi_one_chat_protocol() -> Protocol:
    """Builds the official `AgentChatProtocol v0.3.0` (`chat_protocol_spec`) for `suraksha_concierge`."""
    if HAS_OFFICIAL_ACP and chat_protocol_spec is not None:
        chat_proto = Protocol(spec=chat_protocol_spec)
    else:
        chat_proto = Protocol(name="AgentChatProtocol", version="0.3.0")

    if not getattr(chat_proto, "name", None):
        chat_proto.name = "AgentChatProtocol"
    if not getattr(chat_proto, "version", None):
        chat_proto.version = "0.3.0"

    @chat_proto.on_message(ChatMessage)
    async def handle_chat_message(ctx: Context, sender: str, msg: ChatMessage) -> None:
        # 1. Always acknowledge first (ACP v0.3.0 requirement)
        await ctx.send(
            sender,
            ChatAcknowledgement(
                timestamp=datetime.now(timezone.utc),
                acknowledged_msg_id=msg.msg_id,
            ),
        )

        user_query = _extract_user_text(msg)
        if not user_query or user_query.lower().strip(" !.") in {"hi", "hello", "hey", "start", "help", "namaste", "menu", "new_scan"}:
            intake_form = {
                "title": "🛡️ Suraksha Squad — Multi-Agent Indian Scam & Invoice Investigator",
                "fields": [
                    {
                        "name": "raw_text",
                        "kind": "text",
                        "label": "Paste suspicious SMS, WhatsApp, URL, UPI ID, Phone, or GSTIN",
                        "required": True,
                    },
                    {
                        "name": "channel_hint",
                        "kind": "select",
                        "label": "Channel",
                        "options": [
                            {"value": "auto", "label": "Auto-Detect"},
                            {"value": "sms", "label": "SMS / Bijli / KYC Alert"},
                            {"value": "whatsapp", "label": "WhatsApp / Digital Arrest"},
                            {"value": "upi", "label": "UPI Collect / Refund Request"},
                            {"value": "invoice", "label": "GST Invoice / Bill"},
                        ],
                    },
                ],
                "submit_cta": {
                    "label": "Run Multi-Agent Forensic Audit",
                    "selection": {"action": "investigate_submission"},
                },
            }
            narration = (
                "🛡️ **Namaste! I am Suraksha Squad** — a multi-agent Indian scam, phishing, UPI Collect, "
                "and GST invoice investigator.\n\n"
                "Paste any suspicious **SMS, KYC link, UPI ID (`@oksbi`/`@ybl`), phone number, email header, or GSTIN** "
                "below (or fill the interactive card) to dispatch our specialist uAgents in parallel."
            )
            await ctx.send(
                sender,
                ChatMessage(
                    timestamp=datetime.now(timezone.utc),
                    msg_id=uuid4(),
                    content=[
                        TextContent(type="text", text=narration),
                        MetadataContent(
                            type="metadata",
                            metadata=to_asi_wire_metadata("form", intake_form, terminal=False),
                        ),
                    ],
                ),
            )
            return

        # Check if the user is requesting B2B API Shield subscription via Fetch.ai Payment Protocol
        if re.search(r"^(?:pay via fetch|payment protocol|b2b shield|upgrade pro)\b", user_query.strip(), re.I):
            pay_req = build_b2b_shield_payment_request(owner=sender)
            funds_str = " or ".join(f"**{f.amount} {f.currency}** (`{f.payment_method}`)" for f in pay_req.accepted_funds)
            pay_text = (
                f"💳 **Fetch.ai Agent Payment Protocol (`AgentPaymentProtocol v0.1.0`)**\n\n"
                f"- **Plan:** Suraksha Squad B2B Merchant Fraud Shield (`{pay_req.reference}`)\n"
                f"- **Accepted Funds:** {funds_str}\n"
                f"- **Seller Recipient (`fetch1...`):** `{pay_req.recipient}`\n"
                f"- **Description:** {pay_req.description}\n\n"
                f"A native `RequestPayment` message has been dispatched on the uAgents Payment Protocol channel."
            )
            await ctx.send(
                sender,
                ChatMessage(
                    timestamp=datetime.now(timezone.utc),
                    msg_id=uuid4(),
                    content=[TextContent(type="text", text=pay_text)],
                ),
            )
            await ctx.send(sender, pay_req)
            return

        # Handle JSON form selection if ASI:One returns a JSON selection object
        try:
            parsed = json.loads(user_query)
            if isinstance(parsed, dict) and parsed.get("raw_text"):
                user_query = str(parsed["raw_text"])
        except Exception:
            pass

        req_id = f"acp_{str(msg.msg_id)[:8]}"
        bundle, a2a_meta = await investigate_via_uagents(ctx, raw_text=user_query, request_id=req_id)

        narration_lines = [
            f"### {bundle.verdict_badge}",
            f"**{bundle.headline}**",
            "",
            bundle.concise_explanation,
            "",
            "**Top Forensic Evidence:**",
            *[f"- {line}" for line in bundle.top_evidence_lines[:5]],
            "",
            f"**🔍 Epistemic Skeptic (`suraksha_skeptic`):** {bundle.skeptic_audit.skeptic_note}",
        ]
        if bundle.skeptic_audit.contradictions_found:
            narration_lines.append(f"- *Contradiction Caught:* {bundle.skeptic_audit.contradictions_found[0]}")
        if bundle.skeptic_audit.unverifiable_boundaries:
            narration_lines.append(f"- *Cannot Verify Passively:* {bundle.skeptic_audit.unverifiable_boundaries[0]}")

        narration_lines += [
            "",
            f"**🤖 Multi-Agent Provenance (`uAgents A2A`):** {a2a_meta['via']}",
        ]
        if a2a_meta.get("degraded"):
            narration_lines.append(
                "⚠️ *Note: One or more specialist uAgent processes were unreachable; computed locally by concierge fallback.*"
            )

        narration_lines += [
            "",
            "### 📋 Ready-to-Use Protective Action Drafts (`suraksha_action_agent`)",
            "**1. 1930 / `cybercrime.gov.in` Complaint Draft:**",
            f"```text\n{bundle.action_drafts.cybercrime_1930_report}\n```",
            "**2. Family WhatsApp Alert (Hinglish):**",
            f"> {bundle.action_drafts.family_whatsapp_alert_hi_en}",
        ]

        review_payload = _build_official_review_card_payload(bundle, a2a_meta["via"])
        await ctx.send(
            sender,
            ChatMessage(
                timestamp=datetime.now(timezone.utc),
                msg_id=uuid4(),
                content=[
                    TextContent(type="text", text="\n".join(narration_lines)),
                    MetadataContent(
                        type="metadata",
                        metadata=to_asi_wire_metadata("review", review_payload, terminal=False),
                    ),
                ],
            ),
        )

    @chat_proto.on_message(ChatAcknowledgement)
    async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement) -> None:
        pass

    return chat_proto
