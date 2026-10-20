"""Suraksha Squad Concierge (`suraksha_concierge` :8001) — ASI:One Front Door Orchestrator."""
from __future__ import annotations

from typing import Optional

from suraksha_squad.a2a_protocol import (
    action_specialist_address,
    domain_specialist_address,
    message_specialist_address,
    upi_gst_specialist_address,
)
from suraksha_squad.chat_protocol import build_asi_one_chat_protocol
from suraksha_squad.payment_protocol import build_seller_payment_protocol
from suraksha_squad.uagents_compat import Agent, Context

from .common import make_agent


def build_concierge_agent(*, mailbox: Optional[bool] = None, port: Optional[int] = None) -> Agent:
    agent = make_agent(
        "agent_01_concierge",
        "suraksha_concierge",
        8001,
        "Suraksha Squad — Indian Scam, Phishing, UPI Collect, GSTIN & Digital Arrest Investigator (ACP v0.3.0 + Cards + Payment v0.1.0).",
        "concierge.md",
        mailbox=mailbox,
        port=port,
    )

    @agent.on_event("startup")
    async def on_start(ctx: Context) -> None:
        ctx.logger.info(f"suraksha_concierge ready · address {getattr(ctx, 'address', agent.address)}")
        ctx.logger.info(
            f"A2A specialists: domain={domain_specialist_address()} "
            f"message={message_specialist_address()} upi={upi_gst_specialist_address()} "
            f"action={action_specialist_address()}"
        )

    agent.include(build_asi_one_chat_protocol(), publish_manifest=True)
    agent.include(build_seller_payment_protocol(), publish_manifest=True)
    return agent


if __name__ == "__main__":
    build_concierge_agent().run()
