"""Suraksha Squad UPI, IFSC & Modulo-36 GSTIN Specialist uAgent (`suraksha_upi_verifier` :8005)."""
from __future__ import annotations

from typing import Optional

from suraksha_squad.a2a_protocol import build_upi_gst_specialist_protocol
from suraksha_squad.uagents_compat import Agent, Context

from .common import make_agent


def build_upi_agent(*, mailbox: Optional[bool] = None, port: Optional[int] = None) -> Agent:
    agent = make_agent(
        "agent_05_upi",
        "suraksha_upi_verifier",
        8005,
        "NPCI UPI VPA Registry, UPI Collect Debit Trap, 11-Char IFSC & Modulo-36 GSTIN Specialist uAgent.",
        "upi_agent.md",
        mailbox=mailbox,
        port=port,
    )

    @agent.on_event("startup")
    async def on_start(ctx: Context) -> None:
        ctx.logger.info(f"suraksha_upi_verifier ready · address {getattr(ctx, 'address', agent.address)}")

    agent.include(build_upi_gst_specialist_protocol(), publish_manifest=True)
    return agent


if __name__ == "__main__":
    build_upi_agent().run()
