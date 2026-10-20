"""Suraksha Squad Domain, Page & Reputation Specialist uAgent (`suraksha_domain_forensics` :8002)."""
from __future__ import annotations

from typing import Optional

from suraksha_squad.a2a_protocol import build_domain_specialist_protocol
from suraksha_squad.uagents_compat import Agent, Context

from .common import make_agent


def build_domain_agent(*, mailbox: Optional[bool] = None, port: Optional[int] = None) -> Agent:
    agent = make_agent(
        "agent_02_domain",
        "suraksha_domain_forensics",
        8002,
        "Domain Forensics, Page APK Trap, SSRF Guard & Threat Reputation Specialist uAgent for Suraksha Squad.",
        "domain_agent.md",
        mailbox=mailbox,
        port=port,
    )

    @agent.on_event("startup")
    async def on_start(ctx: Context) -> None:
        ctx.logger.info(f"suraksha_domain_forensics ready · address {getattr(ctx, 'address', agent.address)}")

    agent.include(build_domain_specialist_protocol(), publish_manifest=True)
    return agent


if __name__ == "__main__":
    build_domain_agent().run()
