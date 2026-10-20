"""Suraksha Squad Message, Phone, Email & Pattern Specialist uAgent (`suraksha_message_analyst` :8004)."""
from __future__ import annotations

from typing import Optional

from suraksha_squad.a2a_protocol import build_message_specialist_protocol
from suraksha_squad.uagents_compat import Agent, Context

from .common import make_agent


def build_message_agent(*, mailbox: Optional[bool] = None, port: Optional[int] = None) -> Agent:
    agent = make_agent(
        "agent_04_message",
        "suraksha_message_analyst",
        8004,
        "Multilingual Coercion Lexicon, TRAI Phone Checker, RFC 8601 Email SPF/DKIM/DMARC & I4C Pattern Specialist uAgent.",
        "message_agent.md",
        mailbox=mailbox,
        port=port,
    )

    @agent.on_event("startup")
    async def on_start(ctx: Context) -> None:
        ctx.logger.info(f"suraksha_message_analyst ready · address {getattr(ctx, 'address', agent.address)}")

    agent.include(build_message_specialist_protocol(), publish_manifest=True)
    return agent


if __name__ == "__main__":
    build_message_agent().run()
