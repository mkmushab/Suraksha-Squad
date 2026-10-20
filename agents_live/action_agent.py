"""Suraksha Squad Epistemic Skeptic & 1930 Protective Action Specialist uAgent (`suraksha_action_agent` :8012)."""
from __future__ import annotations

from typing import Optional

from suraksha_squad.a2a_protocol import build_action_specialist_protocol
from suraksha_squad.uagents_compat import Agent, Context

from .common import make_agent


def build_action_agent(*, mailbox: Optional[bool] = None, port: Optional[int] = None) -> Agent:
    agent = make_agent(
        "agent_12_action",
        "suraksha_action_agent",
        8012,
        "Epistemic Skeptic Contradiction Cross-Checker & 1930 Cybercrime / Bank Nodal / Family Alert Specialist uAgent.",
        "action_agent.md",
        mailbox=mailbox,
        port=port,
    )

    @agent.on_event("startup")
    async def on_start(ctx: Context) -> None:
        ctx.logger.info(f"suraksha_action_agent ready · address {getattr(ctx, 'address', agent.address)}")

    agent.include(build_action_specialist_protocol(), publish_manifest=True)
    return agent


if __name__ == "__main__":
    build_action_agent().run()
