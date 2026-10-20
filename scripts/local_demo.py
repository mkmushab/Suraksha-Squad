#!/usr/bin/env python3
"""Offline end-to-end multi-agent Bureau rehearsal for Suraksha Squad:
A scripted 'ASI:One user' uAgent talks to the real `suraksha_concierge` uAgent over
`AgentChatProtocol v0.3.0`, which calls the 4 live specialist uAgents (`domain`, `message`,
`upi`, `action`) over `await ctx.send_and_receive(...)` inside one `Bureau`.

    SURAKSHA_OFFLINE=1 python scripts/local_demo.py              # full 5-agent A2A flow
    SURAKSHA_OFFLINE=1 python scripts/local_demo.py --degraded   # specialists down -> graceful fallback

Exit code 0 = every step produced the expected output. No internet / API keys needed.
"""
from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

os.environ.setdefault("SURAKSHA_OFFLINE", "1")
os.environ.setdefault("MK_OFFLINE", "1")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.chdir(tempfile.mkdtemp(prefix="suraksha-demo-"))

from agents_live.action_agent import build_action_agent  # noqa: E402
from agents_live.concierge_agent import build_concierge_agent  # noqa: E402
from agents_live.domain_agent import build_domain_agent  # noqa: E402
from agents_live.message_agent import build_message_agent  # noqa: E402
from agents_live.upi_agent import build_upi_agent  # noqa: E402
from suraksha_squad.a2a_protocol import concierge_address  # noqa: E402
from suraksha_squad.chat_protocol import (  # noqa: E402
    ChatAcknowledgement,
    ChatMessage,
    MetadataContent,
    TextContent,
)
from suraksha_squad.uagents_compat import Agent, Bureau, Context  # noqa: E402

PORT = 8200
DEGRADED = "--degraded" in sys.argv

STEPS = [
    ("hi", ["Suraksha Squad"], "form"),
    (
        "Dear consumer your electricity power will be disconnected tonight 9:30 PM. "
        "Update KYC at http://uppcl-kyc-update.xyz/bill.apk or pay Rs 10 to electricity.refund@oksbi",
        ["HIGH RISK SCAM", "1930", "Skeptic"],
        "review",
    ),
    (
        "Please verify official portal https://onlinesbi.sbi and GSTIN 07AABCU9603R1ZP",
        ["LOOKS OK"],
        "review",
    ),
    (
        "pay via Fetch.ai",
        ["AgentPaymentProtocol", "SURAKSHA-B2B", "USDC", "FET"],
        None,
    ),
]

if DEGRADED:
    STEPS[1] = (
        STEPS[1][0],
        ["HIGH RISK SCAM", "local fallback"],
        "review",
    )


def build_demo_user() -> Agent:
    user = Agent(
        name="demo_asi_user",
        seed="suraksha-demo-user-seed",
        port=PORT + 9,
        endpoint=[f"http://127.0.0.1:{PORT + 9}/submit"],
        mailbox=False,
    )
    state = {"i": 0, "target": None}

    def describe(msg: ChatMessage) -> tuple[str, str | None]:
        text = "\n".join(getattr(c, "text", "") for c in msg.content if isinstance(c, TextContent) or getattr(c, "type", None) == "text")
        card = next(
            (
                c.metadata.get("card_kind")
                for c in msg.content
                if (isinstance(c, MetadataContent) or getattr(c, "type", None) == "metadata")
                and getattr(c, "metadata", {}).get("card_protocol_version") == "1"
            ),
            None,
        )
        return text, card

    async def send_step(ctx: Context) -> None:
        text, _, _ = STEPS[state["i"]]
        print(f"\n\033[1m👤 USER → {text[:115]}\033[0m")
        await ctx.send(
            state["target"],
            ChatMessage(
                timestamp=datetime.now(timezone.utc),
                msg_id=uuid4(),
                content=[TextContent(type="text", text=text)],
            ),
        )

    @user.on_event("startup")
    async def go(ctx: Context) -> None:
        state["target"] = concierge_address()
        await send_step(ctx)

    @user.on_message(ChatAcknowledgement)
    async def on_ack(ctx: Context, sender: str, msg: ChatAcknowledgement) -> None:
        pass

    @user.on_message(ChatMessage)
    async def on_reply(ctx: Context, sender: str, msg: ChatMessage) -> None:
        await ctx.send(
            sender,
            ChatAcknowledgement(timestamp=datetime.now(timezone.utc), acknowledged_msg_id=msg.msg_id),
        )
        text, card = describe(msg)
        _, expect_text, expect_card = STEPS[state["i"]]
        print(f"🤖 CONCIERGE ({'card:' + card if card else 'text'}):\n{text[:900]}")
        ok = all(s in text for s in expect_text) and (expect_card is None or card == expect_card)
        print("   ✅ expected output" if ok else f"   ❌ expected {expect_text} / card={expect_card}")
        if not ok:
            os._exit(1)
        state["i"] += 1
        if state["i"] >= len(STEPS):
            print("\n\033[92mALL STEPS PASSED — Multi-Agent ctx.send_and_receive flow verified end-to-end.\033[0m")
            sys.stdout.flush()
            os._exit(0)
        await send_step(ctx)

    return user


if __name__ == "__main__":
    bureau = Bureau(port=PORT, endpoint=[f"http://127.0.0.1:{PORT}/submit"])
    specialists = (
        []
        if DEGRADED
        else [
            build_domain_agent(mailbox=False, port=PORT + 1),
            build_message_agent(mailbox=False, port=PORT + 2),
            build_upi_agent(mailbox=False, port=PORT + 3),
            build_action_agent(mailbox=False, port=PORT + 4),
        ]
    )
    for ag in (*specialists, build_concierge_agent(mailbox=False, port=PORT + 5), build_demo_user()):
        bureau.add(ag)
    bureau.run()
