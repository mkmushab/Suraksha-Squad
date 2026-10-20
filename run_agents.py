#!/usr/bin/env python3
"""
Starts or verifies the Suraksha Squad uAgents fleet (Agent Chat Protocol v0.3.0 + Payment Protocol v0.1.0 + A2A).
Usage:
  python run_agents.py --check     # Verifies all 12 uAgents, seeds, and A2A protocols
  python run_agents.py             # Launches the 5 live multi-process uAgents (via run_all.py)
"""

from __future__ import annotations

import argparse
from suraksha_squad.agents import get_agent_registry, instantiate_uagents
from suraksha_squad.chat_protocol import build_asi_one_chat_protocol
from suraksha_squad.env_loader import auto_load_dotenv, get_active_env_summary
from suraksha_squad.payment_protocol import build_seller_payment_protocol, seller_wallet_address


def main() -> None:
    parser = argparse.ArgumentParser(description="Suraksha Squad uAgents Runner")
    parser.add_argument("--check", action="store_true", help="Verify all 12 agents and exit")
    args = parser.parse_args()

    auto_load_dotenv()
    env_info = get_active_env_summary()
    fleet = instantiate_uagents()
    concierge = fleet["agent_01_concierge"]
    concierge.include(build_asi_one_chat_protocol(), publish_manifest=True)
    concierge.include(build_seller_payment_protocol(), publish_manifest=True)

    print("=" * 88)
    print("SURAKSHA SQUAD — FETCH.AI uAGENTS FLEET (ACP v0.3.0 + Payment v0.1.0 + A2A)")
    print("=" * 88)
    print(f"ASI:One Key      : {env_info['asi1_api_key']}")
    print(f"Context.dev Key  : {env_info['context_dev_api_key']}")
    print(f"Agentverse Key   : {env_info['agentverse_api_key']}")
    print(f"Seller Wallet    : {seller_wallet_address()}")
    print("-" * 88)
    live_a2a_ids = {"agent_01_concierge", "agent_02_domain", "agent_04_message", "agent_05_upi", "agent_12_action"}
    for idx, spec in enumerate(get_agent_registry(), start=1):
        mode = "LIVE A2A uAgent (ctx.send_and_receive)" if spec["id"] in live_a2a_ids else "In-Process Forensic Tool"
        print(f"  {idx:02d}. {spec['name']:<26} -> {spec['address']} (:{spec['port']}) [{mode}]")
    print("=" * 88)

    if args.check:
        print("All 12 uAgents initialized and verified with AgentChatProtocol v0.3.0.")
        return

    import run_all
    run_all.main()


if __name__ == "__main__":
    main()
