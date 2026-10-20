#!/usr/bin/env python3
"""
3-Minute CLI & ASI:One Interactive Card Rehearsal Script for Judges.
Runs all 6 benchmark scenarios (5 Indian scams + 1 official safe link control) across all 12 agents
without requiring internet or external API keys, printing derived `agent1q...` addresses and verdicts.
"""

from __future__ import annotations
from suraksha_squad.agents import get_agent_registry, investigate_submission
from suraksha_squad.demo_scenarios import DEMO_SCENARIOS


def main() -> None:
    print("=" * 88)
    print("SURAKSHA SQUAD — 12-AGENT SCAM INVESTIGATOR (FETCH-A-THON 3.0 LIVE REHEARSAL)")
    print("=" * 88)

    registry = get_agent_registry()
    print(f"\n[1] Registered 12-Agent Fleet (Deterministic Bech32 Addresses):")
    for idx, ag in enumerate(registry, start=1):
        print(f"  {idx:02d}. {ag['name']:<26} | {ag['address']} | {ag['role']}")

    print("\n[2] Running 6 End-to-End Scenarios (Form Card -> Progress Card -> Verdict Card -> Action Card):")
    for scen in DEMO_SCENARIOS:
        bundle = investigate_submission(
            raw_text=scen["raw_text"],
            request_id=f"demo_{scen['id']}",
            channel_hint=scen["channel"],
            raw_email_headers=scen["raw_email_headers"],
        )
        print("-" * 88)
        print(f"Scenario : {scen['title']}")
        print(f"Verdict  : {bundle.verdict_badge} (Expected: {scen['expected_verdict']}) [{bundle.total_execution_ms:.2f} ms]")
        print("Evidence :")
        for line in bundle.top_evidence_lines[:5]:
            print(f"  • {line}")
        print(f"Skeptic  : {bundle.skeptic_audit.skeptic_note}")
        assert bundle.verdict == scen["expected_verdict"], (
            f"Verdict mismatch on {scen['id']}: got {bundle.verdict}, expected {scen['expected_verdict']}"
        )

    print("=" * 88)
    print("ALL 6 SCENARIOS (INCLUDING 'LOOKS_OK' CONTROL) VERIFIED SUCCESSFULLY.")
    print("=" * 88)


if __name__ == "__main__":
    main()
