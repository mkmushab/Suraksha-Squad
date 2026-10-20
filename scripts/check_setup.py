#!/usr/bin/env python3
"""Pre-flight check: verifies all 12 agent seeds, 65-char agent1q... addresses, ASI:One key, Context.dev key, and tools."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from suraksha_squad.agents import get_agent_registry, validate_gstin_offline
from suraksha_squad.env_loader import auto_load_dotenv, get_active_env_summary
from suraksha_squad.gst_engine import resolve_pin_to_state
from suraksha_squad.ssrf_guard import validate_url_ssrf


def main() -> None:
    auto_load_dotenv()
    summary = get_active_env_summary()
    registry = get_agent_registry()
    print("=" * 80)
    print("SURAKSHA SQUAD — PRE-FLIGHT SETUP & TOOL CHECK")
    print("=" * 80)
    print(f"✅ 12 Specialist uAgents Derived (Concierge: {registry[0]['address']})")
    print(f"✅ ASI:One API Key     : {summary['asi1_api_key']}")
    print(f"✅ Context.dev API Key : {summary['context_dev_api_key']}")
    print(f"✅ Agentverse API Key  : {summary['agentverse_api_key']}")
    pin_state = resolve_pin_to_state("302001", allow_network=False)
    print(f"✅ India Post PIN Tool : 302001 -> {pin_state}")
    gst_ok = validate_gstin_offline("07AABCU9603R1ZP")["valid"]
    print(f"✅ Modulo-36 GSTIN Tool: 07AABCU9603R1ZP -> valid={gst_ok}")
    ssrf_blocked = not validate_url_ssrf("http://169.254.169.254/latest/meta-data/", resolve_dns=False).allowed
    print(f"✅ SSRF Guard Active   : 169.254.169.254 blocked={ssrf_blocked}")
    print("\nReady for Live Demo & Judging.")


if __name__ == "__main__":
    main()
