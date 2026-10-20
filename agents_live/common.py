"""Shared helpers for the 5 live multi-process Suraksha Squad uAgents."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

from suraksha_squad.a2a_protocol import (
    action_specialist_address,
    concierge_address,
    domain_specialist_address,
    get_seed_for,
    message_specialist_address,
    upi_gst_specialist_address,
)
from suraksha_squad.env_loader import auto_load_dotenv
from suraksha_squad.uagents_compat import Agent, Context, ensure_event_loop

auto_load_dotenv()
ROOT = Path(__file__).resolve().parent.parent


def readme_path(name: str) -> str:
    p = ROOT / "readme" / name
    return str(p) if p.exists() else ""


def use_mailbox() -> bool:
    return os.getenv("MK_USE_MAILBOX", "true").strip().lower() in {"1", "true", "yes"}


def make_agent(
    agent_id: str,
    name: str,
    default_port: int,
    description: str,
    readme_file: str,
    *,
    mailbox: Optional[bool] = None,
    port: Optional[int] = None,
) -> Agent:
    loop = ensure_event_loop()
    mb = use_mailbox() if mailbox is None else mailbox
    actual_port = port or int(os.getenv(f"PORT_{agent_id.upper()}", str(default_port)))
    seed = get_seed_for(agent_id)
    from suraksha_squad.a2a_protocol import _spec_by_id
    if not os.getenv(_spec_by_id(agent_id)["seed_env"], "").strip():
        print(
            f"[WARNING] {name}: using the PUBLIC default seed from the repo. Anyone can derive this agent's private "
            "key. Run `python scripts/init_env.py` to generate your own seeds before going live.",
            flush=True,
        )
    kwargs: Dict[str, Any] = {
        "name": name,
        "seed": seed,
        "port": actual_port,
        "mailbox": mb,
        "loop": loop,
        "description": description,
    }
    rp = readme_path(readme_file)
    if rp:
        kwargs["readme_path"] = rp
    if not mb:
        kwargs["endpoint"] = [f"http://127.0.0.1:{actual_port}/submit"]
    try:
        return Agent(handle_messages_concurrently=True, **kwargs)
    except TypeError:
        return Agent(
            name=name,
            seed=seed,
            port=actual_port,
            endpoint=kwargs.get("endpoint"),
            mailbox=mb,
        )
