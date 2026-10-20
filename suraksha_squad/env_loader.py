"""
Universal `.env` Auto-Loader & Multi-Project Key Alias Mapper.
Automatically detects and normalizes API keys from `TeamMAA_MK-Invoice-Desk_with-ENV`,
`MK-Enterprise-OS`, `MK-ActionPilot`, or custom `.env` files pasted via CLI or Web UI.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, List, Optional


KEY_ALIASES: Dict[str, List[str]] = {
    "ASI1_API_KEY": [
        "ASI1_API_KEY",
        "ASI_ONE_API_KEY",
        "ASI_API_KEY",
        "ASI1_KEY",
        "FETCH_ASI1_KEY",
        "ASI_LLM_API_KEY",
    ],
    "CTX_API_KEY": [
        "CTX_API_KEY",
        "CONTEXT_DEV_API_KEY",
        "CONTEXT_API_KEY",
        "CONTEXTDEV_API_KEY",
        "CONTEXT_DEV_KEY",
        "MCP_CONTEXT_KEY",
    ],
    "AGENTVERSE_API_KEY": [
        "AGENTVERSE_API_KEY",
        "AGENTVERSE_KEY",
        "AGENTVERSE_TOKEN",
        "AGENTVERSE_MAILBOX_KEY",
        "MAILBOX_API_KEY",
    ],
    "GOOGLE_SAFE_BROWSING_API_KEY": [
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "SAFE_BROWSING_API_KEY",
        "GSB_API_KEY",
    ],
}


def parse_env_text(raw_env_content: str) -> Dict[str, str]:
    """Parses raw `.env` file content into a dictionary of key-value pairs."""
    parsed: Dict[str, str] = {}
    for raw_line in raw_env_content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        # Strip inline comments if unquoted
        if " #" in v:
            v = v.split(" #", 1)[0].strip()
        v = v.strip('"').strip("'")
        if k:
            parsed[k] = v
    return parsed


def normalize_and_apply_env(env_dict: Dict[str, str], overwrite: bool = True) -> Dict[str, str]:
    """Applies parsed env vars to `os.environ` and maps all project key aliases to canonical names."""
    applied: Dict[str, str] = {}
    for k, v in env_dict.items():
        if not v:
            continue
        if overwrite or k not in os.environ:
            os.environ[k] = v
        applied[k] = v

    # Map aliases so any key name from MK-Invoice-Desk / ActionPilot / Enterprise-OS works automatically
    for canonical, aliases in KEY_ALIASES.items():
        val = ""
        for alias in aliases:
            cand = env_dict.get(alias, "").strip()
            if cand and not cand.startswith(("your_", "replace_", "asi1_live_ready", "ctx_live_ready", "av_live_ready")):
                val = cand
                break
        if not val:
            for alias in aliases:
                cand = os.environ.get(alias, "").strip()
                if cand and not cand.startswith(("your_", "replace_", "asi1_live_ready", "ctx_live_ready", "av_live_ready")):
                    val = cand
                    break
        if val:
            os.environ[canonical] = val
            if canonical == "CTX_API_KEY":
                os.environ["CONTEXT_DEV_API_KEY"] = val
            applied[canonical] = val
    return applied


def auto_load_dotenv(search_dirs: Optional[List[Path]] = None) -> Dict[str, str]:
    """Searches for `.env` files in project root or parent directories and loads them."""
    dirs = search_dirs or [Path.cwd(), Path(__file__).resolve().parent.parent]
    combined: Dict[str, str] = {}
    for d in dirs:
        for candidate in (d / ".env", d / ".env.local", d / ".env.production"):
            if candidate.exists() and candidate.is_file():
                try:
                    parsed = parse_env_text(candidate.read_text(encoding="utf-8", errors="replace"))
                    combined.update(normalize_and_apply_env(parsed, overwrite=False))
                except Exception:
                    pass
    return combined


def get_active_env_summary() -> Dict[str, any]:
    """Returns a safe, masked summary of active API keys and environment settings."""
    def _mask(val: str) -> str:
        if not val or val.startswith(("your_", "replace_", "asi1_live_ready", "ctx_live_ready", "av_live_ready")):
            return "not_set (using deterministic offline fallback)"
        return "configured (live key active)"

    asi1 = os.environ.get("ASI1_API_KEY", "").strip()
    ctx = os.environ.get("CTX_API_KEY", "") or os.environ.get("CONTEXT_DEV_API_KEY", "")
    av = os.environ.get("AGENTVERSE_API_KEY", "").strip()
    gsb = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    return {
        "asi1_api_key": _mask(asi1),
        "context_dev_api_key": _mask(ctx.strip()),
        "agentverse_api_key": _mask(av),
        "safe_browsing_api_key": _mask(gsb),
        "asi1_live": bool(asi1 and not asi1.startswith(("your_", "replace_", "asi1_live_ready"))),
        "context_dev_live": bool(ctx and not ctx.startswith(("your_", "replace_", "ctx_live_ready"))),
        "agentverse_live": bool(av and not av.startswith(("your_", "replace_", "av_live_ready"))),
    }
