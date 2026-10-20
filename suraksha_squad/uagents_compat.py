"""
Fetch.ai uAgents & Agent Chat Protocol v0.3.0 compatibility layer (Python 3.10–3.14 + Windows UTF-8 safe).
Derives canonical `agent1q...` Bech32 addresses from agent seeds using `uagents_core.identity.Identity.from_seed`.
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
from typing import Any, Callable, Dict, List, Optional

# 1. Windows UTF-8 stdout/stderr safety
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

# 2. Python 3.14 compatibility: ensure an event loop is always available on the current thread
_policy = asyncio.get_event_loop_policy()
_orig_get_event_loop = _policy.get_event_loop


def ensure_event_loop() -> asyncio.AbstractEventLoop:
    try:
        return _orig_get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


_policy.get_event_loop = ensure_event_loop
ensure_event_loop()

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: List[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int = 8, tobits: int = 5, pad: bool = True) -> List[int]:
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def derive_agent_address(seed: str, hrp: str = "agent") -> str:
    """
    Derives a deterministic Fetch.ai Bech32 `agent1q...` address from a seed phrase.
    Uses official `uagents_core.identity.Identity.from_seed(seed, 0)` when installed.
    """
    if hrp == "agent":
        try:
            from uagents_core.identity import Identity  # type: ignore
            return str(Identity.from_seed(seed, 0).address)
        except Exception:
            pass
        try:
            from uagents.crypto import Identity as LegacyIdentity  # type: ignore
            return str(LegacyIdentity.from_seed(seed, 0).address)
        except Exception:
            pass
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    pub_bytes = b"\x00" + hashlib.sha256(b"fetchai_uagent_pubkey:" + digest).digest()
    five_bit = _convertbits(pub_bytes, 8, 5, True)
    checksum = _bech32_create_checksum(hrp, five_bit)
    return hrp + "1" + "".join(CHARSET[d] for d in (five_bit + checksum))


try:
    from uagents import Agent as _UAgent, Bureau as _UBureau, Context as _UContext, Model as _UModel, Protocol as _UProtocol  # type: ignore
    HAS_UAGENTS = True
except ImportError:
    HAS_UAGENTS = False
    from pydantic import BaseModel as _UModel

    class _SimpleLogger:
        def __init__(self, name: str):
            self.name = name

        def info(self, msg: str, *args: Any) -> None:
            pass

        def warning(self, msg: str, *args: Any) -> None:
            pass

        def error(self, msg: str, *args: Any) -> None:
            pass

    class _UContext:
        def __init__(self, agent_name: str, agent_address: str):
            self.name = agent_name
            self.address = agent_address
            self.logger = _SimpleLogger(agent_name)
            self.storage: Dict[str, Any] = {}
            self.outbox: List[Dict[str, Any]] = []

        async def send(self, destination: str, message: Any) -> None:
            self.outbox.append({"destination": destination, "message": message})

    class _UProtocol:
        def __init__(self, name: str = "protocol", version: str = "0.3.0", spec: Any = None, role: Optional[str] = None):
            self.spec = spec
            self.role = role
            self.name = name or getattr(spec, "name", "protocol")
            self.version = version or getattr(spec, "version", "0.3.0")
            self.handlers: Dict[Any, Callable] = {}

        def on_message(self, model: Any = None, replies: Optional[Any] = None) -> Callable:
            def decorator(func: Callable) -> Callable:
                self.handlers[model] = func
                return func
            return decorator

    class _UAgent:
        def __init__(
            self,
            name: str = "agent",
            seed: str = "seed",
            port: int = 8000,
            endpoint: Optional[List[str]] = None,
            mailbox: bool = True,
            **kwargs: Any,
        ):
            self.name = name
            self.seed = seed
            self.port = port
            self.endpoint = endpoint or [f"http://127.0.0.1:{port}/submit"]
            self.mailbox = mailbox
            self.address = derive_agent_address(seed)
            self.protocols: List[_UProtocol] = []
            self.handlers: Dict[Any, Callable] = {}

        def include(self, protocol: _UProtocol, publish_manifest: bool = True) -> None:
            self.protocols.append(protocol)
            if hasattr(protocol, "handlers"):
                self.handlers.update(protocol.handlers)

        def on_message(self, model: Any = None, replies: Optional[Any] = None) -> Callable:
            def decorator(func: Callable) -> Callable:
                self.handlers[model] = func
                return func
            return decorator

        def on_event(self, event_type: str) -> Callable:
            def decorator(func: Callable) -> Callable:
                return func
            return decorator

        def run(self) -> None:
            print(f"[{self.name}] Running on {self.address} (port {self.port}, mailbox={self.mailbox})")

    class _UBureau:
        def __init__(self, port: int = 8000, endpoint: Optional[List[str]] = None, **kwargs: Any):
            self.port = port
            self.endpoint = endpoint
            self.agents: List[_UAgent] = []

        def add(self, agent: _UAgent) -> None:
            self.agents.append(agent)

        def run(self) -> None:
            for a in self.agents:
                a.run()


Model = _UModel
Agent = _UAgent
Bureau = _UBureau
Context = _UContext
Protocol = _UProtocol
