#!/usr/bin/env python3
"""Create .env with fresh random agent seeds if .env does not exist yet."""
import secrets
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
target, example = root / ".env", root / ".env.example"
if target.exists():
    sys.exit(".env already exists - not touching it (edit it by hand).")
lines = []
for line in example.read_text(encoding="utf-8").splitlines():
    if "_SEED=" in line and not line.strip().startswith("#"):
        k = line.split("=", 1)[0].strip()
        line = f"{k}={secrets.token_hex(24)}"
    lines.append(line)
target.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("Created .env with fresh 24-byte hex seeds for all 12 Suraksha Squad agents.")
