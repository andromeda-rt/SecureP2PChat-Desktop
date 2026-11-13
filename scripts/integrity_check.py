#!/usr/bin/env python3
"""Integrity check – rulează după orice modificare."""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errs = []
for p in ROOT.rglob("*.py"):
    if "__pycache__" in str(p):
        continue
    try:
        ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError as e:
        errs.append(f"SYNTAX {p.relative_to(ROOT)}: {e}")

# critical markers for Tor relay path
sig = (ROOT / "client" / "signaling.py").read_text(encoding="utf-8")
main = (ROOT / "client" / "main.py").read_text(encoding="utf-8")
for label, ok in [
    ("signaling socks", "socks" in sig.lower()),
    ("signaling 9150", "9150" in sig),
    ("main onion defaults", "_apply_onion_defaults" in main),
    ("main 9150", "9150" in main),
]:
    if not ok:
        errs.append(f"MISSING {label}")

if errs:
    print("FAIL")
    for e in errs:
        print(e)
    sys.exit(1)
print("OK integrity", ROOT)
sys.exit(0)
