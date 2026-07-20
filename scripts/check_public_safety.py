#!/usr/bin/env python3
"""Fail when public documentation contains common live-lab identifiers or secrets."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", "__pycache__"}
TEXT_SUFFIXES = {".md", ".yml", ".yaml", ".json", ".py", ".txt"}

PATTERNS = {
    "private IPv4 address": re.compile(r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"),
    "overlay IPv4 address": re.compile(r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}\b"),
    "MAC address": re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
    "absolute operator path": re.compile(r"(?:^|[\s`'\"])(?:/root/|/home/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\)"),
    "internal domain": re.compile(r"\bmayuri\.lab\b", re.I),
    "operator domain": re.compile(r"\bmell0wx\.tech\b", re.I),
    "GitHub token": re.compile(r"\bgh[opusr]_[A-Za-z0-9_]{20,}\b"),
    "likely API key assignment": re.compile(r"(?im)^\s*(?:api[_-]?key|token|password|secret|webhook)[A-Za-z0-9_.-]*\s*[:=]\s*(?!\[?REDACTED\]?|runtime-only|external-secret-store)[^\s#]{8,}\s*$"),
}


def iter_files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"LICENSE"}:
            yield path


def main() -> int:
    findings = []
    for path in iter_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append((path.relative_to(ROOT), line, label))
    if findings:
        for path, line, label in findings:
            print(f"FAIL {path}:{line}: {label}")
        return 1
    print("public-safety scan passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
