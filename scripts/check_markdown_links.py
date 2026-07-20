#!/usr/bin/env python3
"""Validate repository-relative links in Markdown files."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def main() -> int:
    failures = []
    for doc in ROOT.rglob("*.md"):
        if ".git" in doc.parts:
            continue
        text = doc.read_text(encoding="utf-8")
        for raw in LINK.findall(text):
            target = raw.strip().split()[0].strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_part = unquote(target.split("#", 1)[0])
            if path_part and not (doc.parent / path_part).resolve().exists():
                failures.append(f"{doc.relative_to(ROOT)} -> {target}")
    if failures:
        print("broken relative Markdown links:")
        print("\n".join(f"- {item}" for item in failures))
        return 1
    print("markdown links passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
