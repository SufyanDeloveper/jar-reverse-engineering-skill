#!/usr/bin/env python3
"""Basic structural validation for the jar-reverse-engineering skill repo."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = [
    "SKILL.md",
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "references/evidence.md",
    "references/fidelity.md",
    "references/obfuscation-patterns.md",
    "references/tooling-evaluation.md",
    "examples/RECOVERY.example.md",
    "scripts/artifact_profile.py",
    "scripts/extract_safe.py",
    "scripts/decompiler_compare.py",
    "scripts/javap_evidence.py",
    "scripts/validate_skill.py",
    "tools/jvmtool/src/JvmTool.java",
    "tools/jvmtool/build.py",
]


def main() -> int:
    errors = []
    for rel in REQUIRED:
        if not (ROOT / rel).exists():
            errors.append(f"Missing required file: {rel}")
    skill = ROOT / "SKILL.md"
    text = skill.read_text(encoding="utf-8") if skill.exists() else ""
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        errors.append("SKILL.md missing YAML frontmatter")
    else:
        fm = m.group(1)
        name = re.search(r"^name:\s*(.+)$", fm, re.M)
        desc = re.search(r"^description:\s*(.+)$", fm, re.M)
        if not name or name.group(1).strip() != "jar-reverse-engineering":
            errors.append("SKILL.md frontmatter name must be jar-reverse-engineering")
        if not desc or len(desc.group(1).strip()) > 1024:
            errors.append("SKILL.md description missing or too long")
    for ref in ["references/evidence.md", "references/fidelity.md"]:
        if ref not in text:
            errors.append(f"SKILL.md should reference {ref}")
    for script in ["scripts/artifact_profile.py"]:
        if script.replace("/", "\\") not in text and script not in text:
            errors.append(f"SKILL.md should mention {script}")
    if errors:
        for e in errors:
            print("ERROR:", e)
        return 1
    print("Validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
