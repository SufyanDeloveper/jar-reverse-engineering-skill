#!/usr/bin/env python3
"""Collect javap bytecode evidence for specific classes from a JAR.

Uses JDK `javap` as a ground-truth fallback when decompilers fail or disagree.
Does not execute artifact code.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Dump javap evidence for classes")
    ap.add_argument("--classpath", required=True, help="JAR or classpath entry")
    ap.add_argument(
        "--class",
        dest="classes",
        action="append",
        required=True,
        help="Fully qualified class name (repeatable)",
    )
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--javap", default="javap", help="javap executable")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for cls in args.classes:
        cmd = [
            args.javap,
            "-private",
            "-verbose",
            "-c",
            "-s",
            "-classpath",
            args.classpath,
            cls,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        safe = cls.replace(".", "_").replace("$", "__")
        p = out / f"{safe}.javap.txt"
        p.write_text(
            (r.stdout or "") + ("\n---STDERR---\n" + r.stderr if r.stderr else ""),
            encoding="utf-8",
            errors="replace",
        )
        print(f"{cls}: exit={r.returncode} -> {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
