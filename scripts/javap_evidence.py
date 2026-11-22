#!/usr/bin/env python3
"""Collect javap bytecode evidence for specific classes from a JAR.

Uses JDK `javap` as a ground-truth fallback when decompilers fail or disagree.
Does not execute artifact code.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

SAFE_RE = re.compile(r"[^A-Za-z0-9._$-]+")


def safe_filename(cls: str) -> str:
    cleaned = SAFE_RE.sub("_", cls).strip("._")
    if not cleaned:
        cleaned = "class"
    return cleaned.replace(".", "_").replace("$", "__")[:180] + ".javap.txt"


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
    ap.add_argument(
        "--timeout", type=int, default=120, help="Per-class timeout seconds"
    )
    args = ap.parse_args()

    if args.timeout <= 0:
        raise SystemExit("--timeout must be > 0")
    javap_cmd = shutil.which(args.javap) or args.javap
    classpath = Path(args.classpath)
    if not classpath.exists():
        raise SystemExit(f"Classpath not found: {classpath}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    failures = 0
    for cls in args.classes:
        cmd = [
            javap_cmd,
            "-private",
            "-verbose",
            "-c",
            "-s",
            "-classpath",
            str(classpath),
            cls,
        ]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=args.timeout
            )
            content = (r.stdout or "") + (
                "\n---STDERR---\n" + r.stderr if r.stderr else ""
            )
            exit_code = r.returncode
        except FileNotFoundError:
            content = f"javap executable not found: {args.javap}\n"
            exit_code = 127
        except subprocess.TimeoutExpired as e:
            stdout = e.stdout or ""
            stderr = e.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            content = (
                stdout
                + "\n---STDERR---\n"
                + stderr
                + f"\n---TIMEOUT---\n{args.timeout}s\n"
            )
            exit_code = 124
        p = out / safe_filename(cls)
        p.write_text(content, encoding="utf-8", errors="replace")
        status = "ok" if exit_code == 0 else "FAIL"
        if exit_code != 0:
            failures += 1
        print(f"{cls}: {status} exit={exit_code} -> {p}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
