#!/usr/bin/env python3
"""Build JvmTool (requires JDK 24+ with java.lang.classfile API)."""

from __future__ import annotations
import shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src" / "JvmTool.java"
OUT = ROOT / "out"
JAR = ROOT / "jvmtool.jar"


def main() -> int:
    javac = shutil.which("javac")
    if not javac:
        print("javac not found; JDK 24+ required to build JvmTool", file=sys.stderr)
        return 2
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    r = subprocess.run(
        [javac, "-g", "-d", str(OUT), str(SRC)], capture_output=True, text=True
    )
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        return r.returncode
    jar = shutil.which("jar")
    if jar:
        subprocess.run(
            [jar, "--create", "--file", str(JAR), "-C", str(OUT), "."], check=True
        )
    print(f"Built {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
