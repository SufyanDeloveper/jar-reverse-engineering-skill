#!/usr/bin/env python3
"""Compare outputs from multiple user-configured decompiler commands.

This script does NOT bundle decompilers. You provide commands; it runs them,
collects outputs, and writes a comparison report. Use only trusted local tools.

Example config JSON:
{
  "decompilers": [
    {"name": "cfr", "cmd": ["java", "-jar", "/path/cfr.jar", "{jar}", "--outputdir", "{out}"]},
    {"name": "vineflower", "cmd": ["java", "-jar", "/path/vineflower.jar", "{jar}", "{out}"]}
  ]
}
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path


def run_one(name: str, cmd: list[str], out_dir: Path, timeout: int) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    log = out_dir / "_run.log"
    start = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        duration = time.time() - start
        log.write_text(
            (r.stdout or "") + "\n---STDERR---\n" + (r.stderr or ""),
            encoding="utf-8",
            errors="replace",
        )
        java_files = list(out_dir.rglob("*.java"))
        return {
            "name": name,
            "cmd": cmd,
            "exit_code": r.returncode,
            "duration_sec": round(duration, 2),
            "java_files": len(java_files),
            "log": str(log),
            "output_dir": str(out_dir),
        }
    except Exception as e:
        return {"name": name, "cmd": cmd, "error": str(e), "output_dir": str(out_dir)}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run and compare multiple decompiler commands"
    )
    ap.add_argument("--jar", required=True, help="Input JAR/class archive")
    ap.add_argument(
        "--config", required=True, help="JSON config with decompiler commands"
    )
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument(
        "--timeout", type=int, default=600, help="Per-decompiler timeout seconds"
    )
    args = ap.parse_args()

    jar = Path(args.jar).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    results = []
    for d in cfg.get("decompilers", []):
        name = d["name"]
        cmd = [str(x).format(jar=str(jar), out=str(out / name)) for x in d["cmd"]]
        print(f"Running {name}...")
        results.append(run_one(name, cmd, out / name, args.timeout))

    report = {"jar": str(jar), "results": results}
    (out / "compare-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # simple overlap report by relative .java paths
    by_name = {}
    for r in results:
        p = Path(r.get("output_dir", ""))
        files = (
            {str(f.relative_to(p)).replace("\\", "/") for f in p.rglob("*.java")}
            if p.exists()
            else set()
        )
        by_name[r["name"]] = files
    all_files = sorted(set().union(*by_name.values())) if by_name else []
    matrix = []
    for f in all_files:
        row = {"file": f}
        for n, files in by_name.items():
            row[n] = f in files
        matrix.append(row)
    (out / "file-matrix.json").write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    md = [
        "# Decompiler compare report",
        "",
        f"Jar: `{jar}`",
        "",
        "| Decompiler | Exit | Java files | Duration(s) | Log |",
        "|---|---:|---:|---:|---|",
    ]
    for r in results:
        md.append(
            f"| {r['name']} | {r.get('exit_code', 'err')} | {r.get('java_files', 0)} | {r.get('duration_sec', '')} | `{r.get('log', '')}` |"
        )
    md += [
        "",
        "## Notes",
        "",
        "- This report compares presence/exit codes only; it does not prove semantic correctness.",
        "- Inspect differing outputs against bytecode (`javap -v -p -c`).",
    ]
    (out / "compare-report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"Wrote {out / 'compare-report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
