#!/usr/bin/env python3
"""Safely extract a JVM archive (JAR/WAR/EAR/ZIP) without executing anything.

Creates an output directory with extracted files, an inventory, and SHA-256 hashes.
Protects against basic zip-slip path traversal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_target(root: Path, name: str) -> Path:
    target = (root / name).resolve()
    root_resolved = root.resolve()
    if not str(target).startswith(str(root_resolved)):
        raise ValueError(f"Unsafe path traversal entry: {name}")
    return target


def main() -> int:
    ap = argparse.ArgumentParser(description="Safe static extraction of JVM archives")
    ap.add_argument("artifact", help="Path to .jar/.war/.ear/.zip")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--inventory", help="Write inventory JSON to this file")
    args = ap.parse_args()

    artifact = Path(args.artifact)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    inventory = {
        "artifact": str(artifact),
        "artifact_sha256": sha256_bytes(artifact.read_bytes()),
        "entries": [],
    }

    with zipfile.ZipFile(artifact) as zf:
        for info in zf.infolist():
            name = info.filename
            target = safe_target(out, name)
            rec = {"name": name, "is_dir": info.is_dir(), "size": info.file_size}
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                data = zf.read(info)
                target.write_bytes(data)
                rec["sha256"] = sha256_bytes(data)
            inventory["entries"].append(rec)

    inv_path = Path(args.inventory) if args.inventory else out / "inventory.json"
    inv_path.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Extracted {len(inventory['entries'])} entries to {out}")
    print(f"Inventory: {inv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
