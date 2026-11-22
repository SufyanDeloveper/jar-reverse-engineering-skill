#!/usr/bin/env python3
"""Static JVM artifact profiler for jar-reverse-engineering skill.

Produces evidence-oriented JSON/markdown profiles. Uses Python stdlib only.
Heuristics are labeled as indicators, not proof of obfuscation or behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

CLASS_MAGIC = b"\xca\xfe\xba\xbe"
TEXT_EXTS = {
    ".mf",
    ".sf",
    ".xml",
    ".properties",
    ".json",
    ".yml",
    ".yaml",
    ".txt",
    ".md",
    ".kotlin_module",
}
SERVICE_PREFIX = "META-INF/services/"
SIG_RE = re.compile(r"^META-INF/.*\.(SF|RSA|DSA|EC)$", re.I)
MAVEN_POM_RE = re.compile(r"^META-INF/maven/.+/pom\.xml$")
MAVEN_PROPS_RE = re.compile(r"^META-INF/maven/.+/pom\.properties$")
SHORT_NAME_RE = re.compile(r"^[a-il-zA-I-L-Z]$|^[a-z]{1,2}$|^[Il1O0]{1,3}$")
SUSPICIOUS_PKG_RE = re.compile(r"(^|\.)(a|b|c|d|e|f|aa|ab|ac)\.?$", re.I)

REFLECTION_APIS = {
    "java/lang/Class.forName",
    "java/lang/ClassLoader.defineClass",
    "java/lang/reflect/Method.invoke",
    "java/lang/reflect/Field.setAccessible",
    "javax/crypto/Cipher.getInstance",
    "java/util/Base64$Decoder.decode",
    "java/lang/Runtime.exec",
    "java/lang/ProcessBuilder",
    "java/net/URLClassLoader",
    "java/lang/invoke/MethodHandles$Lookup",
}
DYNAMIC_LOAD_APIS = {
    "java/lang/ClassLoader",
    "java/net/URLClassLoader",
    "dalvik/system/DexClassLoader",
    "java/lang/invoke/MethodHandles",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def read_u1(buf, off):
    return buf[off], off + 1


def read_u2(buf, off):
    return struct.unpack_from(">H", buf, off)[0], off + 2


def read_u4(buf, off):
    return struct.unpack_from(">I", buf, off)[0], off + 4


def parse_utf8(buf):
    # Minimal JVM modified UTF-8 fallback; decode as UTF-8 with replacement.
    try:
        return buf.decode("utf-8")
    except Exception:
        return buf.decode("latin-1", errors="replace")


def parse_class(data: bytes, name: str) -> dict:
    info = {
        "name": name,
        "valid": False,
        "major": None,
        "minor": None,
        "constant_pool_count": 0,
        "strings": [],
        "class_refs": [],
        "method_refs": [],
        "field_refs": [],
        "bootstrap_methods": False,
        "source_file": None,
        "debug_info": False,
        "annotations": False,
        "is_module_info": name.endswith("module-info.class"),
    }
    if len(data) < 10 or data[:4] != CLASS_MAGIC:
        return info
    off = 4
    try:
        minor, off = read_u2(data, off)
        major, off = read_u2(data, off)
        cp_count, off = read_u2(data, off)
        info.update(
            {
                "valid": True,
                "minor": minor,
                "major": major,
                "constant_pool_count": cp_count,
            }
        )
        cp = [None] * cp_count
        i = 1
        while i < cp_count:
            tag, off = read_u1(data, off)
            if tag == 1:  # Utf8
                ln, off = read_u2(data, off)
                raw = data[off : off + ln]
                off += ln
                cp[i] = ("utf8", parse_utf8(raw))
            elif tag in (3, 4):  # Integer/Float
                cp[i] = ("num", struct.unpack_from(">I", data, off)[0])
                off += 4
            elif tag in (5, 6):  # Long/Double
                cp[i] = ("num2", data[off : off + 8])
                off += 8
                i += 1
            elif tag in (7, 8, 16):  # Class/String/MethodType
                idx, off = read_u2(data, off)
                cp[i] = (tag, idx)
            elif tag in (
                9,
                10,
                11,
                12,
                18,
            ):  # Field/Method/Interface/NameAndType/InvokeDynamic
                a, off = read_u2(data, off)
                b, off = read_u2(data, off)
                cp[i] = (tag, (a, b))
            elif tag == 15:  # MethodHandle
                _, off = read_u1(data, off)
                _, off = read_u2(data, off)
                cp[i] = (tag, None)
            else:
                # Unknown tag; stop parsing safely.
                info["parse_warning"] = f"unknown cp tag {tag} at index {i}"
                return info
            i += 1

        def utf8_at(idx):
            v = cp[idx] if 0 < idx < len(cp) else None
            return v[1] if v and v[0] == "utf8" else None

        for item in cp:
            if not item:
                continue
            tag, val = item
            if tag == 1:
                if len(val) <= 512:
                    info["strings"].append(val)
            elif tag == 7:
                name = utf8_at(val)
                if name:
                    info["class_refs"].append(name)
            elif tag in (9, 10, 11):
                cls_idx, nat_idx = val
                cls = (
                    utf8_at(cp[cls_idx][1])
                    if 0 < cls_idx < len(cp) and cp[cls_idx] and cp[cls_idx][0] == 7
                    else None
                )
                nat = (
                    cp[nat_idx][1]
                    if 0 < nat_idx < len(cp) and cp[nat_idx] and cp[nat_idx][0] == 12
                    else None
                )
                member = utf8_at(nat[0]) if nat else None
                desc = utf8_at(nat[1]) if nat else None
                if cls and member:
                    ref = f"{cls}.{member}{desc or ''}"
                    (info["field_refs"] if tag == 9 else info["method_refs"]).append(
                        ref
                    )

        access, off = read_u2(data, off)
        _, off = read_u2(data, off)
        _, off = read_u2(data, off)
        ifaces_count, off = read_u2(data, off)
        off += 2 * ifaces_count
        fields_count, off = read_u2(data, off)
        for _ in range(fields_count):
            off += 6
            attr_count, off = read_u2(data, off)
            for _ in range(attr_count):
                _, off = read_u2(data, off)
                ln, off = read_u4(data, off)
                off += ln
        methods_count, off = read_u2(data, off)
        for _ in range(methods_count):
            off += 6
            attr_count, off = read_u2(data, off)
            for _ in range(attr_count):
                aname_idx, off = read_u2(data, off)
                ln, off = read_u4(data, off)
                aname = utf8_at(aname_idx)
                attr = data[off : off + ln]
                off += ln
                if aname in (
                    "Code",
                    "LocalVariableTable",
                    "LocalVariableTypeTable",
                    "LineNumberTable",
                ):
                    info["debug_info"] = True
                if aname in (
                    "RuntimeVisibleAnnotations",
                    "RuntimeInvisibleAnnotations",
                ):
                    info["annotations"] = True
        class_attr_count, off = read_u2(data, off)
        for _ in range(class_attr_count):
            aname_idx, off = read_u2(data, off)
            ln, off = read_u4(data, off)
            aname = utf8_at(aname_idx)
            attr = data[off : off + ln]
            off += ln
            if aname == "SourceFile" and len(attr) >= 2:
                idx = struct.unpack_from(">H", attr, 0)[0]
                info["source_file"] = utf8_at(idx)
            if aname == "BootstrapMethods":
                info["bootstrap_methods"] = True
            if aname in ("RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations"):
                info["annotations"] = True
            if aname == "InnerClasses":
                info["debug_info"] = info["debug_info"]
        info["access_flags"] = access
    except Exception as e:
        info["parse_warning"] = str(e)
    return info
def is_probably_text(name: str) -> bool:
    p = Path(name)
    return (
        p.suffix.lower() in TEXT_EXTS
        or name.startswith(SERVICE_PREFIX)
        or name.endswith(".jsp")
    )


def detect_obfuscation_indicators(class_infos, all_strings, entry_names):
    indicators = []
    names = []
    for c in class_infos:
        simple = c["name"].rsplit("/", 1)[-1].replace(".class", "")
        if "$" in simple:
            simple = simple.split("$")[-1]
        if simple and not simple.startswith("module-info"):
            names.append(simple)
    short = sum(1 for n in names if SHORT_NAME_RE.match(n))
    if names and short / len(names) >= 0.25:
        indicators.append(
            {
                "id": "short-identifiers",
                "severity": "medium",
                "evidence": f"{short}/{len(names)} simple class names look short/generated",
                "note": "Heuristic indicator; short names can also come from legitimate minimization or generated code.",
            }
        )
    pkg_segments = []
    for c in class_infos:
        if "/" in c["name"]:
            pkg_segments.extend(c["name"].split("/")[:-1])
    suspicious_pkg = sum(1 for s in pkg_segments if SUSPICIOUS_PKG_RE.match(s))
    if pkg_segments and suspicious_pkg / max(1, len(set(pkg_segments))) >= 0.15:
        indicators.append(
            {
                "id": "suspicious-package-segments",
                "severity": "low",
                "evidence": "Many very short/repetitive package segments detected",
                "note": "Heuristic indicator; verify against known library/package conventions.",
            }
        )

    high_entropy = 0
    for s in all_strings:
        if 20 <= len(s) <= 200:
            b = s.encode("utf-8", errors="ignore")
            if shannon_entropy(b) > 4.6 and re.search(r"[A-Za-z0-9+/=]{20,}", s):
                high_entropy += 1
    if high_entropy >= 20:
        indicators.append(
            {
                "id": "high-entropy-strings",
                "severity": "medium",
                "evidence": f"{high_entropy} high-entropy string constants found",
                "note": "May indicate string encryption/encoding; also common in tokens, hashes, base64 assets.",
            }
        )

    refl = Counter()
    dyn = Counter()
    for c in class_infos:
        for ref in c.get("method_refs", []) + c.get("class_refs", []):
            for api in REFLECTION_APIS:
                if api in ref:
                    refl[api] += 1
            for api in DYNAMIC_LOAD_APIS:
                if api in ref:
                    dyn[api] += 1
    if sum(refl.values()) >= 10:
        indicators.append(
            {
                "id": "reflection-heavy",
                "severity": "medium",
                "evidence": dict(refl.most_common(8)),
                "note": "Reflection can be normal; combined with short names/high-entropy strings it may indicate obfuscation.",
            }
        )
    if sum(dyn.values()) >= 10:
        indicators.append(
            {
                "id": "dynamic-loading-apis",
                "severity": "medium",
                "evidence": dict(dyn.most_common(8)),
                "note": "Dynamic loading may indicate plugins, frameworks, or runtime packing; inspect statically before any execution.",
            }
        )

    if any(
        n.lower().endswith(".class")
        and "module-info.class" not in n.lower()
        and "$" not in n
        and len(Path(n).stem) <= 2
        for n in entry_names
    ):
        indicators.append(
            {
                "id": "short-class-filenames",
                "severity": "low",
                "evidence": "Archive contains very short class file names",
                "note": "Heuristic indicator only.",
            }
        )
    return indicators


def profile_artifact(path: Path, max_classes: int = 5000) -> dict:
    profile = {
        "schema": "jar-reverse-engineering.artifact-profile/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact": {
            "path": str(path),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        },
        "container": {},
        "classes": {},
        "evidence": {},
        "obfuscation_indicators": [],
        "limitations": [],
    }
    if not zipfile.is_zipfile(path):
        profile["container"] = {"type": "non-zip-or-class", "is_zip": False}
        data = path.read_bytes()
        if data[:4] == CLASS_MAGIC:
            cls = parse_class(data, path.name)
            profile["classes"] = summarize_classes([cls])
            profile["obfuscation_indicators"] = detect_obfuscation_indicators(
                [cls], cls.get("strings", []), [path.name]
            )
        else:
            profile["limitations"].append(
                "File is not a ZIP/JAR/WAR/EAR or CLASS; only hash/size recorded."
            )
        return profile

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        class_names = [n for n in names if n.endswith(".class")]
        nested = [
            n for n in names if n.lower().endswith((".jar", ".war", ".ear", ".zip"))
        ]
        manifests = [n for n in names if n.upper() == "META-INF/MANIFEST.MF"]
        signatures = [n for n in names if SIG_RE.match(n)]
        services = [
            n for n in names if n.startswith(SERVICE_PREFIX) and not n.endswith("/")
        ]
        maven_poms = [n for n in names if MAVEN_POM_RE.match(n)]
        maven_props = [n for n in names if MAVEN_PROPS_RE.match(n)]
        multi_release = any(n.startswith("META-INF/versions/") for n in names)
        module_info = [n for n in names if n.endswith("module-info.class")]
        native_libs = [
            n for n in names if n.lower().endswith((".so", ".dll", ".dylib", ".jnilib"))
        ]

        manifest_data = {}
        if manifests:
            try:
                raw = zf.read(manifests[0]).decode("utf-8", errors="replace")
                for line in raw.replace("\r\n", "\n").split("\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        manifest_data[k.strip()] = v.strip()
            except Exception as e:
                profile["limitations"].append(f"Manifest parse failed: {e}")

        class_infos = []
        all_strings = []
        for n in class_names[:max_classes]:
            try:
                data = zf.read(n)
            except Exception as e:
                profile["limitations"].append(f"Failed to read {n}: {e}")
                continue
            cls = parse_class(data, n)
            class_infos.append(cls)
            all_strings.extend(cls.get("strings", []))
        if len(class_names) > max_classes:
            profile["limitations"].append(
                f"Class parsing capped at {max_classes} of {len(class_names)} classes."
            )

        profile["container"] = {
            "type": "zip",
            "entries": len(names),
            "class_files": len(class_names),
            "nested_archives": nested[:200],
            "nested_archive_count": len(nested),
            "manifest": manifest_data,
            "signatures": signatures[:200],
            "signature_count": len(signatures),
            "service_descriptors": services[:200],
            "maven_poms": maven_poms[:200],
            "maven_props": maven_props[:200],
            "multi_release": multi_release,
            "module_info": module_info,
            "native_libraries": native_libs[:200],
        }
        profile["classes"] = summarize_classes(class_infos)
        profile["evidence"] = {
            "service_descriptor_count": len(services),
            "maven_metadata_count": len(maven_poms) + len(maven_props),
            "has_debug_info": any(c.get("debug_info") for c in class_infos),
            "has_source_file_attr": any(c.get("source_file") for c in class_infos),
            "has_bootstrap_methods": any(
                c.get("bootstrap_methods") for c in class_infos
            ),
        }
        profile["obfuscation_indicators"] = detect_obfuscation_indicators(
            class_infos, all_strings, names
        )
    return profile


def summarize_classes(class_infos):
    major_counts = Counter(c.get("major") for c in class_infos if c.get("major"))
    debug = sum(1 for c in class_infos if c.get("debug_info"))
    source = sum(1 for c in class_infos if c.get("source_file"))
    bootstrap = sum(1 for c in class_infos if c.get("bootstrap_methods"))
    annotations = sum(1 for c in class_infos if c.get("annotations"))
    packages = Counter()
    for c in class_infos:
        if "/" in c["name"]:
            packages[c["name"].rsplit("/", 1)[0].replace("/", ".")] += 1
    return {
        "parsed": len(class_infos),
        "valid": sum(1 for c in class_infos if c.get("valid")),
        "major_versions": dict(sorted(major_counts.items())),
        "with_debug_info_attrs": debug,
        "with_source_file": source,
        "with_bootstrap_methods": bootstrap,
        "with_annotations": annotations,
        "top_packages": packages.most_common(20),
    }
def render_markdown(profile: dict) -> str:
    a = profile["artifact"]
    c = profile.get("container", {})
    cls = profile.get("classes", {})
    lines = [
        "# Artifact Profile",
        "",
        f"- Path: `{a.get('path', '')}`",
        f"- Size: {a.get('size_bytes', 0)} bytes",
        f"- SHA-256: `{a.get('sha256', '')}`",
        f"- Generated: {profile.get('generated_at', '')}",
        "",
        "## Container",
        "",
        f"- Type: {c.get('type', 'unknown')}",
        f"- Entries: {c.get('entries', 'n/a')}",
        f"- Class files: {c.get('class_files', 'n/a')}",
        f"- Nested archives: {c.get('nested_archive_count', 0)}",
        f"- Multi-release: {c.get('multi_release', False)}",
        f"- Signed entries: {c.get('signature_count', 0)}",
        f"- Native libraries: {len(c.get('native_libraries', []))}",
        "",
        "## Classes",
        "",
        f"- Parsed/valid: {cls.get('parsed', 0)}/{cls.get('valid', 0)}",
        f"- Major versions: {cls.get('major_versions', {})}",
        f"- With debug attrs: {cls.get('with_debug_info_attrs', 0)}",
        f"- With SourceFile: {cls.get('with_source_file', 0)}",
        f"- With BootstrapMethods: {cls.get('with_bootstrap_methods', 0)}",
        "",
        "## Obfuscation indicators (heuristic)",
        "",
    ]
    inds = profile.get("obfuscation_indicators", [])
    if not inds:
        lines.append("- No strong heuristic indicators detected by this static scan.")
    else:
        for i in inds:
            lines.append(
                f"- `{i['id']}` ({i['severity']}): {i['evidence']} — {i['note']}"
            )
    if profile.get("limitations"):
        lines += ["", "## Limitations", ""]
        for l in profile["limitations"]:
            lines.append(f"- {l}")
    lines += [
        "",
        "## Evidence note",
        "",
        "- This report is static, heuristic, and non-executing. Indicators are not proof of maliciousness or specific obfuscator use.",
    ]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(
        description="Static JVM artifact profiler (evidence-oriented)"
    )
    ap.add_argument("artifact", help="Path to .jar/.war/.ear/.class/.zip")
    ap.add_argument("--json", dest="json_out", help="Write JSON profile to file")
    ap.add_argument("--md", dest="md_out", help="Write Markdown profile to file")
    ap.add_argument(
        "--max-classes", type=int, default=5000, help="Max classes to parse"
    )
    args = ap.parse_args()
    path = Path(args.artifact)
    if not path.exists():
        raise SystemExit(f"Artifact not found: {path}")
    profile = profile_artifact(path, max_classes=args.max_classes)
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    if args.md_out:
        Path(args.md_out).write_text(render_markdown(profile), encoding="utf-8")
    if not args.json_out and not args.md_out:
        print(json.dumps(profile, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
