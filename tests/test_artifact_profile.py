import json
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "artifact_profile.py"


def build_minimal_class(name: str = "Hello") -> bytes:
    def u1(x):
        return bytes([x & 0xFF])

    def u2(x):
        return x.to_bytes(2, "big")

    def u4(x):
        return x.to_bytes(4, "big")

    def utf8(s):
        b = s.encode("utf-8")
        return u1(1) + u2(len(b)) + b

    def cls(idx):
        return u1(7) + u2(idx)

    cp = [None]
    cp.append(utf8(name))  # 1
    cp.append(cls(1))  # 2
    cp.append(utf8("java/lang/Object"))  # 3
    cp.append(cls(3))  # 4
    cp.append(utf8("Code"))  # 5
    cp.append(utf8("SourceFile"))  # 6
    cp.append(utf8(f"{name}.java"))  # 7
    body = b"".join(cp[1:])
    out = b"\xca\xfe\xba\xbe" + u2(0) + u2(61) + u2(len(cp)) + body
    out += u2(0x0021)  # access public super
    out += u2(2)  # this_class
    out += u2(4)  # super_class
    out += u2(0)  # interfaces
    out += u2(0)  # fields
    out += u2(0)  # methods
    attr = u2(6) + u4(2) + u2(7)  # SourceFile
    out += u2(1) + attr
    return out


class ArtifactProfileTests(unittest.TestCase):
    def test_artifact_profile_json_and_md(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            jar = tmp / "sample.jar"
            with zipfile.ZipFile(jar, "w") as zf:
                zf.writestr("com/example/Hello.class", build_minimal_class("Hello"))
                zf.writestr(
                    "META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nBuilt-By: test\n\n"
                )
            json_out = tmp / "profile.json"
            md_out = tmp / "profile.md"
            r = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(jar),
                    "--json",
                    str(json_out),
                    "--md",
                    str(md_out),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            profile = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(
                profile["schema"], "jar-reverse-engineering.artifact-profile/v1"
            )
            self.assertTrue(profile["artifact"]["sha256"])
            self.assertEqual(profile["container"]["class_files"], 1)
            self.assertEqual(profile["classes"]["valid"], 1)
            md = md_out.read_text(encoding="utf-8")
            self.assertIn("# Artifact Profile", md)
            self.assertIn("SHA-256", md)

    def test_artifact_profile_non_zip(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "plain.txt"
            p.write_text("hello", encoding="utf-8")
            r = subprocess.run(
                [sys.executable, str(SCRIPT), str(p)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            profile = json.loads(r.stdout)
            self.assertFalse(profile["container"]["is_zip"])


    def test_parse_class_handles_modern_cp_tags(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("artifact_profile", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        def u1(x): return bytes([x & 0xFF])
        def u2(x): return x.to_bytes(2, "big")
        def u4(x): return x.to_bytes(4, "big")
        def utf8(s):
            b = s.encode("utf-8")
            return u1(1) + u2(len(b)) + b
        def cls(idx): return u1(7) + u2(idx)
        def module(idx): return u1(19) + u2(idx)
        def package(idx): return u1(20) + u2(idx)
        def condyn(bsm, nat): return u1(17) + u2(bsm) + u2(nat)
        def name_and_type(n, t): return u1(12) + u2(n) + u2(t)

        cp = [None]
        cp.append(utf8("Hello"))                 # 1
        cp.append(cls(1))                         # 2
        cp.append(utf8("java/lang/Object"))       # 3
        cp.append(cls(3))                         # 4
        cp.append(utf8("mod"))                    # 5
        cp.append(module(5))                      # 6
        cp.append(utf8("pkg"))                    # 7
        cp.append(package(7))                     # 8
        cp.append(utf8("dynName"))                # 9
        cp.append(utf8("I"))                      # 10
        cp.append(name_and_type(9, 10))           # 11
        cp.append(condyn(0, 11))                  # 12
        cp.append(utf8("SourceFile"))             # 13
        cp.append(utf8("Hello.java"))             # 14
        body = b"".join(cp[1:])
        out = b"\xca\xfe\xba\xbe" + u2(0) + u2(65) + u2(len(cp)) + body
        out += u2(0x0021) + u2(2) + u2(4) + u2(0) + u2(0) + u2(0)
        out += u2(1) + u2(13) + u4(2) + u2(14)

        info = mod.parse_class(out, "Hello.class")
        self.assertTrue(info["valid"])
        self.assertEqual(info["major"], 65)
        self.assertNotIn("parse_warning", info)


if __name__ == "__main__":
    unittest.main()
