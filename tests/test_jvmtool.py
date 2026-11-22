import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL_SRC = ROOT / "tools" / "jvmtool" / "src" / "JvmTool.java"
OUT = ROOT / "tools" / "jvmtool" / "out"


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

    cp = [
        None,
        utf8(name),
        cls(1),
        utf8("java/lang/Object"),
        cls(3),
        utf8("SourceFile"),
        utf8(f"{name}.java"),
    ]
    body = b"".join(cp[1:])
    out = b"\xca\xfe\xba\xbe" + u2(0) + u2(65) + u2(len(cp)) + body
    out += u2(0x21) + u2(2) + u2(4) + u2(0) + u2(0) + u2(0)
    out += u2(1) + u2(6) + u4(2) + u2(7)
    return out


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
class JvmToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["javac", "-g", "-d", str(OUT), str(TOOL_SRC)],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            raise unittest.SkipTest(
                "javac failed (JDK 24+ with classfile API required): " + r.stderr
            )

    def test_profile_and_scan(self):
        with tempfile.TemporaryDirectory() as td:
            jar = Path(td) / "sample.jar"
            with zipfile.ZipFile(jar, "w") as zf:
                zf.writestr("com/example/Hello.class", build_minimal_class("Hello"))
            pjson = Path(td) / "p.json"
            sjson = Path(td) / "s.json"
            rp = subprocess.run(
                [
                    "java",
                    "-cp",
                    str(OUT),
                    "JvmTool",
                    "profile",
                    str(jar),
                    "--json",
                    str(pjson),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(rp.returncode, 0, rp.stdout + rp.stderr)
            rs = subprocess.run(
                [
                    "java",
                    "-cp",
                    str(OUT),
                    "JvmTool",
                    "scan",
                    str(jar),
                    "--json",
                    str(sjson),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(rs.returncode, 0, rs.stdout + rs.stderr)
            p = json.loads(pjson.read_text(encoding="utf-8"))
            s = json.loads(sjson.read_text(encoding="utf-8"))
            self.assertEqual(p["schema"], "jvmtool.profile/v1")
            self.assertEqual(p["summary"]["validClasses"], 1)
            self.assertEqual(s["schema"], "jvmtool.scan/v1")


if __name__ == "__main__":
    unittest.main()
