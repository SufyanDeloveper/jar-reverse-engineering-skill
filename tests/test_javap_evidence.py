import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "javap_evidence.py"


@unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK required")
class JavapEvidenceTests(unittest.TestCase):
    def test_javap_dump(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = tmp / "Hello.java"
            src.write_text(
                "public class Hello { public static int add(int a,int b){ return a+b; } }\n",
                encoding="utf-8",
            )
            r = subprocess.run(
                ["javac", str(src)], cwd=tmp, capture_output=True, text=True
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            out = tmp / "out"
            r = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--classpath",
                    str(tmp),
                    "--class",
                    "Hello",
                    "--out",
                    str(out),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            dump = out / "Hello.javap.txt"
            self.assertTrue(dump.exists())
            self.assertIn("add", dump.read_text(encoding="utf-8", errors="replace"))


if __name__ == "__main__":
    unittest.main()
