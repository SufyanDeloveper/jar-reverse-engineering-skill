import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "decompiler_compare.py"


class DecompilerCompareTests(unittest.TestCase):
    def test_compare_dummy(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            jar = tmp / "dummy.jar"
            jar.write_bytes(b"PK\x05\x06" + b"\0" * 18)  # empty zip
            fake = tmp / "fake.py"
            fake.write_text(
                "import sys, pathlib\nout=pathlib.Path(sys.argv[2])\nout.mkdir(parents=True, exist_ok=True)\n(out/'A.java').write_text('class A{}', encoding='utf-8')\n",
                encoding="utf-8",
            )
            cfg = tmp / "cfg.json"
            cfg.write_text(
                json.dumps(
                    {
                        "decompilers": [
                            {
                                "name": "fake",
                                "cmd": [sys.executable, str(fake), "{jar}", "{out}"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = tmp / "out"
            r = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--jar",
                    str(jar),
                    "--config",
                    str(cfg),
                    "--out",
                    str(out),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            report = json.loads(
                (out / "compare-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["results"][0]["java_files"], 1)

    def test_rejects_bad_config(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            jar = tmp / "dummy.jar"
            jar.write_bytes(b"PK\x05\x06" + b"\0" * 18)
            cfg = tmp / "cfg.json"
            cfg.write_text(json.dumps({"decompilers": []}), encoding="utf-8")
            r = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--jar",
                    str(jar),
                    "--config",
                    str(cfg),
                    "--out",
                    str(tmp / "out"),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("decompilers", r.stdout + r.stderr)

    def test_sanitizes_name(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            jar = tmp / "dummy.jar"
            jar.write_bytes(b"PK\x05\x06" + b"\0" * 18)
            fake = tmp / "fake.py"
            fake.write_text(
                "import sys, pathlib\nout=pathlib.Path(sys.argv[2])\nout.mkdir(parents=True, exist_ok=True)\n(out/'A.java').write_text('class A{}', encoding='utf-8')\n",
                encoding="utf-8",
            )
            cfg = tmp / "cfg.json"
            cfg.write_text(
                json.dumps(
                    {
                        "decompilers": [
                            {
                                "name": "../evil:name",
                                "cmd": [sys.executable, str(fake), "{jar}", "{out}"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = tmp / "out"
            r = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--jar",
                    str(jar),
                    "--config",
                    str(cfg),
                    "--out",
                    str(out),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            report = json.loads(
                (out / "compare-report.json").read_text(encoding="utf-8")
            )
            name = report["results"][0]["name"]
            self.assertNotIn("..", name)
            self.assertNotIn("/", name)
            self.assertNotIn("\\", name)
            self.assertNotIn(":", name)


if __name__ == "__main__":
    unittest.main()
