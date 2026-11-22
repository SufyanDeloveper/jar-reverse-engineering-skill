import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ValidateSkillTests(unittest.TestCase):
    def test_validate_skill_script_passes(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "validate_skill.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Validation passed", r.stdout)


if __name__ == "__main__":
    unittest.main()
