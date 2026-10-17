"""tools/check_scope.sh on throwaway repositories: bank/contract/ is gate-side, bank content is triage/, broker/, intake/.
Run: python3 -m unittest discover -s tests -t ."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FILES = ["bank/contract/answer.yaml", "bank/triage/parameters.yaml", "bank/broker/capabilities.yaml", "bank/intake/rule-map.yaml",
         "engine/executor.py", "tools/validate.py", "tests/engine/test_x.py",
         "tests/cases/D-0001/a.yaml"]


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, capture_output=True, text=True, check=True)


class CheckScope(unittest.TestCase):
    def run_change(self, edits, add=()):
        tmp = tempfile.mkdtemp()
        try:
            git(tmp, "init", "-q")
            for f in FILES:
                os.makedirs(os.path.join(tmp, os.path.dirname(f)), exist_ok=True)
                open(os.path.join(tmp, f), "w").write("expect:\n  outcome: escalate\n" if f.startswith("tests/cases/") else "x: 1\n")
            os.makedirs(os.path.join(tmp, "tools"), exist_ok=True)
            shutil.copy(os.path.join(ROOT, "tools", "check_scope.sh"), os.path.join(tmp, "tools", "check_scope.sh"))
            git(tmp, "add", "-A")
            git(tmp, "commit", "-qm", "base")
            base = git(tmp, "rev-parse", "HEAD").stdout.strip()
            for f in edits:
                open(os.path.join(tmp, f), "a").write("y: 2\n")
            for f in add:
                os.makedirs(os.path.join(tmp, os.path.dirname(f)), exist_ok=True)
                open(os.path.join(tmp, f), "w").write("z: 3\n")
            r = subprocess.run(["bash", "tools/check_scope.sh"], cwd=tmp, capture_output=True, text=True, env=dict(os.environ, BASE=base))
            return r.returncode, r.stdout
        finally:
            shutil.rmtree(tmp)

    def test_contract_with_engine_tools_and_tests_passes(self):
        rc, out = self.run_change(["bank/contract/answer.yaml", "engine/executor.py", "tools/validate.py", "tests/engine/test_x.py"],
                                  add=["bank/contract/proof.yaml"])
        self.assertEqual(rc, 0, out)
        self.assertIn("not a bank PR", out)

    def test_contract_with_triage_fails(self):
        rc, out = self.run_change(["bank/contract/answer.yaml", "bank/triage/parameters.yaml"])
        self.assertEqual(rc, 1, out)
        self.assertIn("bank/contract/answer.yaml", out)

    def test_contract_with_broker_or_intake_fails(self):
        for f in ("bank/broker/capabilities.yaml", "bank/intake/rule-map.yaml"):
            rc, out = self.run_change(["bank/contract/answer.yaml", f])
            self.assertEqual(rc, 1, (f, out))

    def test_new_contract_file_with_bank_content_fails(self):
        rc, out = self.run_change(["bank/triage/parameters.yaml"], add=["bank/contract/proof.yaml"])
        self.assertEqual(rc, 1, out)

    def test_bank_content_with_engine_fails(self):
        rc, out = self.run_change(["bank/triage/parameters.yaml", "engine/executor.py"])
        self.assertEqual(rc, 1, out)

    def test_bank_content_alone_passes(self):
        rc, out = self.run_change(["bank/triage/parameters.yaml"], add=["tests/cases/D-0001/new.yaml"])
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
