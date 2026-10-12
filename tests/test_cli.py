import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from ghost_mode.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GH = "ghp_" + "A1b2C3d4" * 5


class _Out(io.TextIOWrapper):
    """Text stream whose .buffer is a BytesIO, like sys.stdout."""

    def __init__(self):
        super().__init__(io.BytesIO(), encoding="utf-8", write_through=True)

    def value(self):
        return self.buffer.getvalue().decode("utf-8")


def ghost(*args, stdin="", env=None):
    """Run the CLI in-process; return (exit code, stdout, stderr)."""
    out, err = _Out(), _Out()
    fake_in = io.TextIOWrapper(io.BytesIO(stdin.encode()), encoding="utf-8")
    with mock.patch.object(sys, "stdin", fake_in), redirect_stdout(out), redirect_stderr(err), \
            mock.patch.dict(os.environ, env or {}):
        code = main(list(args))
    return code, out.value(), err.value()


class CliTests(unittest.TestCase):
    def test_module_entry_point(self):
        r = subprocess.run([sys.executable, "-m", "ghost_mode", "scrub"], input=f"{GH}\n",
                           capture_output=True, text=True, timeout=60,
                           env={**os.environ, "PYTHONPATH": ROOT})
        self.assertEqual(r.stdout, "[REDACTED:github-token]\n")

    def test_scrub_stdin(self):
        code, out, _ = ghost("scrub", stdin=f"token {GH}\n")
        self.assertEqual((code, out), (0, "token [REDACTED:github-token]\n"))

    def test_scrub_file_and_report(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(f"{GH}\n")
        try:
            _, out, err = ghost("scrub", "--report", fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(out, "[REDACTED:github-token]\n")
        self.assertIn("1 secret", err)
        self.assertNotIn(GH, err)

    def test_dash_means_stdin_anywhere(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("plain\n")
        try:
            _, out, _ = ghost("scrub", fh.name, "-", stdin=f"{GH}\n")
        finally:
            os.unlink(fh.name)
        self.assertEqual(out, "plain\n[REDACTED:github-token]\n")

    def test_scan_exit_codes_and_no_leak(self):
        code, out, err = ghost("scan", stdin=f"a\n{GH}\n")
        self.assertEqual(code, 1)
        self.assertEqual(out.strip(), "<stdin>:2: github-token")
        self.assertNotIn(GH, out + err)
        code, out, _ = ghost("scan", stdin="nothing here\n")
        self.assertEqual((code, out), (0, ""))

    def test_unreadable_input_fails_closed(self):
        for cmd in ("scan", "scrub"):
            code, _, err = ghost(cmd, "/nonexistent/definitely-not-here")
            self.assertEqual(code, 2, cmd)
            self.assertIn("ghost:", err)

    def test_run_scrubs_and_propagates_exit_code(self):
        code_str = f"import sys; print('{GH}'); print('err', file=sys.stderr); sys.exit(3)"
        code, out, _ = ghost("run", "--", sys.executable, "-c", code_str)
        self.assertEqual(code, 3)
        self.assertIn("[REDACTED:github-token]", out)
        self.assertIn("err", out)  # stderr is merged
        self.assertNotIn(GH, out)

    def test_run_scrubs_env_secret_values(self):
        _, out, _ = ghost(
            "run", "--", sys.executable, "-c", "import os; print(os.environ['MY_API_TOKEN'])",
            env={"MY_API_TOKEN": "plain-looking-value-991"},
        )
        self.assertEqual(out.strip(), "[REDACTED:env:MY_API_TOKEN]")

    def test_run_keeps_inner_double_dashes(self):
        code_str = "import sys; print(sys.argv[1:])"
        _, out, _ = ghost("run", "--", sys.executable, "-c", code_str, "--", "x")
        self.assertEqual(out.strip(), "['--', 'x']")

    def test_run_pty(self):
        code, out, _ = ghost("run", "--pty", "--", sys.executable, "-c", f"print('{GH}')")
        self.assertEqual(code, 0)
        self.assertIn("[REDACTED:github-token]", out)
        self.assertNotIn(GH, out)

    def test_run_missing_command(self):
        code, _, _ = ghost("run", "--", "definitely-not-a-real-command-xyz")
        self.assertEqual(code, 127)

    def test_rules_lists_names(self):
        _, out, _ = ghost("rules")
        self.assertIn("github-token", out)
        self.assertIn("private-key", out)


if __name__ == "__main__":
    unittest.main()
