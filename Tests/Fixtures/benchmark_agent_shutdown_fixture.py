#!/usr/bin/env python3
"""Verify the resource benchmark fails when an Agent requires SIGKILL."""
from pathlib import Path
import subprocess
import sys
import tempfile


PROJECT = Path(__file__).resolve().parents[2]
BENCHMARK = PROJECT / "Scripts/benchmark-agent-runtime.py"


def main():
    with tempfile.TemporaryDirectory(prefix="safe-benchmark-shutdown-fixture-") as temporary:
        root = Path(temporary)
        fake_agent = root / "fake-agent"
        fake_agent.write_text(
            "#!/usr/bin/env python3\n"
            "import os, signal, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "fd = os.open(sys.argv[2], os.O_CREAT | os.O_WRONLY, 0o600)\n"
            "os.close(fd)\n"
            "os.write(2, b'x' * (2 * 1024 * 1024))\n"
            "os.write(2, b'fixture-log-tail')\n"
            "while True:\n"
            "    time.sleep(0.1)\n"
        )
        fake_agent.chmod(0o700)
        result = subprocess.run(
            [
                sys.executable,
                str(BENCHMARK),
                "--agent",
                str(fake_agent),
                "--duration",
                "30",
                "--interval",
                "2",
            ],
            cwd=root,
            env={"HOME": str(root), "PATH": "/usr/bin:/bin", "LANG": "C"},
            capture_output=True,
            text=True,
            timeout=55,
        )
        if result.returncode == 0:
            raise AssertionError("benchmark passed although SIGKILL was required")
        if "SIGKILL was required" not in result.stderr:
            raise AssertionError(f"missing shutdown failure: {result.stderr[-2000:]}")
        if "fixture-log-tail" not in result.stderr:
            raise AssertionError("Agent stderr tail was not captured from the isolated log file")
        print(
            '{"benchmark_failed_on_SIGKILL":true,'
            '"large_stderr_did_not_block":true,'
            '"stderr_tail_captured":true}'
        )


if __name__ == "__main__":
    main()
