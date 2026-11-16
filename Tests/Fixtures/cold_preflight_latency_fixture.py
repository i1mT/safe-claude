#!/usr/bin/env python3
"""Measure fresh Agent startup plus Claude launch preflight latency."""
import argparse
import json
import math
import os
from pathlib import Path
import plistlib
import shutil
import statistics
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--samples", type=int, default=10,
                    help="number of fresh-Agent samples (10–100; default: 10)")
parser.add_argument("--app", type=Path,
                    help="packaged SafeClaude.app to measure instead of the Debug build")
args = parser.parse_args()
if not 10 <= args.samples <= 100:
    raise SystemExit("--samples must be between 10 and 100")

root = Path(__file__).resolve().parents[2]
if args.app:
    app = args.app.resolve()
    executables = app / "Contents/MacOS"
    agent = executables / "safe-claude-agent"
    launcher = executables / "safe-claude"
    try:
        with (app / "Contents/Info.plist").open("rb") as plist_file:
            bundle = plistlib.load(plist_file)
        bundle_build = bundle["CFBundleVersion"]
    except (OSError, KeyError, plistlib.InvalidFileException) as error:
        raise SystemExit(f"invalid SafeClaude app bundle: {error}")
else:
    app = None
    bundle_build = None
    agent = root / ".build/debug/safe-claude-agent"
    launcher = root / ".build/debug/safe-claude"
claude = shutil.which("claude")
if (not agent.is_file() or not os.access(agent, os.X_OK) or
        not launcher.is_file() or not os.access(launcher, os.X_OK)):
    raise SystemExit("Agent and launcher executables must exist in the selected build")
if not claude:
    raise SystemExit("Claude Code is required for this local preflight measurement")
if app:
    debug_actions = (
        "fixture-wake-observer",
        "fixture-dns-downgrade",
        "fixture-reset-session-state",
    )
    for binary in (agent, launcher):
        binary_strings = subprocess.check_output(
            ["/usr/bin/strings", "-a", str(binary)], text=True, errors="replace"
        )
        present = [action for action in debug_actions if action in binary_strings]
        if present:
            raise SystemExit(f"{binary.name} contains Debug fixture actions: {present}")

durations = []
for index in range(args.samples):
    with tempfile.TemporaryDirectory(prefix="safe-cold-preflight-") as tmp:
        directory = Path(tmp)
        socket = directory / "agent.sock"
        environment = {"HOME": tmp, "PATH": "/usr/bin:/bin", "LANG": "C"}
        started = time.perf_counter()
        process = subprocess.Popen(
            [str(agent), "--socket", str(socket)], cwd=tmp, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        shutdown_escalated = False
        try:
            deadline = started + 3.0
            while not socket.exists() and process.poll() is None and time.perf_counter() < deadline:
                time.sleep(0.01)
            if not socket.exists():
                raise RuntimeError("fresh Agent did not create its IPC socket")

            command_env = environment | {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}
            result = subprocess.run(
                [str(launcher), "--socket", str(socket), "exec", "--",
                 claude, "--version"],
                cwd=tmp, env=command_env, capture_output=True, timeout=8,
            )
            elapsed = (time.perf_counter() - started) * 1000
            status = json.loads(subprocess.check_output(
                [str(launcher), "--socket", str(socket), "status"],
                cwd=tmp, env=environment, timeout=2,
            ))
            states = {item["rule"]: item for item in status.get("ruleStatuses", [])}
            if (result.returncode != 75 or
                    status.get("assessmentContext") != "claude-launch" or
                    states.get("D05", {}).get("status") != "triggered"):
                raise AssertionError({
                    "sample": index + 1, "return_code": result.returncode,
                    "D05": states.get("D05"),
                    "stderr": result.stderr.decode(errors="replace"),
                })
            durations.append(elapsed)
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                shutdown_escalated = True
                process.kill()
                process.wait(timeout=5)
            if process.stderr:
                process.stderr.close()
        if shutdown_escalated:
            raise RuntimeError("fresh Agent required SIGKILL during fixture cleanup")

ordered = sorted(durations)
p95 = ordered[math.ceil(len(ordered) * 0.95) - 1]
print(json.dumps({
    "sample_count": len(durations),
    "build": args.app.name if args.app else "Debug",
    "bundle_build": bundle_build,
    "fresh_agent_per_sample": True,
    "first_ms": round(durations[0], 1),
    "median_ms": round(statistics.median(durations), 1),
    "p95_ms": round(p95, 1),
    "max_ms": round(max(durations), 1),
    "under_2500ms": sum(value < 2500 for value in durations),
    "scope": "fresh local Agent + launcher + Claude --version; synthetic TLS-disable signal; no credentials or model request",
}, sort_keys=True))
if p95 >= 2500:
    raise AssertionError("cold Agent preflight exceeded the 2.5 s latency budget")
