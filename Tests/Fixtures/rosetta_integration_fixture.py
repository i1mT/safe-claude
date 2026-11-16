#!/usr/bin/env python3
"""Verify universal x86_64 Agent/CLI IPC using Rosetta or native Intel."""

import argparse
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--app", required=True, type=pathlib.Path,
                    help="universal SafeClaude.app bundle to exercise")
args = parser.parse_args()

executables = args.app.resolve() / "Contents" / "MacOS"
agent_binary = executables / "safe-claude-agent"
cli_binary = executables / "safe-claude"
for binary in (agent_binary, cli_binary):
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit(f"missing executable in app bundle: {binary}")

for binary in (agent_binary, cli_binary):
    arch = subprocess.run(["/usr/bin/lipo", str(binary), "-verify_arch", "x86_64"],
                          capture_output=True, text=True)
    if arch.returncode != 0:
        raise SystemExit(f"App bundle is missing an x86_64 slice: {arch.stderr.strip()}")

with tempfile.TemporaryDirectory(prefix="safeclaude-x86-ipc-") as temporary:
    root = pathlib.Path(temporary)
    home = root / "home"
    home.mkdir(mode=0o700)
    socket = root / "agent.sock"
    environment = {"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "C"}
    agent = subprocess.Popen(
        ["/usr/bin/arch", "-x86_64", str(agent_binary), "--socket", str(socket)],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    response = None
    last_error = None
    try:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if agent.poll() is not None:
                raise RuntimeError(f"x86_64 Agent exited: {agent.stderr.read()[-2000:]}")
            if socket.exists():
                result = subprocess.run(
                    ["/usr/bin/arch", "-x86_64", str(cli_binary),
                     "--socket", str(socket), "status"],
                    cwd=root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=6,
                )
                if result.returncode == 0:
                    try:
                        candidate = json.loads(result.stdout)
                    except json.JSONDecodeError as error:
                        last_error = f"invalid status JSON: {error}"
                    else:
                        if len(candidate.get("ruleStatuses") or []) == 64:
                            response = candidate
                            break
                        last_error = f"expected 64 rule statuses, received {len(candidate.get('ruleStatuses') or [])}"
                else:
                    last_error = f"CLI exit {result.returncode}: {result.stderr[-1000:]}"
            time.sleep(0.1)
        if response is None:
            raise TimeoutError(last_error or "x86_64 CLI did not receive a complete Agent status")
    finally:
        if agent.poll() is None:
            agent.send_signal(signal.SIGTERM)
            agent.wait(timeout=5)

print(json.dumps({
    "x86_64_agent_started": True,
    "x86_64_cli_connected": True,
    "complete_rule_statuses": 64,
    "decision": response.get("decision"),
    "isolated_home_and_socket": True,
}, sort_keys=True))
