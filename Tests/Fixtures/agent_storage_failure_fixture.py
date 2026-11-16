#!/usr/bin/env python3
"""Verify corrupt Agent state stays fail-closed in an isolated HOME/socket."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[2]
agent = root / ".build/debug/safe-claude-agent"
cli = root / ".build/debug/safe-claude"


def start_agent(directory: Path, corrupt_file: str):
    socket = directory / "agent.sock"
    state = directory / corrupt_file
    state.write_text("{corrupt", encoding="utf-8")
    state.chmod(0o600)
    environment = {"HOME": str(directory), "PATH": "/usr/bin:/bin", "LANG": "C"}
    process = subprocess.Popen(
        [str(agent), "--socket", str(socket)],
        cwd=directory,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    return process, socket, environment


def status(cli_command, socket):
    return json.loads(subprocess.check_output(
        [str(cli_command), "--socket", str(socket), "status"],
        timeout=5,
    ))


def run_case(corrupt_file: str, marker_name: str):
    with tempfile.TemporaryDirectory(prefix="safeclaude-corrupt-state-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        process, socket, environment = start_agent(directory, corrupt_file)
        marker = directory / marker_name
        try:
            deadline = time.monotonic() + 20
            latest = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Agent exited after {corrupt_file} corruption")
                if socket.exists():
                    latest = status(cli, socket)
                    if corrupt_file == "sessions.json":
                        if "无法读取受管会话记录" in latest.get("reason", ""):
                            break
                    else:
                        rules = {item["rule"]: item for item in latest.get("ruleStatuses", [])}
                        if len(rules) == 64 and rules.get("G02", {}).get("status") == "unknown":
                            break
                time.sleep(0.1)
            else:
                raise AssertionError({"store": corrupt_file, "last_status": latest})

            result = subprocess.run(
                [str(cli), "--socket", str(socket), "exec", "--", "/usr/bin/touch", str(marker)],
                env=environment,
                cwd=directory,
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 75 or marker.exists():
                raise AssertionError({
                    "store": corrupt_file,
                    "exit_code": result.returncode,
                    "marker_created": marker.exists(),
                    "stderr": result.stderr.decode(errors="replace"),
                    "status": latest,
                })
            return latest
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


session_status = run_case("sessions.json", "session-store-must-hold")
rate_status = run_case("launch-rate.json", "rate-store-must-hold")
print(json.dumps({
    "corrupt_session_journal_holds_agent": session_status["decision"] == "hold",
    "corrupt_launch_rate_keeps_G02_unknown": True,
    "both_launches_blocked_before_exec": True,
}, sort_keys=True))
