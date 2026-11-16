#!/usr/bin/env python3
"""Verify a denied processWrapper child terminates only its registered parent."""
import json
import os
import argparse
from pathlib import Path
import shlex
import shutil
import signal
import socket as unix_socket
import struct
import subprocess
import sys
import tempfile
import time


PROJECT = Path(__file__).resolve().parents[2]
AGENT = PROJECT / ".build/debug/safe-claude-agent"
LAUNCHER = PROJECT / ".build/debug/safe-claude"
IDENTITY_SOURCE = PROJECT / "Tests/Fixtures/process_identity_driver.swift"
PROCESS_WRAPPER = PROJECT / "Scripts/integration/process-wrapper"


def wait_for(path, process, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            _, stderr = process.communicate()
            raise RuntimeError(f"process exited early: {process.args}: {stderr!r}")
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for {path.name}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-claude", action="store_true")
    options = parser.parse_args()
    for executable in (AGENT, LAUNCHER):
        if not executable.is_file():
            raise SystemExit(f"build first: missing {executable}")
    claude = shutil.which("claude") if options.real_claude else None
    if options.real_claude and not claude:
        raise SystemExit("Claude Code is not installed")
    with tempfile.TemporaryDirectory(prefix="safe-wrapper-agent-") as temporary:
        root = Path(temporary).resolve()
        libexec = root / "installation/libexec"
        libexec.mkdir(parents=True)
        socket = root / "agent.sock"
        gate = root / "start-child"
        ready = root / "parent-ready"
        result_file = root / "parent-result"
        wrapper_called = root / "wrapper-called"
        wrapper = libexec / "process-wrapper"
        shutil.copy2(PROCESS_WRAPPER, wrapper)
        wrapper.chmod(0o700)

        safe_launcher = libexec / "safe-claude"
        safe_launcher.write_text(
            "#!/bin/sh\nexec "
            + str(LAUNCHER)
            + ' --socket "$SAFECLAUDE_FIXTURE_SOCKET" "$@"\n'
        )
        safe_launcher.chmod(0o700)

        parent_script = root / "parent.py"
        parent_script.write_text(
            """import os, pathlib, signal, subprocess, sys, time
signaled = False
def on_interrupt(_signum, _frame):
    global signaled
    signaled = True
signal.signal(signal.SIGINT, on_interrupt)
ready, gate, result = map(pathlib.Path, sys.argv[1:])
ready.write_text(str(os.getpid()))
while not gate.exists():
    time.sleep(.01)
if os.environ.get('SAFECLAUDE_FAILURE_FIXTURE') == '1':
    import json
    payload = json.dumps({'hook_event_name': 'StopFailure',
                          'session_id': os.environ['SAFECLAUDE_FAILURE_SESSION'],
                          'error': os.environ['SAFECLAUDE_FAILURE_KIND']})
    for _ in range(int(os.environ['SAFECLAUDE_FAILURE_COUNT'])):
        subprocess.run([os.environ['SAFECLAUDE_FIXTURE_LAUNCHER'], '--socket',
                        os.environ['SAFECLAUDE_FIXTURE_SOCKET'], 'hook-event'],
                       input=payload, text=True, capture_output=True, timeout=5)
        if signaled:
            break
    if not signaled:
        raise SystemExit(7)
    result.write_text(json.dumps({
        'signaled': True, 'failure_events': int(os.environ['SAFECLAUDE_FAILURE_COUNT'])
    }))
    raise SystemExit(0)
child = subprocess.run([os.environ['SAFECLAUDE_FIXTURE_WRAPPER'], '/bin/sleep', '30'],
                       capture_output=True, text=True)
result.write_text(json.dumps({'signaled': signaled, 'returncode': child.returncode,
                              'stdout': child.stdout, 'stderr': child.stderr}))
""".replace("import os, pathlib, signal, subprocess, sys, time",
            "import json, os, pathlib, signal, subprocess, sys, time")
        )
        parent_env = os.environ.copy()
        parent_env.update({
            "PATH": "/usr/bin:/bin",
            "HOME": str(root),
            "LANG": "C",
            "SAFECLAUDE_FIXTURE_SOCKET": str(socket),
            "SAFECLAUDE_FIXTURE_WRAPPER": str(wrapper),
            "SAFECLAUDE_FIXTURE_LAUNCHER": str(LAUNCHER),
        })
        if claude:
            work = root / "work"
            config = root / "config"
            work.mkdir()
            config.mkdir()
            state = {
                "hasCompletedOnboarding": True,
                "projects": {str(work): {"hasTrustDialogAccepted": True}},
            }
            for directory in (root, config):
                (directory / ".claude.json").write_text(json.dumps(state))
            gated_wrapper = root / "gated-process-wrapper"
            gated_wrapper.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$$\" > \"$SAFECLAUDE_FIXTURE_WRAPPER_CALLED\"\n"
                "while [ ! -e \"$SAFECLAUDE_FIXTURE_GATE\" ]; do /bin/sleep 0.02; done\n"
                f"{shlex.quote(str(wrapper))} \"$@\"\n"
                "result=$?\n"
                "printf '%s\\n' \"$result\" > \"$SAFECLAUDE_FIXTURE_CHILD_RESULT\"\n"
                "exit \"$result\"\n"
            )
            gated_wrapper.chmod(0o700)
            parent_env.update({
                "CLAUDE_CONFIG_DIR": str(config),
                "ANTHROPIC_BASE_URL": "http://127.0.0.1:1",
                "ANTHROPIC_API_KEY": "fixture-not-a-real-key",
                "DISABLE_TELEMETRY": "1",
                "DISABLE_ERROR_REPORTING": "1",
                "DISABLE_NON_ESSENTIAL_MODEL_CALLS": "1",
                "NO_PROXY": "127.0.0.1,localhost",
                "HTTP_PROXY": "http://127.0.0.1:1",
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "CLAUDE_CODE_PROCESS_WRAPPER": str(gated_wrapper),
                "SAFECLAUDE_FIXTURE_WRAPPER_CALLED": str(wrapper_called),
                "SAFECLAUDE_FIXTURE_GATE": str(gate),
                "SAFECLAUDE_FIXTURE_CHILD_RESULT": str(result_file),
            })
        parent = None
        unrelated = None
        agent = None
        try:
            agent_env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C"}
            agent = subprocess.Popen(
                [str(AGENT), "--socket", str(socket)],
                cwd=root,
                env=agent_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            wait_for(socket, agent)
            deadline = time.monotonic() + 35
            last_status = ""
            while time.monotonic() < deadline:
                status = subprocess.run(
                    [str(LAUNCHER), "--socket", str(socket), "status"],
                    cwd=root,
                    env=agent_env,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                last_status = status.stdout or status.stderr
                if status.returncode == 0 and len(json.loads(status.stdout).get("ruleStatuses") or []) == 64:
                    break
                time.sleep(0.1)
            else:
                raise TimeoutError(f"Agent did not finish initial assessment: {last_status}")

            swiftc = shutil.which("swiftc")
            if not swiftc:
                raise RuntimeError("swiftc is required to read the native process identity")
            identity_binary = root / "process-identity"
            subprocess.run(
                [swiftc, str(IDENTITY_SOURCE), "-o", str(identity_binary)],
                check=True,
                capture_output=True,
                timeout=30,
            )
            if claude:
                parent = subprocess.Popen(
                    [claude, "--model", "fixture", "--background", "fixture"],
                    cwd=root / "work",
                    env=parent_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                wait_for(wrapper_called, parent, timeout=20)
                time.sleep(0.1)
                if parent.poll() is not None:
                    raise RuntimeError("Claude's top-level process exited before wrapper authorization")
            else:
                parent = subprocess.Popen(
                    [sys.executable, str(parent_script), str(ready), str(gate), str(result_file)],
                    cwd=root,
                    env=parent_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                wait_for(ready, parent)
            identity = json.loads(subprocess.check_output(
                [str(identity_binary), str(parent.pid)], text=True, timeout=5
            ))
            request = json.dumps({
                "version": 1,
                "action": "fixture-register-session",
                "sessionPID": identity["pid"],
                "sessionStartSeconds": identity["startSeconds"],
                "sessionStartMicroseconds": identity["startMicroseconds"],
            }).encode()
            with unix_socket.socket(unix_socket.AF_UNIX) as client:
                client.connect(str(socket))
                client.sendall(struct.pack("!I", len(request)) + request)
                header = client.recv(4)
                if len(header) != 4:
                    raise RuntimeError("Agent returned an incomplete fixture registration")
                length = struct.unpack("!I", header)[0]
                chunks = bytearray()
                while len(chunks) < length:
                    chunk = client.recv(length - len(chunks))
                    if not chunk:
                        raise RuntimeError("Agent closed fixture registration early")
                    chunks.extend(chunk)
            registration = json.loads(chunks)
            if registration.get("decision") != "allow":
                raise RuntimeError(f"Agent did not register the fixture process: {registration}")
            unrelated = subprocess.Popen(["/bin/sleep", "30"])
            gate.touch()
            parent.wait(timeout=15 if claude else 8)
            if claude:
                if not result_file.exists() or result_file.read_text().strip() != "75":
                    raise AssertionError({"child_wrapper_return": result_file.read_text()
                                          if result_file.exists() else None})
                if parent.returncode == 0 or identity_binary.exists() and subprocess.run(
                    [str(identity_binary), str(parent.pid)], capture_output=True
                ).returncode == 0:
                    raise AssertionError({"claude_returncode": parent.returncode,
                                          "parent_still_matches": True})
            else:
                if not result_file.exists():
                    raise RuntimeError("registered parent exited without reporting child result")
                result = json.loads(result_file.read_text())
                if parent.returncode != 0 or not result["signaled"] or result["returncode"] != 75:
                    raise AssertionError({"parent_returncode": parent.returncode, "parent_result": result})
            if unrelated.poll() is not None:
                raise AssertionError({"unrelated_process_returncode": unrelated.poll()})

            def verify_failure_threshold(label, error_kind, event_count, rule_id, points):
                failure_ready = root / f"{label}-ready"
                failure_gate = root / f"{label}-gate"
                failure_result = root / f"{label}-result"
                failure_parent = subprocess.Popen(
                    [sys.executable, str(parent_script), str(failure_ready),
                     str(failure_gate), str(failure_result)],
                    cwd=root, env=parent_env | {
                        "SAFECLAUDE_FAILURE_FIXTURE": "1",
                        "SAFECLAUDE_FAILURE_KIND": error_kind,
                        "SAFECLAUDE_FAILURE_COUNT": str(event_count),
                        "SAFECLAUDE_FAILURE_SESSION": f"fixture-session-{label}",
                    },
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    wait_for(failure_ready, failure_parent)
                    failure_identity = json.loads(subprocess.check_output(
                        [str(identity_binary), str(failure_parent.pid)], text=True, timeout=5))
                    request = json.dumps({
                        "version": 1, "action": "fixture-register-session",
                        "sessionPID": failure_identity["pid"],
                        "sessionStartSeconds": failure_identity["startSeconds"],
                        "sessionStartMicroseconds": failure_identity["startMicroseconds"],
                    }).encode()
                    with unix_socket.socket(unix_socket.AF_UNIX) as client:
                        client.connect(str(socket))
                        client.sendall(struct.pack("!I", len(request)) + request)
                        header = client.recv(4)
                        if len(header) != 4:
                            raise RuntimeError("Agent returned incomplete event fixture registration")
                        length = struct.unpack("!I", header)[0]
                        chunks = bytearray()
                        while len(chunks) < length:
                            chunk = client.recv(length - len(chunks))
                            if not chunk:
                                raise RuntimeError("Agent closed event fixture registration early")
                            chunks.extend(chunk)
                    if json.loads(chunks).get("decision") != "allow":
                        raise RuntimeError("Agent did not register failure event fixture")
                    failure_gate.touch()
                    failure_parent.wait(timeout=15)
                    if failure_parent.returncode != 0 or not failure_result.exists():
                        raise AssertionError({
                            "failure_parent_returncode": failure_parent.returncode,
                            "failure_parent_stderr": failure_parent.stderr.read().decode(errors="replace"),
                        })
                    failure_status = json.loads(subprocess.check_output(
                        [str(LAUNCHER), "--socket", str(socket), "status"],
                        env=agent_env, timeout=5))
                    failure_rules = {
                        item["rule"]: item for item in failure_status.get("ruleStatuses", [])
                    }
                    metadata = (root / "claude-failures.json").read_text()
                    if (failure_rules.get(rule_id, {}).get("status") != "triggered" or
                            failure_rules[rule_id].get("points") != points or
                            not any(item["rule"] == rule_id and item["points"] == points
                                    for item in failure_status.get("findings", []))):
                        raise AssertionError({"failure_status": failure_status, "expected": rule_id,
                                              "failure_metadata": metadata,
                                              "failure_result": failure_result.read_text()})
                    if "fixture-session" in metadata or "authentication failed" in metadata:
                        raise AssertionError({"failure_metadata_contains_raw_input": metadata})
                finally:
                    if failure_parent.poll() is None:
                        failure_parent.terminate()
                        failure_parent.wait(timeout=5)

            verify_failure_threshold("authentication", "authentication_failed", 3, "G04", 15)
            reset = json.loads(subprocess.check_output(
                [str(LAUNCHER), "--socket", str(socket), "fixture-reset-session-state"],
                env=agent_env, timeout=5))
            if reset.get("decision") != "allow":
                raise AssertionError({"fixture_state_reset": reset})
            verify_failure_threshold("api-errors", "rate_limit", 11, "G03", 10)
            print(json.dumps({
                "official_process_wrapper": True,
                "safeclaude_exec_child": True,
                "child_denied": True,
                "registered_parent_received_interrupt": True,
                "parent_identity_matched": True,
                "unrelated_process_kept_running": True,
                "authentication_failure_hook_terminates_at_threshold": True,
                "authentication_failure_score_reported_without_raw_payload": True,
                "api_failure_hook_terminates_after_eleven_events": True,
                "real_claude": bool(claude),
            }, sort_keys=True))
        finally:
            if parent is not None and parent.poll() is None:
                parent.send_signal(signal.SIGTERM)
                try:
                    parent.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    parent.kill()
                    parent.wait(timeout=2)
            if unrelated is not None and unrelated.poll() is None:
                unrelated.terminate()
                unrelated.wait(timeout=2)
            if agent is not None and agent.poll() is None:
                agent.terminate()
                try:
                    agent.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    agent.kill()
                    agent.wait(timeout=2)


if __name__ == "__main__":
    main()
