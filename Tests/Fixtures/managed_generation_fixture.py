#!/usr/bin/env python3
"""Exercise F04 through the real Agent managed-session monitor."""
import json
import os
import argparse
from pathlib import Path
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


PROJECT = Path(__file__).resolve().parents[2]
AGENT = PROJECT / ".build/debug/safe-claude-agent"
LAUNCHER = PROJECT / ".build/debug/safe-claude"
IDENTITY_SOURCE = PROJECT / "Tests/Fixtures/process_identity_driver.swift"
PROCESS_WRAPPER = PROJECT / "Scripts/integration/process-wrapper"

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--real-claude", action="store_true",
                    help="exercise F04 against an installed Claude Code without a model request")
parser.add_argument("--network-change", action="store_true",
                    help="advance the Debug Agent network epoch instead of changing policy")
parser.add_argument("--wake-notification", action="store_true",
                    help="post a Debug Agent macOS wake notification instead of changing policy")
options = parser.parse_args()
if options.network_change and options.wake_notification:
    parser.error("--network-change and --wake-notification are mutually exclusive")
claude = shutil.which("claude") if options.real_claude else None
if options.real_claude and not claude:
    raise SystemExit("Claude Code is not installed")


def send_request(path, payload, result):
    try:
        encoded = json.dumps(payload).encode()
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(30)
            client.connect(str(path))
            client.sendall(struct.pack("!I", len(encoded)) + encoded)
            header = client.recv(4)
            if len(header) != 4:
                raise RuntimeError("Agent closed the F04 monitor request")
            length = struct.unpack("!I", header)[0]
            chunks = bytearray()
            while len(chunks) < length:
                part = client.recv(length - len(chunks))
                if not part:
                    raise RuntimeError("Agent returned an incomplete F04 response")
                chunks.extend(part)
        result["response"] = json.loads(chunks)
    except BaseException as error:
        result["error"] = error


with tempfile.TemporaryDirectory(prefix="safe-managed-generation-") as temporary:
    root = Path(temporary).resolve()
    socket_path = root / "agent.sock"
    policy_path = root / "policy.json"
    policy = {"version": 1, "minimumScore": 80,
              "runtimeMinimumScore": 81 if options.network_change or options.wake_notification else 80}
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    policy_path.chmod(0o600)

    claude_settings = root / ".claude" / "settings.json"
    claude_settings.parent.mkdir()
    claude_settings.write_text("{}", encoding="utf-8")
    ready_path = root / "managed-process-ready"
    signal_path = root / "managed-process-interrupted"
    wrapper_called = root / "gated-wrapper-called"
    cancel_wrapper = root / "cancel-gated-wrapper"
    parent_script = root / "managed_process.py"
    parent_script.write_text(
        """import pathlib, signal, sys, time
ready, interrupted = map(pathlib.Path, sys.argv[1:])
def stop(_signum, _frame):
    interrupted.write_text("SIGINT")
    raise SystemExit(0)
signal.signal(signal.SIGINT, stop)
ready.write_text("ready")
while True:
    time.sleep(.05)
""",
        encoding="utf-8",
    )

    env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C"}
    if claude:
        work = root / "work"
        config = root / "config"
        work.mkdir()
        config.mkdir()
        onboarding = {
            "hasCompletedOnboarding": True,
            "projects": {str(work): {"hasTrustDialogAccepted": True}},
        }
        for directory in (root, config):
            (directory / ".claude.json").write_text(json.dumps(onboarding), encoding="utf-8")
        libexec = root / "libexec"
        libexec.mkdir()
        shutil.copy2(PROCESS_WRAPPER, libexec / "process-wrapper")
        (libexec / "process-wrapper").chmod(0o700)
        shutil.copy2(LAUNCHER, libexec / "safe-claude")
        (libexec / "safe-claude").chmod(0o700)
        gated_wrapper = root / "gated-process-wrapper"
        gated_wrapper.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$$\" > {shlex.quote(str(wrapper_called))}\n"
            f"while [ ! -e {shlex.quote(str(cancel_wrapper))} ]; do /bin/sleep 0.02; done\n"
            "exit 130\n",
            encoding="utf-8",
        )
        gated_wrapper.chmod(0o700)
        env.update({
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
        })
    agent = subprocess.Popen(
        [str(AGENT), "--socket", str(socket_path)],
        cwd=root,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    process = None
    unrelated = None
    try:
        deadline = time.monotonic() + 10
        while not socket_path.exists() and time.monotonic() < deadline:
            if agent.poll() is not None:
                raise RuntimeError(f"Agent exited: {agent.stderr.read().decode(errors='replace')}")
            time.sleep(.02)
        if not socket_path.exists():
            raise TimeoutError("Agent socket did not appear")

        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            status = subprocess.run(
                [str(LAUNCHER), "--socket", str(socket_path), "status"],
                env=env, cwd=root, capture_output=True, text=True, timeout=5,
            )
            if status.returncode == 0 and len(json.loads(status.stdout).get("ruleStatuses") or []) == 64:
                break
            time.sleep(.1)
        else:
            raise TimeoutError("Agent did not complete its initial assessment")
        time.sleep(2)

        identity_binary = root / "process-identity"
        subprocess.run(
            ["/usr/bin/swiftc", str(IDENTITY_SOURCE), "-o", str(identity_binary)],
            check=True, capture_output=True, timeout=30,
        )
        if claude:
            process = subprocess.Popen(
                [claude, "--model", "fixture", "--background", "fixture"],
                cwd=root / "work", env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            deadline = time.monotonic() + 20
            while not wrapper_called.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Claude exited before its gated process wrapper was reached")
                time.sleep(.02)
            if not wrapper_called.exists():
                raise TimeoutError("Claude did not reach its gated process wrapper")
        else:
            process = subprocess.Popen(
                [sys.executable, str(parent_script), str(ready_path), str(signal_path)],
                cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            deadline = time.monotonic() + 5
            while not ready_path.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Managed process exited before registration")
                time.sleep(.02)
            if not ready_path.exists():
                raise TimeoutError("Managed process did not become ready")
        identity = json.loads(subprocess.check_output(
            [str(identity_binary), str(process.pid)], text=True, timeout=5,
        ))

        response_holder = {}
        request = {
            "version": 1,
            "action": "fixture-monitor-generation",
            "environment": {key: env[key] for key in ("HOME", "LANG", "CLAUDE_CONFIG_DIR")
                            if key in env},
            "executable": identity["executable"],
            "workingDirectory": str(root),
            "sessionPID": identity["pid"],
            "sessionStartSeconds": identity["startSeconds"],
            "sessionStartMicroseconds": identity["startMicroseconds"],
        }
        request_thread = threading.Thread(
            target=send_request, args=(socket_path, request, response_holder), daemon=True,
        )
        request_thread.start()

        deadline = time.monotonic() + 12
        latest_status = None
        while time.monotonic() < deadline:
            if "error" in response_holder:
                raise response_holder["error"]
            status = subprocess.run(
                [str(LAUNCHER), "--socket", str(socket_path), "status"],
                env=env, cwd=root, capture_output=True, text=True, timeout=5,
            )
            if status.returncode == 0:
                response = json.loads(status.stdout)
                latest_status = response
                f04 = next((item for item in response.get("ruleStatuses", [])
                            if item.get("rule") == "F04"), None)
                if (response.get("assessmentContext") == "managed-session" and f04 and
                        f04.get("status") == "passed"):
                    break
            if process.poll() is not None:
                request_thread.join(timeout=8)
                raise RuntimeError(
                    f"Managed process ended before the generation changed: {response_holder}; "
                    f"signal={signal_path.read_text() if signal_path.exists() else None}"
                )
            time.sleep(.05)
        else:
            raise TimeoutError(f"Monitor did not publish baseline assessment: {latest_status}")

        unrelated = subprocess.Popen(["/bin/sleep", "30"])
        if options.network_change:
            epoch_response = {}
            send_request(socket_path, {
                "version": 1, "action": "fixture-advance-network-epoch",
            }, epoch_response)
            if "error" in epoch_response or epoch_response.get("response", {}).get("decision") != "allow":
                raise AssertionError({"network_epoch_fixture": epoch_response})
        elif options.wake_notification:
            wake_response = {}
            send_request(socket_path, {
                "version": 1, "action": "fixture-post-wake",
            }, wake_response)
            if "error" in wake_response:
                agent_exit = agent.poll()
                agent_stderr = agent.stderr.read().decode(errors="replace") if agent_exit is not None else None
                raise AssertionError({"wake_notification_fixture": wake_response,
                                     "agent_exit": agent_exit, "agent_stderr": agent_stderr})
            if wake_response.get("response", {}).get("decision") != "allow":
                raise AssertionError({"wake_notification_fixture": wake_response})
        else:
            policy["runtimeMinimumScore"] = 81
            temporary_policy = root / "policy.next"
            temporary_policy.write_text(json.dumps(policy), encoding="utf-8")
            temporary_policy.chmod(0o600)
            os.replace(temporary_policy, policy_path)

        finish_deadline = time.monotonic() + 25
        while request_thread.is_alive() and time.monotonic() < finish_deadline:
            process.poll()  # Reap after SIGINT so the Agent can verify process exit.
            request_thread.join(timeout=.05)
        if request_thread.is_alive():
            raise TimeoutError("Agent did not finish F04 policy-generation monitoring")
        if "error" in response_holder:
            raise response_holder["error"]
        result = response_holder.get("response", {})
        if result.get("decision") != "allow" or "F04" not in result.get("reason", ""):
            raise AssertionError({"fixture_response": result})
        process.wait(timeout=5)
        if claude:
            if process.returncode == 0:
                raise AssertionError({"real_claude_returncode": process.returncode})
            if not wrapper_called.exists():
                raise AssertionError("real Claude did not enter its process wrapper")
            cancel_wrapper.touch()
        elif process.returncode != 0 or not signal_path.exists() or signal_path.read_text() != "SIGINT":
            raise AssertionError({
                "managed_process_returncode": process.returncode,
                "interrupt_marker": signal_path.read_text() if signal_path.exists() else None,
            })
        if unrelated.poll() is not None:
            raise AssertionError({"unrelated_process_returncode": unrelated.poll()})
        print(json.dumps({
            "baseline_f04_passed": True,
            "runtime_policy_changed": not options.network_change and not options.wake_notification,
            "network_epoch_changed": options.network_change or options.wake_notification,
            "wake_notification_posted": options.wake_notification,
            "f04_generation_triggered": True,
            "managed_process_interrupted": True,
            "unrelated_process_kept_running": True,
            "real_claude": claude is not None,
            "model_request_sent": False,
        }, sort_keys=True))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        if claude and wrapper_called.exists():
            cancel_wrapper.touch()
            try:
                wrapper_pid = int(wrapper_called.read_text().strip())
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    alive = subprocess.run(["/bin/kill", "-0", str(wrapper_pid)],
                                           capture_output=True, timeout=1).returncode == 0
                    if not alive:
                        break
                    time.sleep(.02)
                else:
                    command = subprocess.run(
                        ["/bin/ps", "-p", str(wrapper_pid), "-o", "command="],
                        capture_output=True, text=True, timeout=2,
                    ).stdout
                    if str(root / "gated-process-wrapper") in command:
                        os.kill(wrapper_pid, 15)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
        if unrelated is not None and unrelated.poll() is None:
            unrelated.terminate()
            unrelated.wait(timeout=5)
        if agent.poll() is None:
            agent.terminate()
            try:
                agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                agent.kill()
                agent.wait(timeout=5)
