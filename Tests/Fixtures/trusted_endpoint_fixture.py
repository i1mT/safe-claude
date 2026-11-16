#!/usr/bin/env python3
"""Exercise endpoint trust classification through the real launcher and IPC."""
import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = str(ROOT / ".build/debug/safe-claude")
SECRET_URL = "https://private-user:private-pass@evil.example/private/path?token=endpoint-secret#fragment"


def write_policy(home, endpoints):
    policy_dir = Path(home) / "Library/Application Support/SafeClaude"
    policy_dir.mkdir(parents=True, mode=0o700)
    policy = {
        "version": 1,
        "minimumScore": 80,
        "runtimeMinimumScore": 80,
        "trustedEndpoints": endpoints,
    }
    (policy_dir / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    os.chmod(policy_dir / "policy.json", 0o600)


def read_frame(conn):
    header = conn.recv(4)
    assert len(header) == 4
    length = struct.unpack("!I", header)[0]
    payload = bytearray()
    while len(payload) < length:
        chunk = conn.recv(length - len(payload))
        assert chunk
        payload.extend(chunk)
    return bytes(payload)


def run_case(*, trusted, source):
    with tempfile.TemporaryDirectory(prefix="safe-endpoint-") as home:
        write_policy(home, ["https://trusted.example"])
        socket_path = str(Path(home) / "agent.sock")
        target = Path(home) / "executed"
        executable = Path(home) / "fixture-target"
        executable.write_text(f"#!/bin/sh\n/usr/bin/touch '{target}'\n", encoding="utf-8")
        os.chmod(executable, 0o700)
        captured = []
        expected_actions = ["preflight", "validate"] if trusted else ["preflight"]
        expiry = time.time() - 978307200 + 0.95

        def server():
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(socket_path)
            os.chmod(socket_path, 0o600)
            listener.listen(2)
            for index, action in enumerate(expected_actions):
                conn, _ = listener.accept()
                with conn:
                    body = read_frame(conn)
                    captured.append(body)
                    request = json.loads(body)
                    assert request["action"] == action
                    if action == "validate":
                        assert request["ticket"] == "endpoint-fixture-ticket"
                    decision = "allow" if trusted else "hold"
                    response = {
                        "version": 1,
                        "decision": decision,
                        "safetyScore": 95 if trusted else 70,
                        "scoreUpperBound": 95 if trusted else 70,
                        "unknownCount": 0,
                        "reason": "endpoint-fixture",
                        "findings": [],
                        "checkedAt": expiry - 0.95,
                        "expiresAt": expiry,
                    }
                    if action == "preflight" and trusted:
                        response["ticket"] = "endpoint-fixture-ticket"
                    encoded = json.dumps(response).encode()
                    conn.sendall(struct.pack("!I", len(encoded)) + encoded)
            listener.close()

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        for _ in range(200):
            if os.path.exists(socket_path):
                break
            time.sleep(0.005)
        env = os.environ.copy()
        env["CFFIXED_USER_HOME"] = home
        env.pop("ANTHROPIC_BASE_URL", None)
        command = [LAUNCHER, "--socket", socket_path, "exec", "--", str(executable)]
        if source == "inline":
            settings = {"env": {"ANTHROPIC_BASE_URL": (
                "https://trusted.example/" if trusted else SECRET_URL)}}
            command.extend(["--settings", json.dumps(settings)])
        elif source == "environment":
            env["ANTHROPIC_BASE_URL"] = "https://trusted.example/" if trusted else SECRET_URL
        else:
            raise AssertionError(source)
        result = subprocess.run(command, env=env, capture_output=True, timeout=5)
        worker.join(timeout=2)
        assert not worker.is_alive(), (
            f"IPC server timed out for trusted={trusted}, source={source}; "
            f"exit={result.returncode}, stderr={result.stderr!r}, requests={len(captured)}"
        )
        assert all(value not in b"".join(captured) for value in (
            b"private-user", b"private-pass", b"endpoint-secret", b"/private/path"
        ))
        assert b"endpoint-secret" not in result.stdout + result.stderr
        if trusted:
            assert result.returncode == 0, result.stderr
            assert target.exists()
            request = json.loads(captured[0])
            assert request.get("customEndpointPresent") is False
            if source == "inline":
                assert request["commandLineSettings"]["customEndpoint"] is False
        else:
            assert result.returncode == 75, (result.returncode, result.stderr)
            assert not target.exists()
            request = json.loads(captured[0])
            assert request.get("customEndpointPresent") is True
            if source == "inline":
                assert request["commandLineSettings"]["customEndpoint"] is True


for endpoint_source in ("inline", "environment"):
    run_case(trusted=True, source=endpoint_source)
    run_case(trusted=False, source=endpoint_source)

print("trusted endpoint preflight, A09 signal, blocking, and IPC redaction: passed")
