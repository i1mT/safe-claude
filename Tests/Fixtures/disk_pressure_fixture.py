#!/usr/bin/env python3
"""Inject real ENOSPC on a disposable macOS disk image and verify Agent holds."""

import errno
import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import tempfile
import time


PROJECT = pathlib.Path(__file__).resolve().parents[2]
AGENT = PROJECT / ".build/debug/safe-claude-agent"


def request(socket_path: pathlib.Path, action: str) -> dict:
    payload = json.dumps({"version": 1, "action": action}).encode()
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(10)
        client.connect(str(socket_path))
        client.sendall(struct.pack("!I", len(payload)) + payload)
        header = client.recv(4)
        if len(header) != 4:
            raise RuntimeError(f"Agent closed the {action} response")
        length = struct.unpack("!I", header)[0]
        data = bytearray()
        while len(data) < length:
            chunk = client.recv(length - len(data))
            if not chunk:
                raise RuntimeError(f"Agent returned a partial {action} response")
            data.extend(chunk)
    return json.loads(data)


def fill_until_enospc(path: pathlib.Path) -> int:
    written_total = 0
    chunk_size = 4096
    with path.open("wb", buffering=0) as stream:
        while chunk_size > 0:
            try:
                written = stream.write(bytes(chunk_size))
                if written is None or written <= 0:
                    raise RuntimeError("disk filler made no progress")
                written_total += written
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
                chunk_size //= 2
    return written_total


with tempfile.TemporaryDirectory(prefix="scdp-", dir="/tmp") as temporary:
    root = pathlib.Path(temporary)
    image = root / "pressure.sparseimage"
    mount = root / "mount"
    mount.mkdir()
    image_device = None
    agent = None
    try:
        created = subprocess.run(
            ["hdiutil", "create", "-size", "64m", "-fs", "HFS+",
             "-volname", "SafeClaudePressure", "-type", "SPARSE", str(image)],
            capture_output=True, text=True, timeout=60,
        )
        if created.returncode:
            raise RuntimeError(f"unable to create isolated pressure image: {created.stderr.strip()}")

        attached = subprocess.run(
            ["hdiutil", "attach", "-nobrowse", "-mountpoint", str(mount), str(image)],
            capture_output=True, text=True, timeout=60,
        )
        if attached.returncode:
            raise RuntimeError(f"unable to mount isolated pressure image: {attached.stderr.strip()}")
        image_device = next(
            (line.split()[0] for line in attached.stdout.splitlines()
             if line.split() and line.split()[0].startswith("/dev/disk")),
            None,
        )
        if image_device is None:
            raise RuntimeError(f"unable to identify pressure image device: {attached.stdout}")

        state_directory = mount / "safeclaude"
        state_directory.mkdir(mode=0o700)
        os.chmod(state_directory, 0o700)
        info = state_directory.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError("temporary HFS+ volume cannot provide a private Agent state directory")

        socket_path = state_directory / "agent.sock"
        environment = {"HOME": str(state_directory), "PATH": "/usr/bin:/bin", "LANG": "C"}
        agent = subprocess.Popen(
            [str(AGENT), "--socket", str(socket_path)],
            cwd=state_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 35
        baseline = None
        while time.monotonic() < deadline:
            if agent.poll() is not None:
                raise RuntimeError(f"Agent exited before the pressure test: {agent.stderr.read()[-2000:]}")
            if socket_path.exists():
                try:
                    baseline = request(socket_path, "status")
                    if len(baseline.get("ruleStatuses") or []) == 64:
                        break
                except (OSError, RuntimeError):
                    pass
            time.sleep(0.1)
        else:
            raise TimeoutError("Agent did not publish the complete baseline assessment")

        bytes_written = fill_until_enospc(mount / "filler.bin")
        launch_write = request(socket_path, "fixture-record-launch-rate")
        session_write = request(socket_path, "fixture-record-session")
        if (launch_write.get("decision") != "hold" or
                launch_write.get("reason") != "无法安全保存启动频率状态，已阻止 Claude 启动。"):
            raise AssertionError({"launch_rate_enospc": launch_write})
        if (session_write.get("decision") != "hold" or
                session_write.get("reason") != "无法安全保存受管会话状态。"):
            raise AssertionError({"session_journal_enospc": session_write})
        if agent.poll() is not None:
            raise AssertionError("Agent exited instead of remaining fail-closed and available")
        print(json.dumps({
            "temporary_volume_enospc": True,
            "filler_bytes_written": bytes_written,
            "launch_rate_write_held": True,
            "session_journal_write_held": True,
            "agent_remained_alive": True,
            "user_volume_modified": False,
        }, sort_keys=True))
    finally:
        if agent is not None and agent.poll() is None:
            agent.send_signal(signal.SIGTERM)
            agent.wait(timeout=5)
        if image_device:
            detached = subprocess.run(
                ["hdiutil", "detach", image_device],
                capture_output=True, text=True, timeout=60,
            )
            if detached.returncode:
                raise RuntimeError(f"unable to detach temporary pressure image: {detached.stderr.strip()}")
