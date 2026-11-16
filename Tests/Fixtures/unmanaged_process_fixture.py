#!/usr/bin/env python3
"""Test detection and termination using isolated copies of local executables."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='safe-claude-unmanaged-') as tmp:
    base = Path(tmp)
    libexec = base / 'libexec'
    libexec.mkdir(mode=0o700)
    agent = libexec / 'safe-claude-agent'
    target = base / 'fixture-claude'
    bystander = base / 'bystander'
    shutil.copy2(root / '.build/debug/safe-claude-agent', agent)
    subprocess.run(['/usr/bin/clang', '-x', 'c', '-o', str(target), '-'],
                   input='#include <unistd.h>\nint main(void) { sleep(30); return 0; }\n',
                   text=True, check=True, capture_output=True, timeout=20)
    shutil.copy2(target, bystander)
    (libexec / 'claude-target').write_text(str(target) + '\n')
    os.chmod(libexec / 'claude-target', 0o600)
    socket = base / 'agent.sock'
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(base), 'LANG': 'C'}
    service = subprocess.Popen([str(agent), '--socket', str(socket)], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    target_process = None
    other_process = None
    try:
        deadline = time.monotonic() + 6
        while not socket.exists() and time.monotonic() < deadline:
            if service.poll() is not None:
                raise RuntimeError('agent exited during startup')
            time.sleep(.05)
        if not socket.exists():
            raise RuntimeError('agent socket did not appear')
        target_process = subprocess.Popen([str(target), '30'], env=env)
        other_process = subprocess.Popen([str(bystander), '30'], env=env)
        deadline = time.monotonic() + 12
        while target_process.poll() is None and time.monotonic() < deadline:
            time.sleep(.1)
        if target_process.poll() not in (-signal.SIGINT, -signal.SIGTERM) or other_process.poll() is not None:
            raise RuntimeError(f'unmanaged target not stopped safely: target={target_process.poll()}, other={other_process.poll()}')
        print(json.dumps({'unmanaged_stopped': True, 'other_executable_untouched': True}))
    finally:
        for process in (target_process, other_process, service):
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
