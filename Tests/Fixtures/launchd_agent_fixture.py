#!/usr/bin/env python3
"""Exercise an isolated, uniquely named per-user launchd service."""
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
import time
import uuid

root = Path(__file__).resolve().parents[2]
agent = root / '.build/debug/safe-claude-agent'
cli = root / '.build/debug/safe-claude'
domain = f'gui/{os.getuid()}'
label = 'local.safeclaude.fixture.' + uuid.uuid4().hex
service = f'{domain}/{label}'

with tempfile.TemporaryDirectory(prefix='safe-claude-launchd-') as tmp:
    home = Path(tmp) / 'home'
    home.mkdir(mode=0o700)
    socket = Path(tmp) / 'agent.sock'
    plist = Path(tmp) / 'agent.plist'
    with plist.open('wb') as stream:
        plistlib.dump({'Label': label, 'ProgramArguments': [str(agent), '--socket', str(socket)],
                       'EnvironmentVariables': {
                           'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LANG': 'C',
                       },
                       'RunAtLoad': True, 'KeepAlive': True, 'ProcessType': 'Background'}, stream)

    def pid():
        result = subprocess.run(['/bin/launchctl', 'print', service], capture_output=True, text=True, timeout=3)
        match = re.search(r'^\s*pid = (\d+)\s*$', result.stdout, re.MULTILINE)
        return int(match.group(1)) if match else None

    def wait_ready(previous=None):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            current = pid()
            if current and current != previous:
                result = subprocess.run([str(cli), '--socket', str(socket), 'status'],
                                        capture_output=True, timeout=3)
                if result.returncode == 0 and json.loads(result.stdout).get('version') == 1:
                    return current
            time.sleep(.1)
        raise RuntimeError('launchd agent did not become ready')

    def service_is_loaded():
        result = subprocess.run(['/bin/launchctl', 'print', service],
                                capture_output=True, text=True, timeout=3)
        return result.returncode == 0

    bootstrap_attempted = False
    try:
        bootstrap_attempted = True
        subprocess.run(['/bin/launchctl', 'bootstrap', domain, str(plist)], check=True, timeout=5)
        first = wait_ready()
        subprocess.run(['/bin/launchctl', 'kill', 'SIGKILL', service], check=True, timeout=5)
        second = wait_ready(previous=first)
        print(json.dumps({'isolated_launchd_started': True, 'crash_restarted': first != second}))
    finally:
        if bootstrap_attempted:
            subprocess.run(['/bin/launchctl', 'bootout', service],
                           capture_output=True, timeout=5)
            deadline = time.monotonic() + 5
            while service_is_loaded() and time.monotonic() < deadline:
                time.sleep(.1)
            if service_is_loaded():
                raise RuntimeError('temporary launchd service remained loaded after bootout')
