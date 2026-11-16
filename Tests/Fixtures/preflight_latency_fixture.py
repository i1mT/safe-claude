#!/usr/bin/env python3
"""Measure real Agent + launcher preflight latency without Claude credentials."""
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
                    help="number of sequential preflight runs (10–1000; default: 10)")
parser.add_argument("--app", type=Path,
                    help="packaged SafeClaude.app to measure instead of the Debug build")
args = parser.parse_args()
if not 10 <= args.samples <= 1000:
    raise SystemExit("--samples must be between 10 and 1000")

root = Path(__file__).resolve().parents[2]
if args.app:
    app = args.app.resolve()
    executables = app / "Contents/MacOS"
    agent = executables / "safe-claude-agent"
    launcher = executables / "safe-claude"
    try:
        with (app / "Contents/Info.plist").open("rb") as plist_file:
            bundle_build = plistlib.load(plist_file)["CFBundleVersion"]
    except (OSError, KeyError, plistlib.InvalidFileException) as error:
        raise SystemExit(f"invalid SafeClaude app bundle: {error}")
else:
    app = None
    bundle_build = None
    agent = root / '.build/debug/safe-claude-agent'
    launcher = root / '.build/debug/safe-claude'
if (not agent.is_file() or not os.access(agent, os.X_OK) or
        not launcher.is_file() or not os.access(launcher, os.X_OK)):
    raise SystemExit("Agent and launcher executables must exist in the selected build")
claude = shutil.which('claude')
if not claude:
    raise SystemExit('Claude Code is required for this local preflight measurement')
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

with tempfile.TemporaryDirectory(prefix='safe-preflight-latency-') as tmp:
    socket = str(Path(tmp) / 'agent.sock')
    service_env = {'PATH': '/usr/bin:/bin', 'HOME': tmp, 'LANG': 'C'}
    process = subprocess.Popen([str(agent), '--socket', socket], env=service_env,
                               cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    shutdown_escalated = False
    try:
        command = [str(launcher), '--socket', socket, 'exec', '--', claude, '--version']
        env = service_env | {'NODE_TLS_REJECT_UNAUTHORIZED': '0'}
        for _ in range(300):
            if Path(socket).exists():
                try:
                    status = json.loads(subprocess.check_output(
                        [str(launcher), '--socket', socket, 'status'], env=service_env,
                        cwd=tmp, timeout=5))
                    if len(status.get('ruleStatuses', [])) == 64:
                        break
                except (subprocess.SubprocessError, json.JSONDecodeError):
                    pass
            if process.poll() is not None:
                raise RuntimeError('isolated Agent exited before becoming ready')
            time.sleep(.1)
        else:
            raise RuntimeError(f'isolated Agent did not become ready: {status}')

        samples = []
        results = []
        for _ in range(args.samples):
            started = time.perf_counter()
            result = subprocess.run(command, env=env, cwd=tmp,
                                    capture_output=True, timeout=8)
            samples.append((time.perf_counter() - started) * 1000)
            results.append(result.returncode)
            status = json.loads(subprocess.check_output(
                [str(launcher), '--socket', socket, 'status'], env=service_env,
                cwd=tmp, timeout=5))
            states = {item['rule']: item for item in status.get('ruleStatuses', [])}
            if (result.returncode != 75 or status.get('assessmentContext') != 'claude-launch' or
                    states.get('D05', {}).get('status') != 'triggered'):
                raise AssertionError({
                    'return_code': result.returncode,
                    'status_context': status.get('assessmentContext'),
                    'D05': states.get('D05'),
                    'stderr': result.stderr.decode(errors='replace'),
                })
        ordered = sorted(samples)
        p95 = ordered[math.ceil(len(ordered) * .95) - 1]
        print(json.dumps({
            'sample_count': len(samples),
            'build': app.name if app else 'Debug',
            'bundle_build': bundle_build,
            'blocked_count': sum(code == 75 for code in results),
            'unexpected_return_codes': sorted(set(results) - {75}),
            'first_ms': round(samples[0], 1),
            'median_ms': round(statistics.median(samples), 1),
            'p95_ms': round(p95, 1),
            'max_ms': round(max(samples), 1),
            'under_2500ms': sum(sample < 2500 for sample in samples),
            'scope': 'real local Agent + launcher + Claude --version; synthetic TLS-disable signal; no credentials or model request',
        }, sort_keys=True))
        if any(code != 75 for code in results) or p95 >= 2500:
            raise AssertionError('Claude preflight failed closed or exceeded the 2.5 s latency budget')
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            shutdown_escalated = True
            process.kill()
            process.wait(timeout=5)
    if shutdown_escalated:
        raise RuntimeError('isolated Agent required SIGKILL during fixture cleanup')
