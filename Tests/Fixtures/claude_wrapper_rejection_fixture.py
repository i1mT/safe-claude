#!/usr/bin/env python3
"""Measure real Claude behavior when a configured wrapper rejects a spawn."""
import json
import os
import shutil
import subprocess
import tempfile
import time


def main():
    claude = shutil.which('claude')
    if not claude:
        raise SystemExit('Claude Code is not installed')
    with tempfile.TemporaryDirectory(prefix='safe-claude-reject-') as tmp:
        root = os.path.realpath(tmp)
        work, config = root + '/work', root + '/config'
        os.mkdir(work)
        os.mkdir(config)
        for directory in (root, config):
            with open(directory + '/.claude.json', 'w') as file:
                json.dump({'hasCompletedOnboarding': True,
                           'projects': {work: {'hasTrustDialogAccepted': True}}}, file)
        wrapper = root + '/wrapper'
        with open(wrapper, 'w') as file:
            file.write('''#!/bin/sh
pid=$$
while [ "$pid" -gt 1 ]; do
  printf '%s\\n' "$pid" >> "$FIXTURE_MARKER"
  pid=$(/bin/ps -o ppid= -p "$pid" | /usr/bin/tr -d ' ')
  case "$pid" in ''|*[!0-9]*) break;; esac
done
exit 77
''')
        os.chmod(wrapper, 0o700)
        env = {'HOME': root, 'PATH': '/usr/bin:/bin', 'CLAUDE_CONFIG_DIR': config,
               'ANTHROPIC_BASE_URL': 'http://127.0.0.1:1', 'ANTHROPIC_API_KEY': 'fixture-not-a-real-key',
               'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
               'DISABLE_NON_ESSENTIAL_MODEL_CALLS': '1', 'NO_PROXY': '127.0.0.1',
               'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1',
               'CLAUDE_CODE_PROCESS_WRAPPER': wrapper, 'FIXTURE_MARKER': root + '/marker'}
        start = time.monotonic()
        process = subprocess.Popen([claude, '--model', 'fixture', '--background', 'fixture'],
                                   cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            process.communicate(timeout=6)
            result_name = 'rejected' if process.returncode else 'unexpected_success'
        except subprocess.TimeoutExpired:
            result_name = 'timed_out'
            process.kill()
            process.communicate(timeout=5)
        finally:
            try:
                subprocess.run([claude, 'daemon', 'stop'], cwd=work, env=env,
                               capture_output=True, text=True, timeout=5)
            except subprocess.TimeoutExpired:
                pass
        ancestors = set()
        if os.path.exists(root + '/marker'):
            with open(root + '/marker') as file:
                ancestors = set(file.read().splitlines())
        output = {'wrapper_called': bool(ancestors), 'top_level_is_ancestor': str(process.pid) in ancestors,
                  'result': result_name,
                  'elapsed_ms': round((time.monotonic() - start) * 1000)}
        print(json.dumps(output, sort_keys=True))
        if not output['wrapper_called'] or result_name == 'unexpected_success':
            raise SystemExit(1)


if __name__ == '__main__':
    main()
