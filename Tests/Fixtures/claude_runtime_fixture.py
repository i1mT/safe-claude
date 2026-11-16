#!/usr/bin/env python3
"""Exercise installed Claude against a synthetic loopback API, without user config."""
import http.server
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import threading
import time


def fixture_processes_using(root):
    result = subprocess.run(['ps', '-axo', 'pid=,command='],
                            capture_output=True, text=True, check=True)
    processes = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and root in fields[1]:
            try:
                processes.append(int(fields[0]))
            except ValueError:
                pass
    return processes


def wait_for_fixture_processes(root, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        processes = fixture_processes_using(root)
        if not processes:
            return []
        time.sleep(0.05)
    return fixture_processes_using(root)


def terminate_fixture_processes(root):
    processes = fixture_processes_using(root)
    for pid in processes:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    remaining = wait_for_fixture_processes(root, 2)
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return wait_for_fixture_processes(root, 2)


class API(http.server.BaseHTTPRequestHandler):
    requests = 0

    def log_message(self, *_):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        type(self).requests += 1
        response = json.dumps({
            'id': 'msg_fixture', 'type': 'message', 'role': 'assistant',
            'content': [{'type': 'text', 'text': 'fixture'}], 'model': 'fixture',
            'stop_reason': 'end_turn', 'stop_sequence': None,
            'usage': {'input_tokens': 1, 'output_tokens': 1},
        }).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def main():
    executable = shutil.which('claude')
    if not executable:
        raise SystemExit('Claude Code is not installed')
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), API)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='safe-claude-runtime-') as tmp:
            root = os.path.realpath(tmp)
            work, config = os.path.join(root, 'work'), os.path.join(root, 'config')
            os.mkdir(work)
            os.mkdir(config)
            state = {'hasCompletedOnboarding': True,
                     'projects': {work: {'hasTrustDialogAccepted': True}}}
            for directory in (root, config):
                with open(os.path.join(directory, '.claude.json'), 'w') as file:
                    json.dump(state, file)
            marker = os.path.join(root, 'called')
            wrapper = os.path.join(root, 'wrapper')
            with open(wrapper, 'w') as file:
                file.write('#!/bin/sh\nprintf called >> "$FIXTURE_MARKER"\nexec "$@"\n')
            os.chmod(wrapper, 0o700)
            env = {
                'HOME': root, 'PATH': '/usr/bin:/bin', 'CLAUDE_CONFIG_DIR': config,
                'ANTHROPIC_BASE_URL': f'http://127.0.0.1:{server.server_port}',
                'ANTHROPIC_API_KEY': 'fixture-not-a-real-key',
                'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
                'DISABLE_NON_ESSENTIAL_MODEL_CALLS': '1',
                # External traffic, if attempted, is confined to an unavailable loopback proxy.
                'NO_PROXY': '127.0.0.1,localhost', 'HTTP_PROXY': 'http://127.0.0.1:1',
                'HTTPS_PROXY': 'http://127.0.0.1:1',
                'CLAUDE_CODE_PROCESS_WRAPPER': wrapper, 'FIXTURE_MARKER': marker,
            }
            def run(args, timeout=20):
                return subprocess.run([executable, *args], cwd=work, env=env,
                                      capture_output=True, text=True, timeout=timeout)
            foreground = run(['--print', '--model', 'fixture', '--no-session-persistence', 'fixture'])
            if foreground.returncode != 0 or foreground.stdout.strip() != 'fixture' or API.requests == 0:
                raise RuntimeError('synthetic API request failed')
            session = None
            try:
                background = run(['--model', 'fixture', '--background', 'fixture'])
                match = re.search(r'backgrounded\s+·\s+([a-zA-Z0-9-]+)', background.stdout)
                session = match.group(1) if match else None
                deadline = time.monotonic() + 3
                while not os.path.exists(marker) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if background.returncode != 0 or not session or not os.path.exists(marker):
                    raise RuntimeError('background process did not invoke wrapper')
                print(json.dumps({'synthetic_api': True, 'background_wrapper_called': True,
                                  'isolated_configuration': True}, sort_keys=True))
            finally:
                stop_result = None
                daemon_result = None
                if session:
                    stop_result = run(['stop', session], timeout=10)
                daemon_result = run(['daemon', 'stop', '--any'], timeout=10)
                remaining = wait_for_fixture_processes(root, 5)
                if remaining:
                    print(json.dumps({
                        'stop_exit': stop_result.returncode if stop_result else None,
                        'stop_stderr': stop_result.stderr.strip() if stop_result else None,
                        'daemon_exit': daemon_result.returncode if daemon_result else None,
                        'daemon_stderr': daemon_result.stderr.strip() if daemon_result else None,
                        'remaining_fixture_pids': remaining,
                    }, sort_keys=True))
                    forced = terminate_fixture_processes(root)
                    if forced:
                        raise RuntimeError(
                            f'Claude background processes did not stop cleanly: {forced}'
                        )
                    raise RuntimeError(
                        'Claude background process outlived stop/daemon stop; '
                        'terminated isolated fixture process before cleanup'
                    )
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
