#!/usr/bin/env python3
"""Compare actual Claude Code HTTP routing using only loopback and fake credentials."""
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading


class FakeAPI(http.server.BaseHTTPRequestHandler):
    counts = {}

    def log_message(self, *_):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        port = self.server.server_port
        self.counts[port] = self.counts.get(port, 0) + 1
        body = json.dumps({'id': 'msg_fixture', 'type': 'message', 'role': 'assistant',
                           'content': [{'type': 'text', 'text': 'fixture'}], 'model': 'fixture',
                           'stop_reason': 'end_turn', 'stop_sequence': None,
                           'usage': {'input_tokens': 1, 'output_tokens': 1}}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    claude = shutil.which('claude')
    if not claude:
        raise SystemExit('Claude Code is not installed')
    servers = [http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeAPI) for _ in range(3)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    target, first, second = [server.server_port for server in servers]
    try:
        with tempfile.TemporaryDirectory(prefix='safe-claude-route-') as tmp:
            root = os.path.realpath(tmp)
            work, config = root + '/work', root + '/config'
            os.mkdir(work)
            os.mkdir(config)
            for directory in (root, config):
                with open(directory + '/.claude.json', 'w') as file:
                    json.dump({'hasCompletedOnboarding': True,
                               'projects': {work: {'hasTrustDialogAccepted': True}}}, file)
            env = {'HOME': root, 'PATH': '/usr/bin:/bin', 'CLAUDE_CONFIG_DIR': config,
                   'ANTHROPIC_BASE_URL': f'http://127.0.0.1:{target}',
                   'ANTHROPIC_API_KEY': 'fixture-not-a-real-key',
                   'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
                   'DISABLE_NON_ESSENTIAL_MODEL_CALLS': '1'}
            proxy1, proxy2 = f'http://127.0.0.1:{first}', f'http://127.0.0.1:{second}'
            cases = [
                ('direct', {}, {}, target),
                ('proxy', {'HTTP_PROXY': proxy1}, {}, first),
                ('no_proxy', {'HTTP_PROXY': proxy1, 'NO_PROXY': '127.0.0.1'}, {}, target),
                ('lowercase_first', {'http_proxy': proxy1, 'HTTP_PROXY': proxy2}, {}, first),
                ('settings_lower_env_upper', {'HTTP_PROXY': proxy2}, {'http_proxy': proxy1}, first),
                ('settings_same_key', {'http_proxy': proxy2}, {'http_proxy': proxy1}, first),
            ]
            results = {}
            for name, extra, settings, expected in cases:
                with open(config + '/settings.json', 'w') as file:
                    json.dump({'env': settings}, file)
                FakeAPI.counts.clear()
                result = subprocess.run([claude, '--print', '--model', 'fixture',
                                         '--no-session-persistence', 'fixture'], cwd=work,
                                        env=env | extra, capture_output=True, text=True, timeout=15)
                results[name] = (result.returncode == 0 and result.stdout.strip() == 'fixture'
                                 and FakeAPI.counts.get(expected, 0) > 0
                                 and all(port == expected for port in FakeAPI.counts))
            print(json.dumps(results, sort_keys=True))
            if not all(results.values()):
                raise SystemExit(1)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    main()
