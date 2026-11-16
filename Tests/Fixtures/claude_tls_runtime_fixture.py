#!/usr/bin/env python3
"""Exercise Claude's TLS and CONNECT path using temporary loopback services."""
import http.server
import json
import os
import shutil
import ssl
import subprocess
import tempfile
from pathlib import Path

import proxy_fixture as fixture


class API(http.server.BaseHTTPRequestHandler):
    requests = 0

    def log_message(self, *_):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        type(self).requests += 1
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
    with tempfile.TemporaryDirectory(prefix='safe-claude-tls-') as tmp:
        root = Path(os.path.realpath(tmp))
        work, config = root / 'work', root / 'config'
        work.mkdir()
        config.mkdir()
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        for directory in (root, config):
            (directory / '.claude.json').write_text(json.dumps({
                'hasCompletedOnboarding': True, 'projects': {str(work): {'hasTrustDialogAccepted': True}}
            }))
        target = http.server.ThreadingHTTPServer(('127.0.0.1', 0), API)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        target.socket = context.wrap_socket(target.socket, server_side=True)
        fixture.HOST = fixture.AUTH_HOST = '127.0.0.1'
        proxies = [fixture.ThreadingServer(('127.0.0.1', 0), fixture.Proxy) for _ in range(2)]
        for proxy in proxies:
            proxy.target_port = target.server_port
            proxy.seen = []
        env = {'HOME': str(root), 'PATH': '/usr/bin:/bin', 'CLAUDE_CONFIG_DIR': str(config),
               'ANTHROPIC_BASE_URL': f'https://127.0.0.1:{target.server_port}',
               'ANTHROPIC_API_KEY': 'fixture-not-a-real-key', 'NODE_EXTRA_CA_CERTS': str(cert),
               'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
               'DISABLE_NON_ESSENTIAL_MODEL_CALLS': '1', 'HTTP_PROXY': 'http://127.0.0.1:1'}
        first, second = [f'http://127.0.0.1:{proxy.server_address[1]}' for proxy in proxies]
        cases = [
            ('connect', {'HTTPS_PROXY': first}, {}, {}, {}, 0),
            ('no_proxy', {'HTTPS_PROXY': first, 'NO_PROXY': '127.0.0.1'}, {}, {}, {}, None),
            ('lowercase_first', {'https_proxy': first, 'HTTPS_PROXY': second}, {}, {}, {}, 0),
            ('settings_same_key', {'https_proxy': second}, {'https_proxy': first}, {}, {}, 0),
            ('project_over_user', {}, {'https_proxy': second}, {'https_proxy': first}, {}, 0),
            ('local_over_project', {}, {}, {'https_proxy': second}, {'https_proxy': first}, 0),
        ]
        with fixture.run_server(target), fixture.run_server(proxies[0]), fixture.run_server(proxies[1]):
            results = {}
            project_config = work / '.claude'
            project_config.mkdir()
            for name, variables, settings, project, local, selected in cases:
                (config / 'settings.json').write_text(json.dumps({'env': settings}))
                (project_config / 'settings.json').write_text(json.dumps({'env': project}))
                (project_config / 'settings.local.json').write_text(json.dumps({'env': local}))
                for proxy in proxies:
                    proxy.seen.clear()
                API.requests = 0
                result = subprocess.run([claude, '--print', '--model', 'fixture',
                                         '--no-session-persistence', 'fixture'], cwd=work,
                                        env=env | variables, capture_output=True, text=True, timeout=15)
                seen = [len(proxy.seen) for proxy in proxies]
                results[name] = (result.returncode == 0 and result.stdout.strip() == 'fixture'
                                 and API.requests > 0 and
                                 (all(count == 0 for count in seen) if selected is None else
                                  seen[selected] > 0 and all(count == 0 for i, count in enumerate(seen) if i != selected)))
            print(json.dumps(results, sort_keys=True))
            if not all(results.values()):
                raise SystemExit(1)


if __name__ == '__main__':
    main()
