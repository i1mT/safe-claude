#!/usr/bin/env python3
"""Exercise geolocation transport through real curl, CONNECT, and bypass."""
import http.server
import json
import os
import shlex
import ssl
import subprocess
import tempfile
from pathlib import Path

import proxy_fixture as fixture

ROOT = Path(__file__).resolve().parents[2]


class Target(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.paths.append(self.path)
        body = b'{"success":true,"ip":"192.0.2.42","country_code":"US"}'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    with tempfile.TemporaryDirectory(prefix='safe-claude-geo-') as tmp:
        tmp = Path(tmp)
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(tmp), 'LANG': 'C'}
        cert, key = tmp / 'cert.pem', tmp / 'key.pem'
        fixture.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                     '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=ipwho.is',
                     '-addext', 'subjectAltName=DNS:ipwho.is'], env=env,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        fixture.run(['/usr/bin/swift', 'build', '--target', 'GuardCore'], cwd=ROOT, env=env,
                    capture_output=True, text=True)
        bin_path = Path(fixture.run(
            ['/usr/bin/swift', 'build', '--show-bin-path'], cwd=ROOT, env=env,
            capture_output=True, text=True).stdout.strip())
        resource_accessor = bin_path / 'GuardCore.build/DerivedSources/resource_bundle_accessor.swift'
        if not resource_accessor.is_file():
            raise RuntimeError(f'SwiftPM resource accessor missing: {resource_accessor}')
        driver = tmp / 'driver'
        sources = sorted(str(path) for path in (ROOT / 'Sources/GuardCore').glob('*.swift'))
        fixture.run(['/usr/bin/xcrun', 'swiftc', *sources, str(resource_accessor),
                     str(ROOT / 'Tests/Fixtures/geo_proxy_driver.swift'), '-o', str(driver)],
                    env=env, capture_output=True, text=True)
        target = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target)
        target.paths = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        target.socket = context.wrap_socket(target.socket, server_side=True)
        fixture.HOST = fixture.AUTH_HOST = '127.0.0.1'
        proxy = fixture.ThreadingServer(('127.0.0.1', 0), fixture.Proxy)
        proxy.target_port = target.server_port
        proxy.seen = []
        wrapper = tmp / 'curl-wrapper'
        wrapper.write_text('#!/bin/sh\nset -eu\n[ "$1" = "-q" ] || exit 91\n'
                           'first="$1"; shift\nexec /usr/bin/curl "$first" --cacert '
                           + shlex.quote(str(cert)) + ' --connect-to '
                           + shlex.quote(f'ipwho.is:443:127.0.0.1:{target.server_port}') + ' "$@"\n')
        wrapper.chmod(0o700)
        proxy_url = f'http://fixture-user:fixture-secret@127.0.0.1:{proxy.server_address[1]}'
        with fixture.run_server(target), fixture.run_server(proxy):
            for bypass in ('', 'ipwho.is'):
                result = fixture.run([str(driver)], env=env, text=True, capture_output=True,
                                     input=json.dumps({'proxy': proxy_url, 'no_proxy': bypass,
                                                       'curl_wrapper': str(wrapper)}))
                assert result.stdout.strip() == 'ok'
                assert 'fixture-secret' not in result.stderr + result.stdout
            assert len(proxy.seen) == 1, proxy.seen
            assert target.paths == ['/192.0.2.42', '/192.0.2.42'], target.paths
        print(json.dumps({'geo_proxy': True, 'geo_no_proxy': True,
                          'tls_verified': True, 'credentials_redacted': True}))


if __name__ == '__main__':
    main()
