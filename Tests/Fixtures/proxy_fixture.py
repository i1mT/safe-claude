#!/usr/bin/env python3
"""Exercise actual Swift TraceProbe and curl over loopback TLS and CONNECT only."""

import contextlib
import http.server
import json
import os
import select
import shlex
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

HOST = "api.fixture.invalid"
AUTH_HOST = "auth.fixture.invalid"
ROOT = Path(__file__).resolve().parents[2]


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append((self.headers.get("Host"), self.path))
        payload = b"ip=192.0.2.42\nloc=US\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        parts = self.rfile.readline(8192).decode("ascii").strip().split(" ")
        while self.rfile.readline(8192) not in (b"\r\n", b"\n", b""):
            pass  # Never retain or log authorization headers.
        if len(parts) != 3 or parts[0] != "CONNECT":
            self.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        host, port = parts[1].rsplit(":", 1)
        if host not in (HOST, AUTH_HOST) or int(port) != self.server.target_port:
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        self.server.seen.append((host, int(port)))
        with socket.create_connection(("127.0.0.1", int(port)), timeout=3) as upstream:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            sockets = [self.connection, upstream]
            while True:
                readable, _, _ = select.select(sockets, [], [], 3)
                if not readable:
                    return
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    (upstream if source is self.connection else self.connection).sendall(chunk)


class ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextlib.contextmanager
def run_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def run(command, *, env, **kwargs):
    return subprocess.run(command, check=True, timeout=30, env=env, **kwargs)


def main():
    with tempfile.TemporaryDirectory(prefix="safe-claude-proxy-") as tmp:
        tmp = Path(tmp)
        # Never inherit user curl, proxy, credential, or compiler configuration.
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(tmp), "LANG": "C"}
        cert, key = tmp / "cert.pem", tmp / "key.pem"
        run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST},DNS:{AUTH_HOST}"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        driver = tmp / "trace-driver"
        run(["/usr/bin/swift", "build", "--target", "GuardCore"], env=env,
            cwd=ROOT, capture_output=True, text=True)
        bin_path = Path(run(["/usr/bin/swift", "build", "--show-bin-path"], env=env,
                            cwd=ROOT, capture_output=True, text=True).stdout.strip())
        resource_accessor = bin_path / "GuardCore.build/DerivedSources/resource_bundle_accessor.swift"
        if not resource_accessor.is_file():
            raise RuntimeError(f"SwiftPM resource accessor missing: {resource_accessor}")
        sources = sorted(str(path) for path in (ROOT / "Sources/GuardCore").glob("*.swift"))
        run(["/usr/bin/xcrun", "swiftc", *sources,
             str(resource_accessor), str(ROOT / "Tests/Fixtures/trace_probe_driver.swift"),
             "-o", str(driver)],
            env=env, capture_output=True, text=True)

        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
        target.requests = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        target.socket = context.wrap_socket(target.socket, server_side=True)
        proxy = ThreadingServer(("127.0.0.1", 0), Proxy)
        proxy.target_port = target.server_port
        proxy.seen = []

        # If curl reads this isolated config, it will force the request to fail.
        (tmp / ".curlrc").write_text('proxy = "http://127.0.0.1:1"\n')
        wrapper = tmp / "curl-wrapper"
        curl_extras = ["--cacert", str(cert),
                       "--resolve", f"{HOST}:{target.server_port}:127.0.0.1",
                       "--resolve", f"{AUTH_HOST}:{target.server_port}:127.0.0.1"]
        # TraceProbe drops HOME. Force a fixture-only curl config directory to
        # demonstrate that its first argument disables config-file loading.
        wrapper.write_text("#!/bin/bash\nset -eu\n"
                           '[ "$1" = "-q" ] || exit 91\n'
                           f"export CURL_HOME={shlex.quote(str(tmp))}\n"
                           'first="$1"; shift\nexec /usr/bin/curl "$first" '
                           + " ".join(shlex.quote(arg) for arg in curl_extras) + ' "$@"\n')
        wrapper.chmod(0o700)
        untrusted = tmp / "curl-untrusted"
        untrusted.write_text("#!/bin/bash\nset -eu\n"
                             '[ "$1" = "-q" ] || exit 91\n'
                             'first="$1"; shift\nexec /usr/bin/curl "$first" '
                             + " ".join(shlex.quote(arg) for arg in curl_extras[2:]) + ' "$@"\n')
        untrusted.chmod(0o700)
        proxy_url = f"http://fixture-user:fixture-secret@127.0.0.1:{proxy.server_address[1]}"

        def probe(host, no_proxy):
            result = run([str(driver)], env=env, text=True, capture_output=True,
                         input=json.dumps({"url": f"https://{host}:{target.server_port}/cdn-cgi/trace",
                                           "proxy": proxy_url, "no_proxy": no_proxy,
                                           "curl_wrapper": str(wrapper)}))
            assert "fixture-secret" not in result.stdout + result.stderr
            parsed = json.loads(result.stdout)
            assert parsed == {"status": "observed", "host": host,
                              "ip": "192.0.2.42", "country": "US"}, parsed

        with run_server(target), run_server(proxy):
            rejected = run([str(driver)], env=env, text=True, capture_output=True,
                           input=json.dumps({"url": f"https://{HOST}:{target.server_port}/cdn-cgi/trace",
                                             "proxy": proxy_url, "no_proxy": HOST,
                                             "curl_wrapper": str(untrusted)}))
            assert json.loads(rejected.stdout) == {"status": "unknown", "reason": "CERTIFICATE_VERIFICATION_FAILED"}
            probe(HOST, AUTH_HOST)
            assert proxy.seen == [(HOST, target.server_port)], proxy.seen
            probe(AUTH_HOST, AUTH_HOST)
            assert proxy.seen == [(HOST, target.server_port)], proxy.seen
            probe(HOST, HOST)
            assert proxy.seen == [(HOST, target.server_port)], proxy.seen
            probe(AUTH_HOST, HOST)
            assert proxy.seen == [(HOST, target.server_port), (AUTH_HOST, target.server_port)], proxy.seen
            assert target.requests == [(f"{h}:{target.server_port}", "/cdn-cgi/trace")
                                       for h in (HOST, AUTH_HOST, HOST, AUTH_HOST)], target.requests
        print(json.dumps({"swift_trace_probe": True, "real_curl": True, "curl_q_first": True,
                          "isolated_curlrc_ignored": True, "tls_verified": True,
                          "untrusted_certificate_detected": True,
                          "connect_routed": 2, "no_proxy_direct": 2,
                          "per_target_split": True, "fixture_credentials_redacted": True}))


if __name__ == "__main__":
    main()
