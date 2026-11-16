#!/usr/bin/env python3
"""Synthetic local server tests the launcher's real exec and ticket protocol."""
import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

launcher = str(Path(__file__).resolve().parents[2] / '.build/debug/safe-claude')
def serve(path, valid):
    server = socket.socket(socket.AF_UNIX)
    server.bind(path)
    os.chmod(path, 0o600)
    server.listen(2)
    expiry = time.time() - 978307200 + 0.9  # Foundation Codable Date epoch
    for index in range(2):
        conn, _ = server.accept()
        with conn:
            header = conn.recv(4)
            count = struct.unpack('!I', header)[0]
            body = b''
            while len(body) < count:
                body += conn.recv(count - len(body))
            request = json.loads(body)
            assert request['action'] == ('preflight' if index == 0 else 'validate')
            if index == 1: assert request['ticket'] == 'fixture-ticket'
            response = {'version': 1, 'decision': 'allow' if index == 0 or valid else 'hold',
                        'safetyScore': 95, 'scoreUpperBound': 95, 'unknownCount': 0,
                        'reason': 'fixture', 'findings': [], 'checkedAt': expiry - 0.9, 'expiresAt': expiry}
            if index == 0: response['ticket'] = 'fixture-ticket'
            data = json.dumps(response).encode()
            conn.sendall(struct.pack('!I', len(data)) + data)
    server.close()

for valid in (True, False):
    with tempfile.TemporaryDirectory(prefix='safe-ticket-') as root:
        path = os.path.join(root, 'agent.sock')
        marker = os.path.join(root, 'target-executed')
        thread = threading.Thread(target=serve, args=(path, valid), daemon=True)
        thread.start()
        for _ in range(100):
            if os.path.exists(path): break
            time.sleep(.01)
        result = subprocess.run([launcher, '--socket', path, 'exec', '--', '/usr/bin/touch', marker],
                                capture_output=True, timeout=5)
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert (result.returncode == 0 and os.path.exists(marker)) if valid else (result.returncode == 75 and not os.path.exists(marker))
print('launcher ticket revalidation and exec: passed')

# Inline --settings is parsed locally. Only selected safe signals cross IPC;
# credentials and unrelated settings remain in argv and are never serialized.
with tempfile.TemporaryDirectory(prefix='safe-settings-ticket-') as root:
    path = os.path.join(root, 'agent.sock')
    payload = {'env': {'ANTHROPIC_API_KEY': 'inline-secret-value',
                       'ANTHROPIC_BASE_URL': 'https://custom.example',
                       'TZ': 'Asia/Tokyo', 'LANG': 'ja_JP.UTF-8'},
               'other': {'token': 'unrelated-secret-value'}}
    def serve_settings():
        server = socket.socket(socket.AF_UNIX)
        server.bind(path)
        os.chmod(path, 0o600)
        server.listen(1)
        conn, _ = server.accept()
        with conn:
            header = conn.recv(4)
            count = struct.unpack('!I', header)[0]
            body = b''
            while len(body) < count:
                body += conn.recv(count - len(body))
            request = json.loads(body)
            signals = request['commandLineSettings']
            assert signals['customEndpoint'] is True
            assert signals['locale'] == {'TZ': 'Asia/Tokyo', 'LANG': 'ja_JP.UTF-8'}
            assert b'inline-secret-value' not in body and b'unrelated-secret-value' not in body
            assert request['customEndpointPresent'] is True
            response = {'version': 1, 'decision': 'hold', 'unknownCount': 1,
                        'reason': 'fixture', 'findings': [], 'checkedAt': time.time() - 978307200}
            data = json.dumps(response).encode()
            conn.sendall(struct.pack('!I', len(data)) + data)
        server.close()
    thread = threading.Thread(target=serve_settings, daemon=True)
    thread.start()
    for _ in range(100):
        if os.path.exists(path): break
        time.sleep(.01)
    result = subprocess.run([launcher, '--socket', path, 'exec', '--', '/usr/bin/touch',
                             '--settings', json.dumps(payload), os.path.join(root, 'must-not-exist')],
                            capture_output=True, timeout=5)
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert result.returncode == 75
    assert not os.path.exists(os.path.join(root, 'must-not-exist'))
print('inline --settings inspection and IPC redaction: passed')

with tempfile.TemporaryDirectory(prefix='safe-settings-file-ticket-') as root:
    path = os.path.join(root, 'agent.sock')
    settings_path = os.path.join(root, 'settings.json')
    with open(settings_path, 'w') as file:
        json.dump({'env': {'ANTHROPIC_BASE_URL': 'https://custom.example',
                           'TZ': 'Asia/Tokyo', 'LANG': 'ja_JP.UTF-8'}}, file)
    received = []
    def serve_settings_file():
        server = socket.socket(socket.AF_UNIX)
        server.bind(path)
        os.chmod(path, 0o600)
        server.listen(1)
        conn, _ = server.accept()
        with conn:
            header = conn.recv(4)
            count = struct.unpack('!I', header)[0]
            body = b''
            while len(body) < count:
                body += conn.recv(count - len(body))
            received.append(json.loads(body))
            response = {'version': 1, 'decision': 'hold', 'unknownCount': 1,
                        'reason': 'fixture', 'findings': [], 'checkedAt': time.time() - 978307200}
            data = json.dumps(response).encode()
            conn.sendall(struct.pack('!I', len(data)) + data)
        server.close()
    thread = threading.Thread(target=serve_settings_file, daemon=True)
    thread.start()
    for _ in range(100):
        if os.path.exists(path): break
        time.sleep(.01)
    result = subprocess.run([launcher, '--socket', path, 'exec', '--', '/usr/bin/touch',
                             '--settings', settings_path, os.path.join(root, 'must-not-exist')],
                            capture_output=True, timeout=5)
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert result.returncode == 75
    assert received[0]['additionalSettingsPath'] == settings_path
    settings_findings = received[0].get('commandLineSettings') or {}
    assert not settings_findings.get('customEndpoint', False)
    assert not settings_findings.get('locale', {})
    assert 'https://custom.example' not in json.dumps(received[0])
    assert not os.path.exists(os.path.join(root, 'must-not-exist'))
print('file --settings path binding: passed')
