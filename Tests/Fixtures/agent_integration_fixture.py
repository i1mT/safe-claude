#!/usr/bin/env python3
"""Exercise the real local agent and launcher inside an isolated directory."""
import json
import os
import pathlib
import shutil
import socket as socket_module
import subprocess
import tempfile
import time

root = pathlib.Path(__file__).resolve().parents[2]
agent = str(root / '.build/debug/safe-claude-agent')
launcher = str(root / '.build/debug/safe-claude')
with tempfile.TemporaryDirectory(prefix='safe-guard-') as tmp:
    socket = os.path.join(tmp, 'agent.sock')
    marker = os.path.join(tmp, 'should-not-exist')
    remote_marker = os.path.join(tmp, 'remote-shell-checked')
    service_env = {'PATH': '/usr/bin:/bin', 'HOME': tmp, 'CFFIXED_USER_HOME': tmp, 'LANG': 'C'}
    policy = {
        'version': 1, 'minimumScore': 80, 'runtimeMinimumScore': 80,
        'trustedEndpoints': ['https://trusted.example'],
    }
    cli_policy_dir = os.path.join(tmp, 'Library', 'Application Support', 'SafeClaude')
    os.makedirs(cli_policy_dir, mode=0o700)
    with open(os.path.join(cli_policy_dir, 'policy.json'), 'w') as file:
        json.dump(policy, file)
    os.chmod(os.path.join(cli_policy_dir, 'policy.json'), 0o600)
    proc = subprocess.Popen([agent, '--socket', socket], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            env=service_env, cwd=tmp)
    try:
        for _ in range(100):
            if os.path.exists(socket):
                break
            if proc.poll() is not None:
                raise RuntimeError('agent exited')
            time.sleep(.02)
        else:
            raise RuntimeError('agent did not start')
        assert os.stat(socket).st_mode & 0o777 == 0o600
        cmd = [launcher, '--socket', socket]
        policy_path = os.path.join(tmp, 'policy.json')
        with open(policy_path, 'w') as file:
            json.dump(policy, file)
        os.chmod(policy_path, 0o600)
        dns_downgrade = json.loads(subprocess.check_output(
            cmd + ['fixture-dns-downgrade'], timeout=5))
        assert dns_downgrade['decision'] == 'allow', dns_downgrade
        wake_result = json.loads(subprocess.check_output(cmd + ['fixture-wake-observer'], timeout=5))
        assert wake_result['decision'] == 'allow', wake_result
        status_payload = None
        e09 = None
        for _ in range(100):
            status = subprocess.run(cmd + ['status'], capture_output=True, timeout=8, check=True)
            status_payload = json.loads(status.stdout)
            assert status_payload['version'] == 1
            e09 = next((item for item in status_payload.get('ruleStatuses', [])
                        if item.get('rule') == 'E09'), None)
            if e09:
                break
            time.sleep(.1)
        assert e09 and e09.get('status') in {'passed', 'triggered', 'unknown'}, status_payload
        if e09['status'] == 'unknown':
            assert e09.get('source') == 'runtime-virtualization', e09

        # The explicit project directory name is part of the Claude process
        # environment, not a settings-file value. The Agent must inspect only
        # index metadata and keep both the directory name and file content out
        # of its response.
        memory_config = os.path.join(tmp, 'memory-config')
        memory_index = os.path.join(memory_config, 'projects', 'fixture-workspace', 'memory')
        os.makedirs(memory_index, mode=0o700)
        memory_secret = 'private-memory-content-fixture'
        with open(os.path.join(memory_index, 'MEMORY.md'), 'w') as file:
            file.write(memory_secret)
        memory_request = {
            'version': 1, 'action': 'preflight',
            'environment': {
                'HOME': tmp, 'LANG': 'C',
                'CLAUDE_CONFIG_DIR': memory_config,
                'CLAUDE_CODE_PROJECT_DIR_NAME': 'fixture-workspace',
            },
            'executable': '/usr/bin/true',
            'workingDirectory': tmp,
            'customEndpointPresent': False,
            'entryKind': 'top',
        }
        encoded = json.dumps(memory_request).encode()
        with socket_module.socket(socket_module.AF_UNIX) as client:
            client.settimeout(8)
            client.connect(socket)
            client.sendall(len(encoded).to_bytes(4, 'big') + encoded)
            header = client.recv(4)
            assert len(header) == 4
            expected_length = int.from_bytes(header, 'big')
            memory_response_bytes = bytearray()
            while len(memory_response_bytes) < expected_length:
                chunk = client.recv(expected_length - len(memory_response_bytes))
                assert chunk
                memory_response_bytes.extend(chunk)
        memory_response = json.loads(memory_response_bytes)
        g07 = next((item for item in memory_response.get('ruleStatuses', [])
                    if item.get('rule') == 'G07'), None)
        assert g07 and g07.get('status') == 'passed', memory_response
        assert b'fixture-workspace' not in memory_response_bytes
        assert memory_secret.encode() not in memory_response_bytes

        custom_memory_config = os.path.join(tmp, 'custom-memory-config')
        custom_memory_path = os.path.join(tmp, 'custom-memory')
        os.makedirs(custom_memory_path, mode=0o700)
        custom_memory_secret = 'custom-memory-body-fixture'
        with open(os.path.join(custom_memory_path, 'MEMORY.md'), 'w') as file:
            file.write(custom_memory_secret)
        os.makedirs(custom_memory_config, mode=0o700)
        with open(os.path.join(custom_memory_config, 'settings.json'), 'w') as file:
            json.dump({'autoMemoryDirectory': custom_memory_path}, file)
        custom_memory_request = {
            'version': 1, 'action': 'preflight',
            'environment': {
                'HOME': tmp, 'LANG': 'C',
                'CLAUDE_CONFIG_DIR': custom_memory_config,
            },
            'executable': '/usr/bin/true',
            'workingDirectory': tmp,
            'customEndpointPresent': False,
            'entryKind': 'top',
        }
        encoded = json.dumps(custom_memory_request).encode()
        with socket_module.socket(socket_module.AF_UNIX) as client:
            client.settimeout(8)
            client.connect(socket)
            client.sendall(len(encoded).to_bytes(4, 'big') + encoded)
            header = client.recv(4)
            assert len(header) == 4
            expected_length = int.from_bytes(header, 'big')
            custom_memory_response_bytes = bytearray()
            while len(custom_memory_response_bytes) < expected_length:
                chunk = client.recv(expected_length - len(custom_memory_response_bytes))
                assert chunk
                custom_memory_response_bytes.extend(chunk)
        custom_memory_response = json.loads(custom_memory_response_bytes)
        custom_g07 = next((item for item in custom_memory_response.get('ruleStatuses', [])
                           if item.get('rule') == 'G07'), None)
        assert custom_g07 and custom_g07.get('status') == 'passed', custom_memory_response
        assert custom_memory_path.encode() not in custom_memory_response_bytes
        assert custom_memory_secret.encode() not in custom_memory_response_bytes

        inline_memory_marker = os.path.join(tmp, 'inline-memory-executed')
        previous_checked_at = json.loads(subprocess.check_output(
            cmd + ['status'], timeout=5))['checkedAt']
        inline_memory_settings = json.dumps({'autoMemoryDirectory': custom_memory_path})
        inline_memory_launch = subprocess.run(
            cmd + ['exec', '--settings', inline_memory_settings, '--', '/usr/bin/touch',
                   inline_memory_marker],
            env=service_env, cwd=tmp, capture_output=True, timeout=30)
        inline_memory_status = None
        for _ in range(30):
            inline_memory_status = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
            if (inline_memory_status.get('assessmentContext') == 'claude-launch' and
                    inline_memory_status['checkedAt'] > previous_checked_at):
                break
            time.sleep(.1)
        inline_g07 = next((item for item in inline_memory_status.get('ruleStatuses', [])
                           if item.get('rule') == 'G07'), None)
        assert inline_g07 and inline_g07.get('status') == 'passed', inline_memory_status
        inline_output = inline_memory_launch.stdout + inline_memory_launch.stderr + \
            json.dumps(inline_memory_status).encode()
        assert custom_memory_path.encode() not in inline_output
        assert custom_memory_secret.encode() not in inline_output
        if os.path.exists(inline_memory_marker):
            os.unlink(inline_memory_marker)

        # Exercise endpoint classification inside the real Agent, including
        # the file settings parser and policy loaded beside its test socket.
        for trusted, endpoint in (
            (True, 'https://trusted.example/'),
            (False, 'https://fixture-user:fixture-pass@evil.example/path?token=endpoint-secret#fragment'),
        ):
            settings_path = os.path.join(tmp, 'endpoint-settings.json')
            with open(settings_path, 'w') as file:
                json.dump({'env': {'ANTHROPIC_BASE_URL': endpoint}}, file)
            request = {
                'version': 1, 'action': 'preflight',
                'environment': {'HOME': tmp, 'LANG': 'C'},
                'executable': '/usr/bin/true',
                'workingDirectory': tmp,
                'additionalSettingsPath': settings_path,
                'customEndpointPresent': False,
                'entryKind': 'top',
            }
            encoded = json.dumps(request).encode()
            with socket_module.socket(socket_module.AF_UNIX) as client:
                client.settimeout(8)
                client.connect(socket)
                client.sendall(len(encoded).to_bytes(4, 'big') + encoded)
                header = client.recv(4)
                assert len(header) == 4
                expected_length = int.from_bytes(header, 'big')
                response_bytes = bytearray()
                while len(response_bytes) < expected_length:
                    chunk = client.recv(expected_length - len(response_bytes))
                    assert chunk
                    response_bytes.extend(chunk)
            endpoint_response = json.loads(response_bytes)
            a09 = next((item for item in endpoint_response.get('ruleStatuses', [])
                        if item.get('rule') == 'A09'), None)
            assert a09 is not None, endpoint_response
            if trusted:
                assert a09['status'] != 'triggered', a09
            else:
                assert a09['status'] == 'triggered' and a09['points'] == 20, a09
            redacted = response_bytes.decode(errors='replace')
            for secret in ['fixture-user', 'fixture-pass', 'endpoint-secret', '/path']:
                assert secret not in redacted

        # Run the real launcher against the real Agent for process environment
        # endpoints. The launcher reduces the URL to a boolean before IPC.
        endpoint_cases = (
            (True, 'https://trusted.example/'),
            (False, 'https://fixture-user:fixture-pass@evil.example/path?token=endpoint-secret#fragment'),
        )
        for source in ('environment', 'inline-settings'):
            for trusted, endpoint in endpoint_cases:
                endpoint_marker = os.path.join(tmp, 'endpoint-executed')
                previous_status = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
                previous_checked_at = previous_status['checkedAt']
                endpoint_env = service_env.copy()
                endpoint_command = cmd + ['exec', '--', '/usr/bin/touch']
                if source == 'environment':
                    endpoint_env['ANTHROPIC_BASE_URL'] = endpoint
                else:
                    inline_settings = json.dumps({'env': {'ANTHROPIC_BASE_URL': endpoint}})
                    endpoint_command.extend(['--settings', inline_settings])
                endpoint_command.append(endpoint_marker)
                endpoint_launch = subprocess.run(
                    endpoint_command, env=endpoint_env, cwd=tmp, capture_output=True, timeout=30)
                assert not os.path.exists(endpoint_marker), endpoint_launch.stdout
                endpoint_status = None
                for _ in range(30):
                    endpoint_status = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
                    if (endpoint_status.get('assessmentContext') == 'claude-launch' and
                            endpoint_status['checkedAt'] > previous_checked_at):
                        break
                    time.sleep(.1)
                endpoint_a09 = next((item for item in endpoint_status.get('ruleStatuses', [])
                                     if item.get('rule') == 'A09'), None)
                assert endpoint_a09 is not None, endpoint_status
                if trusted:
                    assert endpoint_a09['status'] != 'triggered', endpoint_a09
                else:
                    assert endpoint_a09['status'] == 'triggered' and endpoint_a09['points'] == 20, endpoint_a09
                output = endpoint_launch.stdout + endpoint_launch.stderr + json.dumps(endpoint_status).encode()
                for secret in ['fixture-user', 'fixture-pass', 'endpoint-secret', '/path']:
                    assert secret.encode() not in output
        ssh_env = service_env | {
            'SSH_CONNECTION': '192.0.2.18 54821 198.51.100.4 22',
        }
        remote_launch = subprocess.run(
            cmd + ['exec', '--', '/usr/bin/touch', remote_marker],
            env=ssh_env, cwd=tmp, capture_output=True, timeout=30)
        remote_status = None
        remote_e09 = None
        for _ in range(50):
            remote_status = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
            remote_e09 = next((item for item in remote_status.get('ruleStatuses', [])
                               if item.get('rule') == 'E09'), None)
            if remote_e09 and remote_e09.get('status') == 'triggered':
                break
            time.sleep(.1)
        assert remote_e09 and remote_e09.get('status') == 'triggered', remote_status
        assert remote_e09.get('points') == 3, remote_e09
        if remote_launch.returncode == 0:
            os.unlink(remote_marker)
        else:
            assert not os.path.exists(remote_marker), remote_launch.stderr.decode(errors='replace')
        proxy_conflict_env = service_env | {
            'all_proxy': 'socks5://lower-user:lower-secret@127.0.0.1:1080',
            'ALL_PROXY': 'socks5://upper-user:upper-secret@127.0.0.1:1081',
        }
        proxy_conflict_launch = subprocess.run(
            cmd + ['exec', '--', '/usr/bin/touch', marker],
            env=proxy_conflict_env, cwd=tmp, capture_output=True, timeout=15)
        assert proxy_conflict_launch.returncode == 75, proxy_conflict_launch.stderr
        assert not os.path.exists(marker)
        proxy_conflict_status = None
        f01 = None
        for _ in range(50):
            proxy_conflict_status = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
            f01 = next((item for item in proxy_conflict_status.get('ruleStatuses', [])
                        if item.get('rule') == 'F01'), None)
            if f01 and f01.get('status') == 'triggered':
                break
            time.sleep(.1)
        assert f01 and f01.get('status') == 'triggered' and f01.get('points') == 8, proxy_conflict_status
        redacted_proxy_output = json.dumps(proxy_conflict_status) + \
            proxy_conflict_launch.stdout.decode(errors='replace') + \
            proxy_conflict_launch.stderr.decode(errors='replace')
        for secret in ['lower-user', 'lower-secret', 'upper-user', 'upper-secret',
                       '127.0.0.1', '1080', '1081', 'socks5://']:
            assert secret not in redacted_proxy_output
        draining = json.loads(subprocess.check_output(cmd + ['prepare-uninstall'], timeout=5))
        assert draining['decision'] == 'allow' and draining['managedSessions'] == 0
        state = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
        assert state['decision'] == 'hold'
        subprocess.run(cmd + ['cancel-uninstall'], capture_output=True, timeout=5, check=True)
        env = service_env.copy()
        env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'  # Force incomplete, without external requests.
        denied = subprocess.run(cmd + ['exec', '--', '/usr/bin/touch', marker], env=env, cwd=tmp,
                                capture_output=True, timeout=8)
        assert denied.returncode == 75, denied.stderr
        assert not os.path.exists(marker)
        def assert_model_block(arguments, launch_env):
            for _ in range(20):
                result = subprocess.run(cmd + ['exec', '--', '/usr/bin/touch', marker] + arguments,
                                        env=launch_env, cwd=tmp, capture_output=True, timeout=8)
                assert result.returncode == 75, result.stderr
                current = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
                rules = {item['rule']: item for item in current.get('ruleStatuses', [])}
                if (current.get('assessmentContext') == 'claude-launch' and
                        rules.get('G06', {}).get('status') == 'triggered'):
                    assert not os.path.exists(marker)
                    return
                if '后台服务未就绪或启动检查正在进行'.encode() not in result.stderr:
                    break
                time.sleep(.15)
            raise AssertionError({'status': current,
                                  'launcher_stderr': result.stderr.decode(errors='replace')})

        retired_model = 'claude-opus-4-1-20250805'
        assert_model_block(['--model=' + retired_model], env)
        assert_model_block([], env | {'ANTHROPIC_MODEL': retired_model})
        assert_model_block(['--settings', json.dumps({'model': retired_model})], env)
        real_claude = shutil.which('claude')
        if real_claude:
            for _ in range(300):
                ready = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
                if len(ready.get('ruleStatuses', [])) == 64:
                    break
                time.sleep(.1)
            else:
                raise AssertionError(f'Agent did not finish initial recovery: {ready}')
            unsafe_env = service_env.copy()
            unsafe_env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'
            real_attempt = subprocess.run(
                cmd + ['exec', '--', real_claude, '--version'],
                env=unsafe_env, cwd=tmp, capture_output=True, timeout=30)
            assert real_attempt.returncode == 75, real_attempt.stderr
            first_status = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
            for _ in range(100):
                status = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
                states = {item['rule']: item for item in status.get('ruleStatuses', [])}
                if states.get('D05', {}).get('status') == 'triggered':
                    break
                time.sleep(.1)
            else:
                raise AssertionError({'first': first_status, 'last': status,
                                      'stderr': real_attempt.stderr.decode(errors='replace')})
            assert status.get('assessmentContext') == 'claude-launch', status
            real_claude_blocked = True
        else:
            real_claude_blocked = None
        def assert_custom_trust_block(arguments, launch_env):
            attempt = subprocess.run(cmd + ['exec', '--', '/usr/bin/touch', marker] + arguments,
                                     env=launch_env, cwd=tmp, capture_output=True, timeout=8)
            assert attempt.returncode == 75 and not os.path.exists(marker), attempt.stderr
            for _ in range(100):
                current = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
                current_rules = {item['rule']: item for item in current.get('ruleStatuses', [])}
                if (current.get('assessmentContext') == 'claude-launch' and
                        current_rules.get('F08', {}).get('status') == 'triggered'):
                    return
                time.sleep(.1)
            raise AssertionError({'status': current,
                                  'stderr': attempt.stderr.decode(errors='replace')})

        assert_custom_trust_block([], service_env | {'NODE_EXTRA_CA_CERTS': '/private/fixture/custom-root.pem'})
        assert_custom_trust_block(
            ['--settings', json.dumps({'env': {'SSL_CERT_FILE': '/private/fixture/custom-root.pem'}})],
            service_env)
        client_certificate = os.path.join(tmp, 'client-certificate.pem')
        client_private_key = os.path.join(tmp, 'client-private-key.pem')
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', client_private_key, '-out', client_certificate, '-days', '1',
                        '-subj', '/CN=SafeClaude fixture'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        attempt = subprocess.run(
            cmd + ['exec', '--', '/usr/bin/touch', marker, '--settings',
                   json.dumps({'env': {'CLAUDE_CODE_CLIENT_CERT': client_certificate}})],
            env=service_env, cwd=tmp, capture_output=True, timeout=8)
        assert attempt.returncode == 75 and not os.path.exists(marker), attempt.stderr
        for _ in range(100):
            current = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
            current_rules = {item['rule']: item for item in current.get('ruleStatuses', [])}
            if (current.get('assessmentContext') == 'claude-launch' and
                    current_rules.get('D08', {}).get('status') == 'triggered'):
                encoded = json.dumps(current)
                assert client_certificate not in encoded and client_private_key not in encoded
                assert b'client-certificate.pem' not in attempt.stdout + attempt.stderr
                assert b'client-private-key.pem' not in attempt.stdout + attempt.stderr
                break
            time.sleep(.1)
        else:
            raise AssertionError({'status': current,
                                  'stderr': attempt.stderr.decode(errors='replace')})
        def assert_tls_downgrade_block(arguments, launch_env):
            attempt = subprocess.run(cmd + ['exec', '--', '/usr/bin/touch', marker] + arguments,
                                     env=launch_env, cwd=tmp, capture_output=True, timeout=8)
            assert attempt.returncode == 75 and not os.path.exists(marker), attempt.stderr
            for _ in range(100):
                current = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
                current_rules = {item['rule']: item for item in current.get('ruleStatuses', [])}
                if (current.get('assessmentContext') == 'claude-launch' and
                        current_rules.get('D07', {}).get('status') == 'triggered'):
                    encoded = json.dumps(current)
                    assert 'private-node-plugin.js' not in encoded
                    assert '--tls-min-v1.0' not in encoded
                    return
                time.sleep(.1)
            raise AssertionError({'status': current,
                                  'stderr': attempt.stderr.decode(errors='replace')})

        unsafe_node_options = '--tls-min-v1.0 --require=/private/private-node-plugin.js'
        assert_tls_downgrade_block([], service_env | {'NODE_OPTIONS': unsafe_node_options})
        assert_tls_downgrade_block(
            ['--settings', json.dumps({'env': {'NODE_OPTIONS': unsafe_node_options}})],
            service_env)
        for _ in range(60):
            detail = json.loads(subprocess.check_output(cmd + ['status'], timeout=5))
            if detail.get('unknownRules'):
                assert len(detail['unknownRules']) == detail['unknownCount']
                assert all(len(rule) == 3 for rule in detail['unknownRules'])
                statuses = detail['ruleStatuses']
                assert len(statuses) == 64
                assert len({item['rule'] for item in statuses}) == 64
                assert all(set(item).issubset({'rule', 'status', 'points', 'source', 'observedAt',
                                               'remediation'})
                           for item in statuses)
                assert all(isinstance(item.get('remediation'), str) and item['remediation']
                           for item in statuses)
                assert all(item['status'] in {
                    'triggered', 'passed', 'notApplicable', 'unknown', 'unsupported', 'missing'
                } for item in statuses)
                break
            time.sleep(.1)
        else:
            raise AssertionError('agent did not expose incomplete rule identifiers')
        duplicate = subprocess.run([agent, '--socket', socket], env=service_env, cwd=tmp, capture_output=True, timeout=5)
        assert duplicate.returncode != 0
        assert json.loads(subprocess.check_output(cmd + ['status'], timeout=5))['version'] == 1
        proc.terminate()
        proc.wait(timeout=5)
        offline = subprocess.run(cmd + ['exec', '--', '/usr/bin/touch', marker], env=service_env, cwd=tmp,
                                 capture_output=True, timeout=5)
        assert offline.returncode == 75 and not os.path.exists(marker)
        print(json.dumps({'agent_status': True, 'unknown_rule_details': True, 'all_rule_statuses': True,
                          'e09_runtime_virtualization': e09['status'],
                          'e09_source': e09.get('source'),
                          'e09_ssh_remote_context': remote_e09['status'],
                          'f01_proxy_case_conflict': f01['status'],
                          'wake_revalidation': wake_result['decision'] == 'allow',
                          'dns_encryption_downgrade': dns_downgrade['decision'] == 'allow',
                          'deprecated_model_preflight_scored': True,
                          'model_flag_environment_settings': True,
                          'custom_ca_status_scored': True,
                          'settings_client_certificate_expiry_scored': True,
                          'g07_project_custom_and_inline_directory_metadata_only': True,
                          'real_claude_blocked': real_claude_blocked,
                          'fail_closed': True,
                          'duplicate_agent_rejected': True, 'offline_blocked': True}))
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
