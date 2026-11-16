#!/usr/bin/env python3
"""Test shell installation and rollback without changing the real home."""
import os
import json
import shlex
import shutil
import fcntl
import time
import argparse
import importlib.util
import plistlib
from pathlib import Path
import subprocess
import tempfile
from unittest import mock

project = Path(__file__).resolve().parents[2]
setup = project / 'Scripts/setup-integration.py'
with tempfile.TemporaryDirectory(prefix='safe-setup-') as temp:
    home = Path(temp)
    prefix = home / 'installation'
    fake_claude = home / 'original-claude'
    fake_claude.write_text('#!/bin/sh\n[ \"$1\" = \"--version\" ] && echo \"2.1.319 (Claude Code)\"\n')
    fake_claude.chmod(0o700)
    rc = home / '.zshrc'
    original = b'export EXAMPLE=1'  # no trailing newline
    rc.write_bytes(original)
    env = os.environ.copy()
    env['HOME'] = str(home)
    env['SAFE_CLAUDE_AGENT_SOCKET'] = str(home / 'Library/Application Support/SafeClaude/fixture-agent.sock')
    env.pop('CLAUDE_CONFIG_DIR', None)
    env.pop('CLAUDE_CODE_PROCESS_WRAPPER', None)
    settings = home / '.claude/settings.json'
    settings.parent.mkdir()
    original_settings = (
        b'{\n  \"env\": {\"ANTHROPIC_API_KEY\": \"fixture-secret\"},\n'
        b'  \"hooks\": {\"StopFailure\": [{\"matcher\":\"server_error\",'
        b'\"hooks\":[{\"type\":\"command\",\"command\":\"echo existing\"}]}]}\n}\n'
    )
    settings.write_bytes(original_settings)
    base = ['python3', str(setup)]
    subprocess.run(base + ['install', '--prefix', str(prefix), '--claude', str(fake_claude), '--no-launchd'],
                   cwd=project, env=env, check=True, stdout=subprocess.DEVNULL)
    lifecycle = prefix / 'SafeClaude.app/Contents/MacOS/SafeClaude_GuardCore.bundle/claude-model-lifecycle.json'
    assert lifecycle.is_file() and json.loads(lifecycle.read_text())
    agent_lifecycle = prefix / 'libexec/SafeClaude_GuardCore.bundle/claude-model-lifecycle.json'
    assert agent_lifecycle.is_file() and json.loads(agent_lifecycle.read_text())
    doctor_env = env | {'PATH': str(prefix / 'bin') + os.pathsep + env['PATH']}
    fixture_socket = env['SAFE_CLAUDE_AGENT_SOCKET']
    doctor = subprocess.run([str(prefix / 'libexec/safe-claude'), '--socket', fixture_socket, 'doctor'], env=doctor_env,
                            capture_output=True, text=True, timeout=5)
    doctor_report = json.loads(doctor.stdout)
    assert doctor.returncode == 75  # Agent is intentionally not installed in this fixture.
    assert doctor_report['shimInstalled'] and doctor_report['shimSelectedByPATH']
    assert doctor_report['modelLifecycleResourcesValid']
    assert doctor_report['agentModelLifecycleResourceValid'] and doctor_report['appModelLifecycleResourceValid']
    for required_resource in (lifecycle, agent_lifecycle):
        contents = required_resource.read_bytes()
        required_resource.unlink()
        incomplete = subprocess.run([str(prefix / 'libexec/safe-claude'), '--socket', fixture_socket, 'doctor'], env=doctor_env,
                                   capture_output=True, text=True, timeout=5)
        incomplete_report = json.loads(incomplete.stdout)
        assert incomplete.returncode == 75 and not incomplete_report['modelLifecycleResourcesValid']
        expected_key = 'appModelLifecycleResourceValid' if required_resource == lifecycle \
            else 'agentModelLifecycleResourceValid'
        assert not incomplete_report[expected_key]
        required_resource.write_bytes(contents)
    assert b'safe-claude managed' in rc.read_bytes()
    config = json.loads(settings.read_text())
    assert config['processWrapper'] == str(prefix / 'libexec/process-wrapper')
    assert config['env']['ANTHROPIC_API_KEY'] == 'fixture-secret'
    stop_failure_hooks = config['hooks']['StopFailure']
    assert len(stop_failure_hooks) == 2
    assert stop_failure_hooks[0] == {
        'matcher': 'server_error',
        'hooks': [{'type': 'command', 'command': 'echo existing'}],
    }
    assert 'safe-claude' in stop_failure_hooks[1]['hooks'][0]['command']
    assert stop_failure_hooks[1]['hooks'][0]['command'].endswith(' hook-event')
    assert b'fixture-secret' not in (prefix / 'manifest.json').read_bytes()
    shell_before_upgrade = rc.read_bytes()
    legacy_manifest_path = prefix / 'manifest.json'
    legacy_manifest = json.loads(legacy_manifest_path.read_text())
    hook_fragment = next(fragment for fragment in legacy_manifest['settingsFragments']
                         if '"matcher"' in fragment and 'safe-claude' in fragment)
    settings_content = settings.read_text()
    assert settings_content.count(hook_fragment) == 1
    settings.write_text(settings_content.replace(hook_fragment, '', 1))
    wrapper_fragment = next(fragment for fragment in legacy_manifest['settingsFragments']
                            if '"processWrapper"' in fragment)
    legacy_manifest.pop('settingsFragments')
    legacy_manifest['settingsFragment'] = wrapper_fragment
    legacy_manifest_path.write_text(json.dumps(legacy_manifest, indent=2))
    legacy_manifest_path.chmod(0o600)
    legacy_settings = settings.read_bytes()
    subprocess.run(base + ['upgrade', '--prefix', str(prefix)], cwd=project, env=env, check=True,
                   stdout=subprocess.DEVNULL)
    migrated_settings = settings.read_bytes()
    assert migrated_settings != legacy_settings
    migrated_config = json.loads(migrated_settings)
    assert len(migrated_config['hooks']['StopFailure']) == 2
    migrated_manifest = json.loads(legacy_manifest_path.read_text())
    assert 'settingsFragments' in migrated_manifest and 'settingsFragment' not in migrated_manifest
    settings_before_upgrade = migrated_settings
    subprocess.run(base + ['upgrade', '--prefix', str(prefix)], cwd=project, env=env, check=True,
                   stdout=subprocess.DEVNULL)
    assert rc.read_bytes() == shell_before_upgrade
    assert settings.read_bytes() == settings_before_upgrade
    assert json.loads((prefix / 'manifest.json').read_text())['launchd'] is False
    installed_manifest = (prefix / 'manifest.json').read_bytes()
    malicious_manifest = json.loads(installed_manifest)
    malicious_manifest['files']['../outside-fixture'] = '0' * 64
    (prefix / 'manifest.json').write_text(json.dumps(malicious_manifest))
    rejected_manifest = subprocess.run(base + ['uninstall', '--prefix', str(prefix)], cwd=project,
                                       env=env, capture_output=True, timeout=5)
    assert rejected_manifest.returncode != 0
    assert b'invalid installation manifest path' in rejected_manifest.stderr
    assert prefix.is_dir()
    (prefix / 'manifest.json').write_bytes(installed_manifest)
    altered_shell = shell_before_upgrade.replace(str(prefix / 'bin').encode(), b'/custom/bin')
    rc.write_bytes(altered_shell)
    conflicted_shell_upgrade = subprocess.run(base + ['upgrade', '--prefix', str(prefix)], cwd=project,
        env=env, capture_output=True, timeout=10)
    assert conflicted_shell_upgrade.returncode != 0 and rc.read_bytes() == altered_shell
    rc.write_bytes(shell_before_upgrade)
    altered_settings = settings_before_upgrade.replace(
        str(prefix / 'libexec/process-wrapper').encode(), b'/custom/process-wrapper')
    settings.write_bytes(altered_settings)
    conflicted_settings_upgrade = subprocess.run(base + ['upgrade', '--prefix', str(prefix)], cwd=project,
        env=env, capture_output=True, timeout=10)
    assert conflicted_settings_upgrade.returncode != 0 and settings.read_bytes() == altered_settings
    settings.write_bytes(settings_before_upgrade)
    journal = home / 'Library/Application Support/SafeClaude/sessions.json'
    journal.parent.mkdir(parents=True, exist_ok=True)
    journal.write_text('[{\"recorded\":\"active\"}]')
    active_upgrade = subprocess.run(base + ['upgrade', '--prefix', str(prefix)], cwd=project,
                                    env=env, capture_output=True, timeout=10)
    assert active_upgrade.returncode != 0 and prefix.is_dir()
    assert (prefix / 'manifest.json').read_bytes() == installed_manifest
    assert rc.read_bytes() == shell_before_upgrade and settings.read_bytes() == settings_before_upgrade
    journal.unlink()
    slow_bin = home / 'slow-swift'
    slow_bin.mkdir()
    slow_swift = slow_bin / 'swift'
    slow_swift.write_text('#!/bin/sh\nif [ \"$1\" = build ] && [ \"$#\" = 3 ]; then /bin/sleep 2; fi\n'
                          + 'exec ' + shlex.quote(shutil.which('swift')) + ' \"$@\"\n')
    slow_swift.chmod(0o700)
    slow_upgrade_env = env | {'PATH': str(slow_bin) + os.pathsep + env['PATH']}
    upgrade_process = subprocess.Popen(base + ['upgrade', '--prefix', str(prefix)], cwd=project,
                                       env=slow_upgrade_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lock_path = home / 'Library/Application Support/SafeClaude/setup.lock'
    lock_held = False
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not lock_held:
        lock_fd = os.open(lock_path, os.O_RDWR)
        try:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except BlockingIOError:
                lock_held = True
        finally:
            os.close(lock_fd)
        if not lock_held:
            time.sleep(0.02)
    assert lock_held
    competing_upgrade = subprocess.run(base + ['upgrade', '--prefix', str(prefix)], cwd=project,
                                       env=env, capture_output=True, timeout=5)
    assert competing_upgrade.returncode != 0 and b'in progress' in competing_upgrade.stderr
    assert upgrade_process.wait(timeout=10) == 0
    upgrade_process.communicate()
    failed_swift_bin = home / 'failed-swift'
    failed_swift_bin.mkdir()
    failed_swift = failed_swift_bin / 'swift'
    failed_swift.write_text('#!/bin/sh\nexit 88\n')
    failed_swift.chmod(0o700)
    failed_upgrade_env = env | {'PATH': str(failed_swift_bin) + os.pathsep + env['PATH']}
    failed_upgrade = subprocess.run(base + ['upgrade', '--prefix', str(prefix)], cwd=project,
                                    env=failed_upgrade_env, capture_output=True, timeout=10)
    assert failed_upgrade.returncode != 0 and prefix.is_dir()
    assert (prefix / 'manifest.json').read_bytes() == installed_manifest
    assert rc.read_bytes() == shell_before_upgrade and settings.read_bytes() == settings_before_upgrade
    result = subprocess.run([str(prefix / 'bin/claude')], env=env, capture_output=True, timeout=5)
    assert result.returncode == 75 and b'safe-claude' in result.stderr
    target = prefix / 'libexec/claude-target'
    before = target.read_bytes()
    target.write_bytes(b'/usr/bin/false\n')
    changed = subprocess.run(base + ['uninstall', '--prefix', str(prefix)], cwd=project, env=env, capture_output=True)
    assert changed.returncode != 0 and prefix.exists()
    target.write_bytes(before)
    installed_settings = settings.read_bytes()
    settings.write_bytes(installed_settings.replace(
        str(prefix / 'libexec/process-wrapper').encode(), b'/another/wrapper'))
    changed = subprocess.run(base + ['uninstall', '--prefix', str(prefix)], cwd=project, env=env, capture_output=True)
    assert changed.returncode != 0 and prefix.exists()
    assert settings.read_bytes() == installed_settings.replace(
        str(prefix / 'libexec/process-wrapper').encode(), b'/another/wrapper')
    settings.write_bytes(installed_settings)
    installed_shell = rc.read_bytes()
    changed_shell = installed_shell.replace(str(prefix / 'bin').encode(), b'/another/bin')
    rc.write_bytes(changed_shell)
    changed = subprocess.run(base + ['uninstall', '--prefix', str(prefix)], cwd=project, env=env, capture_output=True)
    assert changed.returncode != 0 and prefix.exists()
    assert rc.read_bytes() == changed_shell
    rc.write_bytes(installed_shell)
    subprocess.run(base + ['uninstall', '--prefix', str(prefix)], cwd=project, env=env, check=True, stdout=subprocess.DEVNULL)
    assert rc.read_bytes() == original and settings.read_bytes() == original_settings and not prefix.exists()
    conflict = b'{"env":{"CLAUDE_CODE_PROCESS_WRAPPER":"/other/wrapper"}}\n'
    settings.write_bytes(conflict)
    failed = subprocess.run(base + ['install', '--prefix', str(prefix), '--claude', str(fake_claude), '--no-launchd'],
                            cwd=project, env=env, capture_output=True)
    assert failed.returncode != 0 and b'already contain CLAUDE_CODE_PROCESS_WRAPPER' in failed.stderr
    assert not prefix.exists() and settings.read_bytes() == conflict
    # Simulate another program editing configuration while the release build
    # is running, then ensure setup neither overwrites the edit nor leaves a
    # dangling installation. The fake swift delegates to the real compiler.
    settings.write_bytes(original_settings)
    settings.chmod(0o640)
    fake_bin = home / 'fake-bin'
    fake_bin.mkdir()
    real_swift = shutil.which('swift')
    assert real_swift
    swift = fake_bin / 'swift'
    swift.write_text('#!/bin/sh\nprintf "%s\\n" "changed by another program" > "$FIXTURE_CHANGED_FILE"\n'
                     + 'exec ' + shlex.quote(real_swift) + ' "$@"\n')
    swift.chmod(0o700)
    race_env = env | {'PATH': str(fake_bin) + os.pathsep + env['PATH'], 'FIXTURE_CHANGED_FILE': str(settings)}
    race = subprocess.run(base + ['install', '--prefix', str(prefix), '--claude', str(fake_claude), '--no-launchd'],
                          cwd=project, env=race_env, capture_output=True)
    assert race.returncode != 0 and b'file changed during installation' in race.stderr
    assert settings.read_text() == 'changed by another program\n' and not prefix.exists()
    settings.write_bytes(original_settings)
    rc.write_bytes(original)
    race_env['FIXTURE_CHANGED_FILE'] = str(rc)
    race = subprocess.run(base + ['install', '--prefix', str(prefix), '--claude', str(fake_claude), '--no-launchd'],
                          cwd=project, env=race_env, capture_output=True)
    assert race.returncode != 0 and b'file changed during installation' in race.stderr
    assert rc.read_text() == 'changed by another program\n' and settings.read_bytes() == original_settings
    assert settings.stat().st_mode & 0o777 == 0o640 and not prefix.exists()

    # Exercise the online LaunchAgent upgrade rollback without touching the
    # real user launchd domain. Import the installer and replace only calls to
    # the absolute launchctl executable with a deterministic service model.
    launch_home = home / 'launch-agent-home'
    launch_prefix = launch_home / 'installation'
    launch_home.mkdir()
    launch_env = env | {
        'HOME': str(launch_home),
        'SAFE_CLAUDE_AGENT_SOCKET':
            str(launch_home / 'Library/Application Support/SafeClaude/fixture-agent.sock'),
    }
    subprocess.run(base + ['install', '--prefix', str(launch_prefix), '--claude', str(fake_claude),
                           '--no-shell', '--no-settings', '--no-launchd'],
                   cwd=project, env=launch_env, check=True, stdout=subprocess.DEVNULL)
    launch_manifest_path = launch_prefix / 'manifest.json'
    launch_manifest_before = json.loads(launch_manifest_path.read_text())
    launch_manifest_before['launchd'] = True
    launch_manifest_path.write_text(json.dumps(launch_manifest_before, indent=2))
    launch_manifest_path.chmod(0o600)

    launch_agents = launch_home / 'Library/LaunchAgents'
    launch_agents.mkdir(parents=True)
    agent_plist = launch_agents / 'local.safeclaude.agent.plist'
    menu_plist = launch_agents / 'local.safeclaude.menu.plist'
    launch_specs = {
        agent_plist: {'Label': 'local.safeclaude.agent',
                      'ProgramArguments': [str(launch_prefix / 'libexec/safe-claude-agent')]},
        menu_plist: {'Label': 'local.safeclaude.menu',
                     'ProgramArguments': ['/usr/bin/open', '-gj', str(launch_prefix / 'SafeClaude.app')]},
    }
    launch_snapshots = {}
    for path, spec_data in launch_specs.items():
        path.write_bytes(plistlib.dumps(spec_data))
        path.chmod(0o600)
        launch_snapshots[path] = path.read_bytes()

    module_spec = importlib.util.spec_from_file_location('safe_claude_setup_fixture', setup)
    setup_module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(setup_module)
    empty_hooks_update, empty_hooks_fragments = setup_module.settings_integrations(
        '{\"env\":{\"EXAMPLE\":\"value\"}}\n',
        Path('/tmp/safe-claude-setup-fixture'))
    empty_hooks_config = json.loads(empty_hooks_update)
    assert empty_hooks_config['hooks']['StopFailure']
    assert setup_module.remove_settings_fragments(
        empty_hooks_update, empty_hooks_fragments) == '{\"env\":{\"EXAMPLE\":\"value\"}}\n'
    setup_module.LAUNCH_FILE = agent_plist
    setup_module.UI_LAUNCH_FILE = menu_plist
    loaded_services = {'local.safeclaude.agent': True, 'local.safeclaude.menu': True}
    launchctl_calls = []
    bootstrap_calls = [0]
    real_run = subprocess.run

    def launchctl_run(command, *args, **kwargs):
        if isinstance(command, list) and command[:1] == ['/bin/launchctl']:
            action = command[1]
            label = command[2].rsplit('/', 1)[-1] if action == 'print' else Path(command[-1]).stem
            launchctl_calls.append((action, label))
            if action == 'print':
                return subprocess.CompletedProcess(command, 0 if loaded_services[label] else 113,
                                                   stdout='', stderr='')
            if action == 'bootout':
                loaded_services[label] = False
                return subprocess.CompletedProcess(command, 0, stdout='', stderr='')
            if action == 'bootstrap':
                bootstrap_calls[0] += 1
                if bootstrap_calls[0] == 1:
                    return subprocess.CompletedProcess(command, 37, stdout='', stderr='injected bootstrap failure')
                loaded_services[label] = True
                return subprocess.CompletedProcess(command, 0, stdout='', stderr='')
            raise AssertionError(command)
        if isinstance(command, list) and command[:1] == [str(launch_prefix / 'libexec/safe-claude')]:
            arguments = command[1:]
            if arguments[:1] == ['--socket']:
                arguments = arguments[2:]
            if arguments[0] == 'prepare-uninstall':
                return subprocess.CompletedProcess(command, 0,
                    stdout=b'{"decision":"allow","managedSessions":0}', stderr=b'')
            if arguments[0] in ('stop-ui', 'cancel-uninstall'):
                return subprocess.CompletedProcess(command, 0, stdout=b'', stderr=b'')
        return real_run(command, *args, **kwargs)

    with mock.patch.object(setup_module.subprocess, 'run', side_effect=launchctl_run):
        try:
            setup_module.upgrade(argparse.Namespace(prefix=str(launch_prefix)))
        except subprocess.CalledProcessError as error:
            assert error.returncode == 37
        else:
            raise AssertionError('injected LaunchAgent bootstrap failure did not fail the upgrade')
    assert launch_manifest_path.read_bytes() == json.dumps(launch_manifest_before, indent=2).encode()
    assert all(path.read_bytes() == snapshot for path, snapshot in launch_snapshots.items())
    assert loaded_services == {'local.safeclaude.agent': True, 'local.safeclaude.menu': True}
    assert bootstrap_calls[0] == 3  # failed new Agent, then both old services restarted
    assert [label for action, label in launchctl_calls if action == 'bootstrap'] == [
        'local.safeclaude.agent', 'local.safeclaude.menu', 'local.safeclaude.agent']
    assert not list(launch_home.glob('.installation.upgrade-*'))
    print('isolated setup: install, staged upgrade, bootstrap failure rollback, exact restore and concurrent-edit protection passed')
