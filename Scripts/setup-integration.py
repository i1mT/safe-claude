#!/usr/bin/env python3
"""Create a reversible local shim and optional user launchd integration."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
PACKAGED_APP = next(
    (parent for parent in Path(__file__).resolve().parents if parent.suffix == '.app'),
    None,
)
FROZEN_RESOURCES = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else None
PACKAGED_INSTALLER = (
    FROZEN_RESOURCES if FROZEN_RESOURCES else
    PACKAGED_APP / 'Contents/Resources/Installer' if PACKAGED_APP else None
)
PROJECT = SCRIPT_DIRECTORY.parent if SCRIPT_DIRECTORY.name == 'Scripts' else None
HOME = Path.home()
DEFAULT_PREFIX = HOME / 'Library/Application Support/SafeClaude/installation'
LAUNCH_FILE = HOME / 'Library/LaunchAgents/local.safeclaude.agent.plist'
UI_LAUNCH_FILE = HOME / 'Library/LaunchAgents/local.safeclaude.menu.plist'
SHELL_FILE = HOME / '.zshrc'
CLAUDE_SETTINGS = Path(os.environ.get('CLAUDE_CONFIG_DIR') or (HOME / '.claude')).expanduser().absolute() / 'settings.json'
BEGIN = '# >>> safe-claude managed >>>\n'
END = '# <<< safe-claude managed <<<\n'


def agent_command(executable, *arguments):
    socket = os.environ.get(
        'SAFE_CLAUDE_AGENT_SOCKET',
        str(HOME / 'Library/Application Support/SafeClaude/agent.sock'))
    return [str(executable), '--socket', socket, *arguments]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def executable_identity(path):
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Claude executable is not a regular file')
    seconds, nanoseconds = divmod(info.st_mtime_ns, 1_000_000_000)
    return {'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size,
            'modifiedSeconds': seconds, 'modifiedNanoseconds': nanoseconds}

def copy_time_status_service(binaries, app_contents):
    helper_directory = app_contents / 'Library/PrivilegedHelperTools'
    helper_directory.mkdir(parents=True)
    shutil.copy2(binaries / 'safe-claude-time-status',
                 helper_directory / 'safe-claude-time-status')
    daemon_directory = app_contents / 'Library/LaunchDaemons'
    daemon_directory.mkdir(parents=True)
    plist = (PACKAGED_INSTALLER / 'local.safeclaude.time-status.plist'
             if PACKAGED_INSTALLER else PROJECT / 'Sources/GuardApp/local.safeclaude.time-status.plist')
    shutil.copy2(plist,
                 daemon_directory / 'local.safeclaude.time-status.plist')


def source_app_for(args):
    candidate = getattr(args, 'source_app', None)
    app = Path(candidate).expanduser().resolve() if candidate else PACKAGED_APP
    if app is None:
        return None
    if not app.is_dir() or app.suffix != '.app':
        raise ValueError('source app must be a SafeClaude .app bundle')
    contents = app / 'Contents'
    info_path = contents / 'Info.plist'
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError) as error:
        raise ValueError('source app has no valid Info.plist') from error
    if (info.get('CFBundleExecutable') != 'SafeClaudeApp' or
            info.get('CFBundlePackageType') != 'APPL'):
        raise ValueError('source app is not a SafeClaude application bundle')
    required = [
        contents / 'MacOS/SafeClaudeApp',
        contents / 'MacOS/safe-claude',
        contents / 'MacOS/safe-claude-agent',
        contents / 'MacOS/SafeClaude_GuardCore.bundle/claude-model-lifecycle.json',
        contents / 'Library/PrivilegedHelperTools/safe-claude-time-status',
        contents / 'Library/LaunchDaemons/local.safeclaude.time-status.plist',
        contents / 'Library/SystemExtensions/SafeClaudeDNS.systemextension/Contents/Info.plist',
        contents / 'Library/SystemExtensions/SafeClaudeDNS.systemextension/Contents/MacOS/SafeClaudeDNS',
    ]
    if not all(path.is_file() for path in required):
        raise ValueError('source app is missing a required executable or resource')
    installer = app / 'Contents/Resources/Installer'
    if not all((installer / path).is_file() for path in (
            'setup-integration.py', 'safe-claude-setup',
            'THIRD_PARTY_NOTICES.txt',
            'integration/claude', 'integration/process-wrapper',
            'local.safeclaude.time-status.plist')):
        raise ValueError('source app is missing packaged installation resources')
    if not os.access(installer / 'safe-claude-setup', os.X_OK):
        raise ValueError('source app setup runtime is not executable')
    return app


def build_or_use_app(args):
    app = source_app_for(args)
    if app is not None:
        return app, app / 'Contents/MacOS'
    if PROJECT is None:
        raise ValueError('packaged setup cannot locate its source app')
    subprocess.run(['swift', 'build', '-c', 'release'], cwd=PROJECT, check=True)
    binaries = Path(subprocess.check_output(
        ['swift', 'build', '-c', 'release', '--show-bin-path'], cwd=PROJECT, text=True).strip())
    return None, binaries


def integration_asset(name):
    base = PACKAGED_INSTALLER if PACKAGED_INSTALLER else PROJECT / 'Scripts'
    return base / 'integration' / name


def supported_install_manifest(paths):
    expected = {'bin/claude', 'libexec/safe-claude', 'libexec/safe-claude-agent',
                'libexec/process-wrapper', 'libexec/claude-target',
                'SafeClaude.app/Contents/MacOS/SafeClaudeApp', 'SafeClaude.app/Contents/Info.plist'}
    current = expected | {'libexec/claude-identity.json'}
    app_resource = 'SafeClaude.app/Contents/MacOS/SafeClaude_GuardCore.bundle/claude-model-lifecycle.json'
    libexec_resource = 'libexec/SafeClaude_GuardCore.bundle/claude-model-lifecycle.json'
    helper = 'SafeClaude.app/Contents/Library/PrivilegedHelperTools/safe-claude-time-status'
    daemon = 'SafeClaude.app/Contents/Library/LaunchDaemons/local.safeclaude.time-status.plist'
    service_files = {helper, daemon}
    legacy = (expected, current, expected | {app_resource}, current | {app_resource},
              expected | {app_resource, libexec_resource},
              current | {app_resource, libexec_resource})
    if paths in legacy or any(paths == allowed | service_files for allowed in legacy):
        return True

    fixed = current | {libexec_resource}
    app_paths = paths - fixed
    required_app_paths = {
        *expected,
        app_resource,
        helper,
        daemon,
        'SafeClaude.app/Contents/MacOS/safe-claude',
        'SafeClaude.app/Contents/MacOS/safe-claude-agent',
        'SafeClaude.app/Contents/Library/SystemExtensions/SafeClaudeDNS.systemextension/Contents/Info.plist',
        'SafeClaude.app/Contents/Library/SystemExtensions/SafeClaudeDNS.systemextension/Contents/MacOS/SafeClaudeDNS',
        'SafeClaude.app/Contents/Resources/Installer/setup-integration.py',
        'SafeClaude.app/Contents/Resources/Installer/safe-claude-setup',
        'SafeClaude.app/Contents/Resources/Installer/LICENSE.python.txt',
        'SafeClaude.app/Contents/Resources/Installer/THIRD_PARTY_NOTICES.txt',
        'SafeClaude.app/Contents/Resources/Installer/integration/claude',
        'SafeClaude.app/Contents/Resources/Installer/integration/process-wrapper',
        'SafeClaude.app/Contents/Resources/Installer/local.safeclaude.time-status.plist',
    }
    if not required_app_paths <= paths or not app_paths:
        return False
    return all(path.startswith('SafeClaude.app/Contents/') for path in app_paths)


def validate_manifest_paths(paths):
    for relative in paths:
        parts = Path(relative).parts
        if (Path(relative).is_absolute() or Path(relative).as_posix() != relative or
                not parts or any(part in ('', '.', '..') for part in parts)):
            raise ValueError('invalid installation manifest path')
    if not supported_install_manifest(set(paths)):
        raise ValueError('invalid installation manifest')


def shell_block(prefix):
    path = str(prefix / 'bin')
    if '\n' in path or '\r' in path or ':' in path:
        raise ValueError('invalid character in installation path')
    # Quoting applies to literal path portions; PATH itself is expanded by zsh.
    q = shlex.quote(path)
    return BEGIN + f'export PATH={q}:"$PATH"\n' + END


def regular_or_absent(path):
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISREG(mode):
        raise ValueError(f'not a regular file: {path}')


def write_atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.safe-claude-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def require_unchanged(path, original, existed, expected_mode=None):
    regular_or_absent(path)
    if (path.exists() != existed or
        (existed and (path.read_bytes() != original or
                      (expected_mode is not None and stat.S_IMODE(path.stat().st_mode) != expected_mode)))):
        raise ValueError(f'file changed during installation: {path}')


def settings_fragment(prefix, has_other_fields):
    wrapper = str(prefix / 'libexec/process-wrapper')
    return (',' if has_other_fields else '') + '\n  "processWrapper": ' + json.dumps(wrapper, ensure_ascii=False)


def json_source_tree(text):
    decoder = json.JSONDecoder()

    def skip_space(index):
        while index < len(text) and text[index] in ' \t\r\n':
            index += 1
        return index

    def parse(index):
        index = skip_space(index)
        start = index
        if index >= len(text):
            raise ValueError('invalid Claude settings JSON')
        if text[index] == '{':
            children = {}
            index = skip_space(index + 1)
            if text[index] == '}':
                return {'kind': 'object', 'start': start, 'end': index + 1, 'children': children}
            while True:
                index = skip_space(index)
                key, key_end = decoder.raw_decode(text, index)
                if not isinstance(key, str):
                    raise ValueError('invalid Claude settings object key')
                index = skip_space(key_end)
                if index >= len(text) or text[index] != ':':
                    raise ValueError('invalid Claude settings object')
                value = parse(index + 1)
                if key in children:
                    raise ValueError('duplicate key in Claude settings')
                children[key] = value
                index = skip_space(value['end'])
                if index < len(text) and text[index] == '}':
                    return {'kind': 'object', 'start': start, 'end': index + 1, 'children': children}
                if index >= len(text) or text[index] != ',':
                    raise ValueError('invalid Claude settings object')
                index += 1
        if text[index] == '[':
            children = []
            index = skip_space(index + 1)
            if index < len(text) and text[index] == ']':
                return {'kind': 'array', 'start': start, 'end': index + 1, 'children': children}
            while True:
                value = parse(index)
                children.append(value)
                index = skip_space(value['end'])
                if index < len(text) and text[index] == ']':
                    return {'kind': 'array', 'start': start, 'end': index + 1, 'children': children}
                if index >= len(text) or text[index] != ',':
                    raise ValueError('invalid Claude settings array')
                index += 1
        value, end = decoder.raw_decode(text, index)
        kind = 'string' if isinstance(value, str) else 'primitive'
        return {'kind': kind, 'start': start, 'end': end}

    root = parse(0)
    if root['kind'] != 'object' or skip_space(root['end']) != len(text):
        raise ValueError('Claude settings must be one JSON object')
    return root


def trailing_space_start(text, node):
    index = node['end'] - 1
    while index > node['start'] and text[index - 1] in ' \t\r\n':
        index -= 1
    return index


def settings_integrations(content, prefix):
    config = parse_settings(content)
    if 'processWrapper' in config:
        raise ValueError('Claude settings already contain processWrapper')
    env_config = config.get('env', {})
    if not isinstance(env_config, dict):
        raise ValueError('Claude settings env must be an object')
    if 'CLAUDE_CODE_PROCESS_WRAPPER' in env_config:
        raise ValueError('Claude settings already contain CLAUDE_CODE_PROCESS_WRAPPER')

    wrapper = str(prefix / 'libexec/process-wrapper')
    entry = failure_event_hook_entry(prefix)
    tree = json_source_tree(content)
    root_fields = tree['children']
    hooks_node = root_fields.get('hooks')
    if hooks_node is None:
        fragment = (',' if config else '') + '\n  "processWrapper": ' + \
            json.dumps(wrapper, ensure_ascii=False) + ',\n  "hooks": ' + \
            json.dumps({'StopFailure': [entry]}, ensure_ascii=False, separators=(',', ':'))
        position = trailing_space_start(content, tree)
        updated = content[:position] + fragment + content[position:]
        parse_settings(updated)
        return updated, [fragment]

    if hooks_node['kind'] != 'object' or not isinstance(config.get('hooks'), dict):
        raise ValueError('Claude settings hooks must be an object')
    stop_failure_node = hooks_node['children'].get('StopFailure')
    hook_json = json.dumps(entry, ensure_ascii=False, separators=(',', ':'))
    edits = []
    fragments = []
    if stop_failure_node is None:
        hooks_config = config['hooks']
        fragment = (',' if hooks_config else '') + '\n    "StopFailure": [' + hook_json + ']'
        edits.append((trailing_space_start(content, hooks_node), fragment))
        fragments.append(fragment)
    else:
        if stop_failure_node['kind'] != 'array' or not isinstance(config['hooks']['StopFailure'], list):
            raise ValueError('Claude settings hooks.StopFailure must be an array')
        fragment = (',' if config['hooks']['StopFailure'] else '') + '\n      ' + hook_json
        edits.append((trailing_space_start(content, stop_failure_node), fragment))
        fragments.append(fragment)
    wrapper_fragment = settings_fragment(prefix, bool(config))
    edits.append((trailing_space_start(content, tree), wrapper_fragment))
    fragments.append(wrapper_fragment)
    updated = content
    for position, fragment in sorted(edits, reverse=True):
        updated = updated[:position] + fragment + updated[position:]
    parse_settings(updated)
    return updated, fragments


def failure_event_hook_entry(prefix):
    hook_command = shlex.quote(str(prefix / 'libexec/safe-claude')) + ' hook-event'
    matcher = '|'.join((
        'rate_limit', 'overloaded', 'authentication_failed', 'oauth_org_not_allowed',
        'account_on_hold', 'billing_error', 'invalid_request', 'model_not_found',
        'server_error', 'max_output_tokens', 'cloud_credential_error', 'unknown',
    ))
    return {'matcher': matcher, 'hooks': [{'type': 'command', 'command': hook_command}]}


def failure_event_hook_present(config, prefix):
    command = shlex.quote(str(prefix / 'libexec/safe-claude')) + ' hook-event'
    hooks = config.get('hooks')
    if not isinstance(hooks, dict) or not isinstance(hooks.get('StopFailure'), list):
        return False
    return any(
        isinstance(group, dict) and isinstance(group.get('hooks'), list) and
        any(isinstance(hook, dict) and hook.get('type') == 'command' and
            hook.get('command') == command for hook in group['hooks'])
        for group in hooks['StopFailure']
    )


def add_failure_event_hook(content, prefix):
    config = parse_settings(content)
    entry = failure_event_hook_entry(prefix)
    tree = json_source_tree(content)
    hooks_node = tree['children'].get('hooks')
    hook_json = json.dumps(entry, ensure_ascii=False, separators=(',', ':'))
    if hooks_node is None:
        fragment = (',' if config else '') + '\n  "hooks": ' + \
            json.dumps({'StopFailure': [entry]}, ensure_ascii=False, separators=(',', ':'))
        position = trailing_space_start(content, tree)
        updated = content[:position] + fragment + content[position:]
    else:
        if hooks_node['kind'] != 'object' or not isinstance(config.get('hooks'), dict):
            raise ValueError('Claude settings hooks must be an object')
        stop_node = hooks_node['children'].get('StopFailure')
        if stop_node is None:
            fragment = (',' if config['hooks'] else '') + '\n    "StopFailure": [' + hook_json + ']'
            position = trailing_space_start(content, hooks_node)
        else:
            if stop_node['kind'] != 'array' or not isinstance(config['hooks'].get('StopFailure'), list):
                raise ValueError('Claude settings hooks.StopFailure must be an array')
            fragment = (',' if config['hooks']['StopFailure'] else '') + '\n      ' + hook_json
            position = trailing_space_start(content, stop_node)
        updated = content[:position] + fragment + content[position:]
    parse_settings(updated)
    return updated, [fragment]


def installed_settings_fragments(manifest):
    fragments = manifest.get('settingsFragments')
    if fragments is None:
        legacy = manifest.get('settingsFragment')
        return [legacy] if isinstance(legacy, str) else None
    if not isinstance(fragments, list) or not fragments or not all(
            isinstance(fragment, str) and fragment for fragment in fragments):
        return None
    return fragments


def remove_settings_fragments(content, fragments):
    restored = content
    for fragment in fragments:
        if restored.count(fragment) != 1:
            raise ValueError('Claude settings integration changed; remove it manually')
        restored = restored.replace(fragment, '', 1)
    parse_settings(restored)
    return restored


def parse_settings(content):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate key in Claude settings')
            result[key] = value
        return result
    value = json.loads(content, object_pairs_hook=unique_pairs)
    if not isinstance(value, dict): raise ValueError('Claude settings must be an object')
    return value


def install(args):
    prefix = Path(args.prefix).expanduser().absolute()
    if prefix.exists() or prefix.is_symlink():
        raise ValueError(f'installation path already exists: {prefix}')
    if os.environ.get('CLAUDE_CODE_PROCESS_WRAPPER'):
        raise ValueError('current environment already defines CLAUDE_CODE_PROCESS_WRAPPER')
    target_input = args.claude or shutil.which('claude')
    if not target_input: raise ValueError('Claude executable not found')
    target = Path(target_input).expanduser().absolute()
    if not target.is_file() or not os.access(target, os.X_OK) or '\n' in str(target):
        raise ValueError('Claude executable is invalid')
    selected_identity = executable_identity(target)
    version_env = {'PATH': '/usr/bin:/bin', 'HOME': str(HOME), 'LANG': 'C'}
    version_output = subprocess.run([str(target), '--version'], env=version_env, capture_output=True,
                                    text=True, timeout=5, check=True).stdout.strip()
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:\s|$)', version_output)
    if not match or tuple(map(int, match.groups())) < (2, 1, 210):
        raise ValueError('Claude Code 2.1.210 or later is required for processWrapper')
    if not args.no_launchd:
        for launch_file in (LAUNCH_FILE, UI_LAUNCH_FILE):
            if launch_file.exists() or launch_file.is_symlink():
                raise ValueError(f'launch agent already exists: {launch_file}')
    old_shell = None
    old_settings = None
    settings_existed = False
    settings_fragments = None
    updated_settings_text = None
    settings_mode = 0o600
    shell_mode = 0o600
    if not args.no_settings:
        regular_or_absent(CLAUDE_SETTINGS)
        settings_existed = CLAUDE_SETTINGS.exists()
        if settings_existed: settings_mode = stat.S_IMODE(CLAUDE_SETTINGS.stat().st_mode)
        old_settings = CLAUDE_SETTINGS.read_bytes() if settings_existed else b'{}\n'
        if len(old_settings) > 2_000_000: raise ValueError('Claude settings file is too large')
        settings_text = old_settings.decode('utf-8')
        updated_settings_text, settings_fragments = settings_integrations(settings_text, prefix)
    shell_existed = False
    if not args.no_shell:
        regular_or_absent(SHELL_FILE)
        shell_existed = SHELL_FILE.exists()
        if shell_existed: shell_mode = stat.S_IMODE(SHELL_FILE.stat().st_mode)
        old_shell = SHELL_FILE.read_bytes() if shell_existed else b''
        if BEGIN.encode() in old_shell or END.encode() in old_shell:
            raise ValueError('a SafeClaude shell block already exists')
        old_shell.decode('utf-8')
    source_app, binaries = build_or_use_app(args)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.safe-claude-stage-', dir=prefix.parent))
    installed = False
    shell_written = False
    settings_written = False
    launch_written = []
    installed_settings = None
    installed_shell = None
    try:
        (staging / 'bin').mkdir()
        (staging / 'libexec').mkdir()
        app_contents = staging / 'SafeClaude.app/Contents'
        if source_app:
            shutil.copytree(source_app, staging / 'SafeClaude.app')
        else:
            (app_contents / 'MacOS').mkdir(parents=True)
            shutil.copy2(binaries / 'SafeClaudeApp', app_contents / 'MacOS/SafeClaudeApp')
        resource_bundle = binaries / 'SafeClaude_GuardCore.bundle'
        if not resource_bundle.is_dir():
            raise ValueError(f'missing Swift package resources: {resource_bundle}')
        if not source_app:
            shutil.copytree(resource_bundle, app_contents / 'MacOS' / resource_bundle.name)
        shutil.copytree(resource_bundle, staging / 'libexec' / resource_bundle.name)
        if not source_app:
            copy_time_status_service(binaries, app_contents)
            with (app_contents / 'Info.plist').open('wb') as stream:
                plistlib.dump({'CFBundleName': 'SafeClaude', 'CFBundleIdentifier': 'local.safeclaude.app',
                               'CFBundleExecutable': 'SafeClaudeApp', 'CFBundlePackageType': 'APPL',
                               'CFBundleShortVersionString': '0.1.0', 'CFBundleVersion': '1',
                               'LSMinimumSystemVersion': '13.0', 'LSUIElement': True}, stream)
        for name in ('safe-claude', 'safe-claude-agent'):
            shutil.copy2(binaries / name, staging / 'libexec' / name)
        shutil.copy2(integration_asset('claude'), staging / 'bin/claude')
        shutil.copy2(integration_asset('process-wrapper'), staging / 'libexec/process-wrapper')
        (staging / 'libexec/claude-target').write_text(str(target) + '\n')
        os.chmod(staging / 'libexec/claude-target', 0o600)
        (staging / 'libexec/claude-identity.json').write_text(json.dumps(selected_identity, sort_keys=True))
        os.chmod(staging / 'libexec/claude-identity.json', 0o600)
        files = {str(p.relative_to(staging)): digest(p) for p in staging.rglob('*') if p.is_file()}
        (staging / 'manifest.json').write_text(json.dumps({'version': 1, 'files': files, 'shell': not args.no_shell,
            'shellExisted': shell_existed, 'shellAddedNewline': bool(old_shell and not old_shell.endswith(b'\n')),
            'settings': not args.no_settings, 'settingsPath': str(CLAUDE_SETTINGS) if not args.no_settings else None,
            'settingsExisted': settings_existed, 'settingsFragments': settings_fragments,
            'launchd': not args.no_launchd}, indent=2))
        os.chmod(staging / 'manifest.json', 0o600)
        if executable_identity(target) != selected_identity:
            raise ValueError('Claude executable changed during installation')
        os.rename(staging, prefix)
        installed = True
        if old_settings is not None:
            # No backup of the settings file is written: it may contain secrets.
            require_unchanged(CLAUDE_SETTINGS, old_settings, settings_existed, settings_mode)
            installed_settings = updated_settings_text.encode()
            write_atomic(CLAUDE_SETTINGS, installed_settings, settings_mode)
            settings_written = True
        if not args.no_launchd:
            spec = {'Label': 'local.safeclaude.agent', 'ProgramArguments': [str(prefix / 'libexec/safe-claude-agent')],
                    'RunAtLoad': True, 'KeepAlive': True, 'ProcessType': 'Background'}
            ui_spec = {'Label': 'local.safeclaude.menu', 'ProgramArguments': ['/usr/bin/open', '-gj', str(prefix / 'SafeClaude.app')],
                       'RunAtLoad': True}
            LAUNCH_FILE.parent.mkdir(parents=True, exist_ok=True)
            for launch_file, definition in ((LAUNCH_FILE, spec), (UI_LAUNCH_FILE, ui_spec)):
                fd = os.open(launch_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream: plistlib.dump(definition, stream)
                launch_written.append(launch_file)
                subprocess.run(['/bin/launchctl', 'bootstrap', f'gui/{os.getuid()}', str(launch_file)], check=True)
        if old_shell is not None:
            separator = b'\n' if old_shell and not old_shell.endswith(b'\n') else b''
            require_unchanged(SHELL_FILE, old_shell, shell_existed, shell_mode)
            installed_shell = old_shell + separator + shell_block(prefix).encode()
            write_atomic(SHELL_FILE, installed_shell, shell_mode)
            shell_written = True
        print(f'installed: {prefix}')
        print(f"菜单栏应用：{prefix / 'SafeClaude.app'}")
        print('重新打开终端以加载 PATH。')
    except Exception as error:
        # A concurrent edit after our write may contain the user's new data.
        # Keep the installation and integrations intact rather than replacing
        # that edit or leaving a wrapper pointing at a deleted executable.
        try:
            if shell_written: require_unchanged(SHELL_FILE, installed_shell, True, shell_mode)
            if settings_written: require_unchanged(CLAUDE_SETTINGS, installed_settings, True, settings_mode)
        except (OSError, ValueError) as conflict:
            raise ValueError(f'installation interrupted and configuration changed; '
                             f'installation preserved at {prefix}: {conflict}') from error
        if shell_written:
            if shell_existed: write_atomic(SHELL_FILE, old_shell or b'', shell_mode)
            else: SHELL_FILE.unlink(missing_ok=True)
        if settings_written:
            if settings_existed: write_atomic(CLAUDE_SETTINGS, old_settings or b'{}', settings_mode)
            else: CLAUDE_SETTINGS.unlink(missing_ok=True)
        for launch_file in reversed(launch_written):
            subprocess.run(['/bin/launchctl', 'bootout', f'gui/{os.getuid()}', str(launch_file)], capture_output=True)
            launch_file.unlink(missing_ok=True)
        if installed:
            subprocess.run(agent_command(prefix / 'libexec/safe-claude', 'stop-ui', '--',
                                         str(prefix / 'SafeClaude.app/Contents/MacOS/SafeClaudeApp')),
                           capture_output=True)
        if installed: shutil.rmtree(prefix)
        raise
    finally:
        if staging.exists(): shutil.rmtree(staging)


def upgrade(args):
    prefix = Path(args.prefix).expanduser().absolute()
    manifest_path = prefix / 'manifest.json'
    regular_or_absent(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('version') != 1 or not isinstance(manifest.get('files'), dict):
        raise ValueError('unrecognized installation')
    validate_manifest_paths(manifest['files'])
    for relative, expected in manifest['files'].items():
        path = prefix / relative
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError(f'installed file changed: {path}; leaving installation intact')
    expected_paths = set(manifest['files']) | {'manifest.json'}
    actual_paths = {str(p.relative_to(prefix)) for p in prefix.rglob('*') if p.is_file() or p.is_symlink()}
    if actual_paths != expected_paths:
        raise ValueError('installation contains unexpected files; leaving installation intact')

    target_file = prefix / 'libexec/claude-target'
    target = Path(target_file.read_text().strip())
    selected_identity = executable_identity(target)
    identity_file = prefix / 'libexec/claude-identity.json'
    if identity_file.exists() and json.loads(identity_file.read_text()) != selected_identity:
        raise ValueError('Claude executable changed since installation; repair the selected target first')
    version_output = subprocess.run([str(target), '--version'],
        env={'PATH': '/usr/bin:/bin', 'HOME': str(HOME), 'LANG': 'C'},
        capture_output=True, text=True, timeout=5, check=True).stdout.strip()
    version = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:\s|$)', version_output)
    if not version or tuple(map(int, version.groups())) < (2, 1, 210):
        raise ValueError('Claude Code 2.1.210 or later is required for processWrapper')

    shell_snapshot = None
    if manifest.get('shell'):
        regular_or_absent(SHELL_FILE)
        shell_snapshot = SHELL_FILE.read_bytes()
        if shell_snapshot.decode('utf-8').count(shell_block(prefix)) != 1:
            raise ValueError('shell integration changed; repair it before upgrading')
    settings_snapshot = None
    settings_mode = None
    settings_updated_text = None
    settings_updated_bytes = None
    settings_fragments = None
    settings_written = False
    if manifest.get('settings'):
        settings_path = Path(manifest['settingsPath'])
        regular_or_absent(settings_path)
        settings_mode = stat.S_IMODE(settings_path.stat().st_mode)
        settings_snapshot = settings_path.read_bytes()
        settings_content = settings_snapshot.decode('utf-8')
        settings = parse_settings(settings_content)
        settings_fragments = installed_settings_fragments(manifest)
        if (settings_fragments is None or
                settings.get('processWrapper') != str(prefix / 'libexec/process-wrapper') or
                any(settings_content.count(fragment) != 1 for fragment in settings_fragments)):
            raise ValueError('Claude wrapper settings changed; repair them before upgrading')
        if not failure_event_hook_present(settings, prefix):
            settings_updated_text, added_fragments = add_failure_event_hook(settings_content, prefix)
            settings_fragments = settings_fragments + added_fragments
            settings_updated_bytes = settings_updated_text.encode()
            manifest['settingsFragments'] = settings_fragments
            manifest.pop('settingsFragment', None)
    launch_snapshots = {}
    launch_labels = {
        LAUNCH_FILE: 'local.safeclaude.agent',
        UI_LAUNCH_FILE: 'local.safeclaude.menu',
    }

    def run_launchctl(action, launch_file):
        return subprocess.run(['/bin/launchctl', action, f'gui/{os.getuid()}', str(launch_file)],
                              capture_output=True, text=True, timeout=5)

    def service_loaded(launch_file):
        result = subprocess.run(
            ['/bin/launchctl', 'print', f'gui/{os.getuid()}/{launch_labels[launch_file]}'],
            capture_output=True, text=True, timeout=5)
        return result.returncode == 0

    if manifest.get('launchd'):
        for launch_file, label, arguments in (
            (LAUNCH_FILE, 'local.safeclaude.agent', [str(prefix / 'libexec/safe-claude-agent')]),
            (UI_LAUNCH_FILE, 'local.safeclaude.menu', ['/usr/bin/open', '-gj', str(prefix / 'SafeClaude.app')])):
            regular_or_absent(launch_file)
            if not launch_file.is_file():
                raise ValueError(f'launch agent is missing: {launch_file}')
            snapshot = launch_file.read_bytes()
            spec = plistlib.loads(snapshot)
            if spec.get('Label') != label or spec.get('ProgramArguments') != arguments:
                raise ValueError('launch agent changed; repair it before upgrading')
            if not service_loaded(launch_file):
                raise ValueError(f'launch agent is not loaded; start it before upgrading: {launch_file}')
            launch_snapshots[launch_file] = snapshot

    def prepare_staged_tree():
        source_app, binaries = build_or_use_app(args)
        stage = Path(tempfile.mkdtemp(prefix='.safe-claude-upgrade-', dir=prefix.parent))
        try:
            (stage / 'bin').mkdir()
            (stage / 'libexec').mkdir()
            app_contents = stage / 'SafeClaude.app/Contents'
            if source_app:
                shutil.copytree(source_app, stage / 'SafeClaude.app')
            else:
                (app_contents / 'MacOS').mkdir(parents=True)
                shutil.copy2(binaries / 'SafeClaudeApp', app_contents / 'MacOS/SafeClaudeApp')
            resource_bundle = binaries / 'SafeClaude_GuardCore.bundle'
            if not resource_bundle.is_dir():
                raise ValueError(f'missing Swift package resources: {resource_bundle}')
            if not source_app:
                shutil.copytree(resource_bundle, app_contents / 'MacOS' / resource_bundle.name)
            shutil.copytree(resource_bundle, stage / 'libexec' / resource_bundle.name)
            if not source_app:
                copy_time_status_service(binaries, app_contents)
                with (app_contents / 'Info.plist').open('wb') as stream:
                    plistlib.dump({'CFBundleName': 'SafeClaude', 'CFBundleIdentifier': 'local.safeclaude.app',
                                   'CFBundleExecutable': 'SafeClaudeApp', 'CFBundlePackageType': 'APPL',
                                   'CFBundleShortVersionString': '0.1.0', 'CFBundleVersion': '1',
                                   'LSMinimumSystemVersion': '13.0', 'LSUIElement': True}, stream)
            for name in ('safe-claude', 'safe-claude-agent'):
                shutil.copy2(binaries / name, stage / 'libexec' / name)
            shutil.copy2(integration_asset('claude'), stage / 'bin/claude')
            shutil.copy2(integration_asset('process-wrapper'), stage / 'libexec/process-wrapper')
            (stage / 'libexec/claude-target').write_text(str(target) + '\n')
            os.chmod(stage / 'libexec/claude-target', 0o600)
            (stage / 'libexec/claude-identity.json').write_text(json.dumps(selected_identity, sort_keys=True))
            os.chmod(stage / 'libexec/claude-identity.json', 0o600)
            metadata = {key: manifest.get(key) for key in
                        ('shell', 'shellExisted', 'shellAddedNewline', 'settings', 'settingsPath',
                         'settingsExisted', 'settingsFragments', 'settingsFragment', 'launchd')}
            if metadata['settingsFragments'] is not None:
                metadata.pop('settingsFragment', None)
            files = {str(path.relative_to(stage)): digest(path)
                     for path in stage.rglob('*') if path.is_file()}
            (stage / 'manifest.json').write_text(
                json.dumps({'version': 1, 'files': files, **metadata}, indent=2))
            os.chmod(stage / 'manifest.json', 0o600)
            if executable_identity(target) != selected_identity:
                raise ValueError('Claude executable changed during upgrade')
            return stage
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise

    backup = prefix.parent / f'.{prefix.name}.upgrade-backup-{os.getpid()}'
    if backup.exists() or backup.is_symlink():
        raise ValueError(f'upgrade recovery directory already exists: {backup}')
    drain_started = False
    old_cli = prefix / 'libexec/safe-claude'
    status = subprocess.run(agent_command(old_cli, 'prepare-uninstall'),
                            capture_output=True, timeout=5)
    if status.returncode == 0:
        drain_started = True
        try:
            result = json.loads(status.stdout)
        except ValueError:
            subprocess.run(agent_command(old_cli, 'cancel-uninstall'),
                           capture_output=True, timeout=5)
            raise ValueError('Agent returned an invalid upgrade status')
        if result.get('decision') != 'allow' or result.get('managedSessions') != 0:
            subprocess.run(agent_command(old_cli, 'cancel-uninstall'),
                           capture_output=True, timeout=5)
            raise ValueError('managed sessions are active or unavailable; close them before upgrading')
        if not manifest.get('launchd'):
            subprocess.run(agent_command(old_cli, 'cancel-uninstall'),
                           capture_output=True, timeout=5)
            raise ValueError('Agent is running without the managed LaunchAgent; stop it before upgrading')
    else:
        journal = HOME / 'Library/Application Support/SafeClaude/sessions.json'
        regular_or_absent(journal)
        if journal.exists() and json.loads(journal.read_text()) != []:
            raise ValueError('Agent is offline with recorded sessions; restart it before upgrading')

    try:
        staging = prepare_staged_tree()
    except Exception:
        if drain_started:
            subprocess.run(agent_command(old_cli, 'cancel-uninstall'),
                           capture_output=True, timeout=5)
        raise

    bootout_attempted = []
    booted_out = []
    bootstrap_attempted = []

    def cancel_agent_drain():
        cli = prefix / 'libexec/safe-claude'
        for _ in range(20):
            result = subprocess.run(agent_command(cli, 'cancel-uninstall'),
                                    capture_output=True, timeout=2)
            if result.returncode == 0:
                return True
            time.sleep(0.1)
        return False

    try:
        subprocess.run(agent_command(old_cli, 'stop-ui', '--',
                        str(prefix / 'SafeClaude.app/Contents/MacOS/SafeClaudeApp')),
                       check=True, timeout=5)
        for launch_file in (UI_LAUNCH_FILE, LAUNCH_FILE) if manifest.get('launchd') else ():
            require_unchanged(launch_file, launch_snapshots[launch_file], True, 0o600)
            bootout_attempted.append(launch_file)
            result = run_launchctl('bootout', launch_file)
            if result.returncode != 0 and service_loaded(launch_file):
                raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
            if not service_loaded(launch_file):
                booted_out.append(launch_file)

        if shell_snapshot is not None:
            require_unchanged(SHELL_FILE, shell_snapshot, True)
        if settings_snapshot is not None:
            require_unchanged(settings_path, settings_snapshot, True)
        for launch_file, snapshot in launch_snapshots.items():
            require_unchanged(launch_file, snapshot, True, 0o600)
        os.rename(prefix, backup)
        os.rename(staging, prefix)
        staging = None
        for launch_file in (LAUNCH_FILE, UI_LAUNCH_FILE) if manifest.get('launchd') else ():
            bootstrap_attempted.append(launch_file)
            result = run_launchctl('bootstrap', launch_file)
            if result.returncode != 0 and not service_loaded(launch_file):
                raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
        if settings_updated_bytes is not None:
            require_unchanged(settings_path, settings_snapshot, True, settings_mode)
            write_atomic(settings_path, settings_updated_bytes, settings_mode)
            settings_written = True
        print(f'upgraded: {prefix}')
        try:
            shutil.rmtree(backup)
        except OSError as cleanup_error:
            print(f'upgrade backup preserved at {backup}: {cleanup_error}')
    except Exception as upgrade_error:
        recovery_errors = []
        if settings_written:
            try:
                require_unchanged(settings_path, settings_updated_bytes, True, settings_mode)
                write_atomic(settings_path, settings_snapshot, settings_mode)
                settings_written = False
            except (OSError, ValueError) as restore_error:
                recovery_errors.append(f'could not restore previous Claude settings: {restore_error}')
        for launch_file in reversed(bootstrap_attempted):
            result = run_launchctl('bootout', launch_file)
            if service_loaded(launch_file):
                recovery_errors.append(f'new launchd service remains loaded: {launch_labels[launch_file]}')
        failed = None
        old_restored = not backup.exists()
        if not recovery_errors and backup.exists():
            try:
                if prefix.exists():
                    subprocess.run(agent_command(prefix / 'libexec/safe-claude', 'stop-ui', '--',
                                    str(prefix / 'SafeClaude.app/Contents/MacOS/SafeClaudeApp')),
                                   capture_output=True, timeout=5)
                    failed = prefix.parent / f'.{prefix.name}.upgrade-failed-{os.getpid()}'
                    if failed.exists() or failed.is_symlink():
                        raise OSError(f'upgrade recovery directory already exists: {failed}')
                    os.rename(prefix, failed)
                os.rename(backup, prefix)
                old_restored = True
            except OSError as recovery_error:
                recovery_errors.append(f'could not restore previous installation: {recovery_error}')

        if not recovery_errors and backup.exists():
            recovery_errors.append('previous installation remains in backup; current path could not be replaced')
        if not recovery_errors:
            for launch_file in booted_out:
                result = run_launchctl('bootstrap', launch_file)
                if result.returncode != 0 and not service_loaded(launch_file):
                    recovery_errors.append(f'could not restart previous launchd service: '
                                           f'{launch_labels[launch_file]}')
        if drain_started and old_restored and prefix.is_dir() and not cancel_agent_drain():
            recovery_errors.append('could not cancel the previous Agent drain state')
        if failed and failed.exists() and not recovery_errors:
            shutil.rmtree(failed, ignore_errors=True)

        if recovery_errors:
            details = '; '.join(recovery_errors)
            raise ValueError(
                f'upgrade failed: {upgrade_error}; rollback incomplete: {details}; '
                f'preserved recovery paths: current={prefix}, backup={backup}, failed={failed}') from upgrade_error
        raise
    finally:
        if staging and staging.exists():
            shutil.rmtree(staging)


def uninstall(args):
    prefix = Path(args.prefix).expanduser().absolute()
    manifest_path = prefix / 'manifest.json'
    regular_or_absent(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('version') != 1: raise ValueError('unrecognized installation')
    validate_manifest_paths(manifest['files'])
    for relative, expected in manifest['files'].items():
        path = prefix / relative
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError(f'installed file changed: {path}; leaving installation intact')
    expected_paths = set(manifest['files']) | {'manifest.json'}
    actual_paths = {str(p.relative_to(prefix)) for p in prefix.rglob('*') if p.is_file() or p.is_symlink()}
    if actual_paths != expected_paths: raise ValueError('installation contains unexpected files; leaving it intact')
    shell_snapshot = None
    shell_mode = None
    if manifest['shell']:
        regular_or_absent(SHELL_FILE)
        shell_mode = stat.S_IMODE(SHELL_FILE.stat().st_mode)
        shell_snapshot = SHELL_FILE.read_bytes()
        content = shell_snapshot.decode('utf-8')
        block = shell_block(prefix)
        if content.count(block) != 1: raise ValueError('shell integration changed; remove it manually')
        block_start = content.index(block)
        if manifest.get('shellAddedNewline') and (block_start == 0 or content[block_start - 1] != '\n'):
            raise ValueError('shell integration separator changed; remove it manually')
    settings_snapshot = None
    settings_mode = None
    if manifest.get('settings'):
        settings_path = Path(manifest['settingsPath'])
        regular_or_absent(settings_path)
        settings_mode = stat.S_IMODE(settings_path.stat().st_mode)
        settings_snapshot = settings_path.read_bytes()
        settings_content = settings_snapshot.decode('utf-8')
        config = parse_settings(settings_content)
        fragments = installed_settings_fragments(manifest)
        if (fragments is None or
                config.get('processWrapper') != str(prefix / 'libexec/process-wrapper')):
            raise ValueError('Claude wrapper settings changed; remove them manually')
        restored_settings = remove_settings_fragments(settings_content, fragments)
    launch_snapshots = {}
    if manifest['launchd']:
        for launch_file, label, arguments in (
            (LAUNCH_FILE, 'local.safeclaude.agent', [str(prefix / 'libexec/safe-claude-agent')]),
            (UI_LAUNCH_FILE, 'local.safeclaude.menu', ['/usr/bin/open', '-gj', str(prefix / 'SafeClaude.app')])):
            regular_or_absent(launch_file)
            launch_snapshots[launch_file] = launch_file.read_bytes()
            spec = plistlib.loads(launch_snapshots[launch_file])
            if spec.get('Label') != label or spec.get('ProgramArguments') != arguments:
                raise ValueError('launch agent changed; leaving installation intact')
        status = subprocess.run(agent_command(prefix / 'libexec/safe-claude', 'prepare-uninstall'),
                                capture_output=True, timeout=5)
        draining = status.returncode == 0
        if status.returncode == 0:
            try:
                result = json.loads(status.stdout)
            except ValueError:
                subprocess.run(agent_command(prefix / 'libexec/safe-claude', 'cancel-uninstall'),
                               capture_output=True, timeout=5)
                raise
            if result.get('decision') != 'allow' or result.get('managedSessions') != 0:
                subprocess.run(agent_command(prefix / 'libexec/safe-claude', 'cancel-uninstall'),
                               capture_output=True, timeout=5)
                raise ValueError('managed sessions are active or unavailable; close them before uninstalling')
        else:
            journal = HOME / 'Library/Application Support/SafeClaude/sessions.json'
            regular_or_absent(journal)
            if journal.exists() and json.loads(journal.read_text()) != []:
                raise ValueError('agent is offline with recorded sessions; restart it before uninstalling')
        try:
            if not args.managed_ui:
                subprocess.run(agent_command(prefix / 'libexec/safe-claude', 'stop-ui', '--',
                                str(prefix / 'SafeClaude.app/Contents/MacOS/SafeClaudeApp')),
                               check=True, timeout=5)
            for launch_file, snapshot in launch_snapshots.items():
                require_unchanged(launch_file, snapshot, True, 0o600)
            for launch_file in (UI_LAUNCH_FILE, LAUNCH_FILE):
                subprocess.run(['/bin/launchctl', 'bootout', f'gui/{os.getuid()}', str(launch_file)], check=True)
                launch_file.unlink()
        except Exception:
            if draining:
                subprocess.run(agent_command(prefix / 'libexec/safe-claude', 'cancel-uninstall'),
                               capture_output=True, timeout=5)
            raise
    if manifest['shell']:
        block_start = content.index(block)
        remove_start = block_start - 1 if manifest.get('shellAddedNewline') else block_start
        restored = content[:remove_start] + content[block_start + len(block):]
    if manifest['shell']:
        require_unchanged(SHELL_FILE, shell_snapshot, True, shell_mode)
    if manifest.get('settings'):
        require_unchanged(settings_path, settings_snapshot, True, settings_mode)
    if manifest['shell']:
        if not manifest.get('shellExisted') and not restored:
            SHELL_FILE.unlink()
        else:
            write_atomic(SHELL_FILE, restored.encode(), shell_mode)
    if manifest.get('settings'):
        if not manifest.get('settingsExisted') and parse_settings(restored_settings) == {}:
            settings_path.unlink()
        else:
            write_atomic(settings_path, restored_settings.encode(), settings_mode)
    shutil.rmtree(prefix)
    print(f'uninstalled: {prefix}')


def run_serialized(operation, args):
    lock_directory = HOME / 'Library/Application Support/SafeClaude'
    lock_directory.mkdir(parents=True, exist_ok=True)
    lock_path = lock_directory / 'setup.lock'
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('setup lock is not a regular file owned by the current user')
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('another SafeClaude install operation is in progress') from error
        operation(args)
    finally:
        os.close(fd)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['install', 'upgrade', 'uninstall'])
    parser.add_argument('--prefix', default=str(DEFAULT_PREFIX))
    parser.add_argument('--claude')
    parser.add_argument('--source-app')
    parser.add_argument('--no-launchd', action='store_true')
    parser.add_argument('--no-shell', action='store_true')
    parser.add_argument('--no-settings', action='store_true')
    parser.add_argument('--managed-ui', action='store_true',
                        help='keep the calling GUI alive so it can report uninstall status')
    args = parser.parse_args()
    if args.managed_ui and args.action != 'uninstall':
        parser.error('--managed-ui is only valid with uninstall')
    try:
        run_serialized({'install': install, 'upgrade': upgrade, 'uninstall': uninstall}[args.action], args)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(f'safe-claude setup: {error}')

if __name__ == '__main__':
    main()
