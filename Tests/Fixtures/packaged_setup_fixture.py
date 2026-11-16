#!/usr/bin/env python3
"""Install, upgrade, and uninstall using only resources embedded in a packaged app."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


if len(sys.argv) != 2:
    raise SystemExit("usage: packaged_setup_fixture.py /path/to/SafeClaude.app")
app = Path(sys.argv[1]).resolve()
setup = app / "Contents/Resources/Installer/safe-claude-setup"
if not setup.is_file() or not os.access(setup, os.X_OK):
    raise SystemExit(f"packaged installer runtime is missing: {setup}")

with tempfile.TemporaryDirectory(prefix="safe-claude-packaged-") as temp:
    home = Path(temp)
    target = home / "claude-original"
    target.write_text('#!/bin/sh\n[ "${1:-}" = "--version" ] && echo "2.1.323 (Claude Code)"\n')
    target.chmod(0o700)
    shell = home / ".zshrc"
    shell.write_text("export SAFECLAUDE_FIXTURE=1\n")
    settings_dir = home / ".claude"
    settings_dir.mkdir()
    settings = settings_dir / "settings.json"
    settings.write_text('{"env":{"FIXTURE":"preserve"}}\n')
    prefix = home / "Library/Application Support/SafeClaude/installation"
    isolated_path = home / "empty-path"
    isolated_path.mkdir()
    env = os.environ | {
        "HOME": str(home),
        "PATH": str(isolated_path),
        "LANG": "C",
        "SAFE_CLAUDE_AGENT_SOCKET":
            str(home / "Library/Application Support/SafeClaude/fixture-agent.sock"),
    }

    def run(action, *options):
        result = subprocess.run(
            [str(setup), action, "--prefix", str(prefix),
             "--claude", str(target), "--no-launchd", *options],
            env=env, capture_output=True, text=True, timeout=60,
        )
        if result.returncode:
            raise RuntimeError(f"packaged {action} failed: {result.stderr.strip()}")

    run("install")
    installed_app = prefix / "SafeClaude.app"
    extension = installed_app / (
        "Contents/Library/SystemExtensions/SafeClaudeDNS.systemextension/"
        "Contents/MacOS/SafeClaudeDNS"
    )
    assert extension.is_file()
    assert (installed_app / "Contents/Resources/Installer/setup-integration.py").is_file()
    assert json.loads(settings.read_text())["env"]["FIXTURE"] == "preserve"

    run("upgrade")
    assert extension.is_file()
    assert json.loads(settings.read_text())["env"]["FIXTURE"] == "preserve"

    run("uninstall", "--managed-ui")
    assert not prefix.exists()
    assert settings.read_text() == '{"env":{"FIXTURE":"preserve"}}\n'
    assert shell.read_text() == "export SAFECLAUDE_FIXTURE=1\n"

print(json.dumps({
    "packaged_install": True,
    "packaged_upgrade": True,
    "nested_dns_extension": True,
    "user_settings_preserved": True,
    "packaged_uninstall": True,
    "system_python_required": False,
}))
