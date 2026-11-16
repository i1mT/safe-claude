#!/usr/bin/env python3
"""Exercise exec semantics with a local child; never launches Claude."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
launcher = root / ".build" / "debug" / "safe-claude"
target = """
import json,os,sys
print(json.dumps({'pid':os.getpid(),'cwd':os.getcwd(),'argv':sys.argv[1:],
                  'input':sys.stdin.read(),'sentinel':os.environ.get('GUARD_FIXTURE_SENTINEL')}))
sys.exit(42)
"""
with tempfile.TemporaryDirectory(prefix="safe claude cwd ") as cwd:
    env = dict(os.environ, GUARD_FIXTURE_SENTINEL="fixture environment")
    child = subprocess.Popen(
        [str(launcher), "fixture-exec", "--", sys.executable, "-c", target, "a b", "literal;$()"],
        cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, text=True,
    )
    stdout, stderr = child.communicate("fixture stdin", timeout=3)
    result = json.loads(stdout)
    assert result == {"pid": child.pid, "cwd": os.path.realpath(cwd), "argv": ["a b", "literal;$()"],
                      "input": "fixture stdin", "sentinel": "fixture environment"}, result
    assert child.returncode == 42 and stderr == ""
    print(json.dumps({"same_pid": True, "arguments_preserved": True, "cwd_preserved": True,
                      "environment_preserved": True, "stdin_preserved": True,
                      "stdout_unmodified": True, "exit_code_preserved": True}))
