#!/usr/bin/env python3
"""Measure only the local proxy diagnostic, not the future full preflight."""

import json
import math
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / ".build/release/safe-claude"
environment = {
    "PATH": "/usr/bin:/bin",
    "LANG": "en_US.UTF-8",
    "HTTPS_PROXY": "http://127.0.0.1:8123",
}
samples = []
for _ in range(40):
    start = time.perf_counter()
    result = subprocess.run(
        [str(BINARY), "probe-config", "api.fixture.invalid"],
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=True, timeout=3,
    )
    samples.append((time.perf_counter() - start) * 1000)
    assert json.loads(result.stdout)["decision"] == "proxy"
ordered = sorted(samples)
print(json.dumps({
    "sample_count": len(samples),
    "first_ms": round(samples[0], 2),
    "median_ms": round(statistics.median(samples), 2),
    "p95_ms": round(ordered[math.ceil(len(ordered) * 0.95) - 1], 2),
    "max_ms": round(ordered[-1], 2),
    "scope": "local proxy configuration diagnostic only",
}))
