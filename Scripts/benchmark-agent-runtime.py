#!/usr/bin/env python3
"""Measure an isolated SafeClaude Agent's idle CPU and resident memory."""
import argparse
import json
import math
import os
import pathlib
import signal
import statistics
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--agent", required=True, type=pathlib.Path)
parser.add_argument("--duration", type=int, default=60)
parser.add_argument("--interval", type=float, default=2.0)
parser.add_argument("--json-output", type=pathlib.Path,
                    help="write the final report to a new file without overwriting")
args = parser.parse_args()

agent = args.agent.resolve()
if not agent.is_file() or not os.access(agent, os.X_OK):
    raise SystemExit(f"Agent must be an executable file: {agent}")
if not 30 <= args.duration <= 14400:
    raise SystemExit("duration must be between 30 and 14400 seconds")
if not 0.5 <= args.interval <= 30:
    raise SystemExit("interval must be between 0.5 and 30 seconds")

with tempfile.TemporaryDirectory(prefix="safeclaude-agent-benchmark-") as temporary:
    root = pathlib.Path(temporary)
    home = root / "home"
    home.mkdir(mode=0o700)
    socket = root / "agent.sock"
    environment = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
    }
    stderr_file = (root / "agent.stderr").open("w+b")
    process = subprocess.Popen(
        [str(agent), "--socket", str(socket)],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=stderr_file,
    )
    samples = []
    failure = None
    shutdown_escalated = False
    try:
        deadline = time.monotonic() + 30
        while not socket.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        if not socket.exists():
            failure = "agent did not create its isolated IPC socket"
        else:
            end = time.monotonic() + args.duration
            previous_cpu = None
            previous_sample = None
            while time.monotonic() < end:
                if process.poll() is not None:
                    failure = f"agent exited during measurement with status {process.returncode}"
                    break
                result = subprocess.run(
                    ["/bin/ps", "-o", "time=,rss=", "-p", str(process.pid)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                fields = result.stdout.split()
                if len(fields) != 2:
                    failure = "process disappeared while collecting a sample"
                    break
                cpu_text = fields[0]
                days = 0
                if "-" in cpu_text:
                    day_text, cpu_text = cpu_text.split("-", 1)
                    days = int(day_text)
                clock = cpu_text.split(":")
                if len(clock) == 3:
                    hours, minutes, seconds = int(clock[0]), int(clock[1]), float(clock[2])
                elif len(clock) == 2:
                    hours, minutes, seconds = 0, int(clock[0]), float(clock[1])
                else:
                    failure = "unexpected ps CPU time format"
                    break
                cpu_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
                sampled_at = time.monotonic()
                if previous_cpu is not None and sampled_at > previous_sample:
                    cpu_percent = max(0.0, (cpu_seconds - previous_cpu) /
                                      (sampled_at - previous_sample) * 100)
                    samples.append({"cpu_percent": cpu_percent, "rss_kib": int(fields[1])})
                previous_cpu = cpu_seconds
                previous_sample = sampled_at
                time.sleep(min(args.interval, max(0, end - sampled_at)))
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                shutdown_escalated = True
                process.kill()
                process.wait(timeout=5)
        stderr_file.flush()
        stderr_file.seek(0, os.SEEK_END)
        stderr_size = stderr_file.tell()
        stderr_file.seek(max(0, stderr_size - 4096))
        stderr = stderr_file.read().decode("utf-8", errors="replace")
        stderr_file.close()

if shutdown_escalated:
    failure = failure or "agent did not stop after SIGTERM; SIGKILL was required"
if failure:
    raise SystemExit(f"{failure}\nAgent stderr: {stderr[-2000:]}")
if len(samples) < max(5, int(args.duration / args.interval * 0.8)):
    raise SystemExit(f"insufficient samples: {len(samples)}")

cpu = [sample["cpu_percent"] for sample in samples]
rss = [sample["rss_kib"] for sample in samples]
report = {
    "agent": agent.name,
    "duration_seconds": args.duration,
    "sample_interval_seconds": args.interval,
    "sample_count": len(samples),
    "cpu_percent_mean": round(statistics.fmean(cpu), 3),
    "cpu_percent_p95": round(sorted(cpu)[math.ceil(len(cpu) * 0.95) - 1], 3),
    "rss_mib_mean": round(statistics.fmean(rss) / 1024, 2),
    "rss_mib_peak": round(max(rss) / 1024, 2),
    "shutdown_escalated": shutdown_escalated,
    "shutdown_returncode": process.returncode,
    "isolated_home": True,
    "model_requests": False,
}
encoded_report = json.dumps(report, sort_keys=True)
if args.json_output:
    output = args.json_output.expanduser().absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(encoded_report + "\n")
        stream.flush()
        os.fsync(stream.fileno())
print(encoded_report)
