"""Generic app-log collector — tails a file or a command's stdout and POSTs each
line to the aggregator under an app name. Stdlib only.

Examples:
    # Burp: Proxy > Options > "Log to file", then:
    python -m aggregator.tail burp --file /tmp/burp_http.log

    # Wireshark/tshark live capture:
    python -m aggregator.tail wireshark --cmd "tshark -l -i eth0 -T fields \\
        -e http.request.method -e http.host -e http.request.uri"

    # Anything else:
    python -m aggregator.tail nmap --cmd "tail -f /tmp/nmap.log"
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

from . import config


def post_line(app: str, line: str) -> None:
    data = json.dumps({"line": line}).encode()
    req = urllib.request.Request(
        f"{config.AGG_URL}/app/{app}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5).close()
    except (urllib.error.URLError, OSError):
        pass  # aggregator down — skip this line


def tail_file(path: str):
    """Yield appended lines, following the file like `tail -f`."""
    with open(path, "r", errors="replace") as f:
        f.seek(0, 2)  # start at EOF
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(0.3)


def tail_cmd(cmd: str):
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, text=True, bufsize=1
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line.rstrip("\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Tail a log/command into ctf-brain.")
    ap.add_argument("app", help="app name (e.g. burp, wireshark)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="path to a log file to follow")
    src.add_argument("--cmd", help="command whose stdout to follow")
    args = ap.parse_args()

    source = tail_file(args.file) if args.file else tail_cmd(args.cmd)
    print(f"[tail] {args.app} -> {config.AGG_URL}/app/{args.app}", file=sys.stderr)
    try:
        for line in source:
            if line.strip():
                post_line(args.app, line)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
