"""tmux collector — dumps every pane across every session/window and POSTs to
the aggregator. Stdlib only (no deps) so it can run as a tiny standalone process.

`tmux capture-pane` only ever sees one pane, so we enumerate panes with
`list-panes -a` and capture each by target, giving the LLM all live terminals at
once — your nmap window, your exploit REPL, your nc listener — labelled by pane.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

from . import config

_FMT = "#{session_name}\t#{window_index}\t#{pane_index}\t#{pane_current_command}\t#{pane_active}"


def _tmux(*args: str) -> str | None:
    try:
        out = subprocess.run(
            ["tmux", *args],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def dump_all_panes() -> dict[str, dict]:
    listing = _tmux("list-panes", "-a", "-F", _FMT)
    if listing is None:
        return {}
    panes: dict[str, dict] = {}
    for line in listing.strip().splitlines():
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 5:
            continue
        sess, win, pane, cmd, active = parts
        target = f"{sess}:{win}.{pane}"
        content = _tmux("capture-pane", "-p", "-t", target, "-S", f"-{config.PANE_CAPTURE_LINES}")
        panes[f"{sess}:{win}:{pane}"] = {
            "session": sess,
            "window": win,
            "pane": pane,
            "command": cmd,
            "active": active == "1",
            "content": (content or "")[-8000:],
            "updated": time.time(),
        }
    return panes


def post_panes(panes: dict[str, dict]) -> bool:
    data = json.dumps({"panes": panes}).encode()
    req = urllib.request.Request(
        f"{config.AGG_URL}/panes",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def main() -> None:
    if _tmux("-V") is None:
        print("[tmux_poll] tmux not available; exiting.", file=sys.stderr)
        return
    print(f"[tmux_poll] polling every {config.POLL_INTERVAL}s -> {config.AGG_URL}/panes")
    misses = 0
    while True:
        panes = dump_all_panes()
        if panes:
            ok = post_panes(panes)
            if not ok:
                misses += 1
                if misses in (1, 5) or misses % 30 == 0:
                    print(f"[tmux_poll] aggregator unreachable (x{misses})", file=sys.stderr)
            else:
                if misses:
                    print("[tmux_poll] aggregator back online", file=sys.stderr)
                misses = 0
        time.sleep(config.POLL_INTERVAL)


if __name__ == "__main__":
    main()
