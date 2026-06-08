"""In-memory rolling state shared across requests.

Single-process, single-worker uvicorn: a module-level object guarded by a lock
is plenty. Collectors POST in; /context and /chat read out.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from . import config


class State:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.panes: dict[str, dict[str, Any]] = {}
        self.browser: dict[str, Any] | None = None
        # base64 PNG + when it was captured, or None.
        self.screenshot: dict[str, Any] | None = None
        self.burp: deque[str] = deque(maxlen=200)
        self.wireshark: deque[str] = deque(maxlen=400)
        self.last_pane_update: float | None = None
        # Proxy/extension HTTP flows + deduped detection findings.
        self.flows: deque[dict[str, Any]] = deque(maxlen=300)
        self.findings: list[dict[str, Any]] = []
        self._finding_keys: set[str] = set()
        self._max_findings = 500
        # Burp-style target scope (host/URL substrings). Empty = everything.
        self.scope: list[str] = list(config.SCOPE)

    # --- writers ----------------------------------------------------------
    def set_panes(self, panes: dict[str, dict[str, Any]]) -> None:
        with self._lock:
            self.panes = panes
            self.last_pane_update = time.time()

    def set_browser(self, snap: dict[str, Any]) -> None:
        snap = dict(snap)
        snap["timestamp_recv"] = time.time()
        with self._lock:
            prev = self.browser or {}
            # Keep the rolling request window only while we're on the same page;
            # navigating away clears stale requests (e.g. another tab's traffic).
            same_page = prev.get("url") and prev.get("url") == snap.get("url")
            xhr = list(prev.get("xhr", [])) if same_page else []
            new = snap.pop("xhr_events", None)
            if new:
                xhr.extend(new)
            snap["xhr"] = xhr[-30:]
            self.browser = snap

    def add_xhr(self, event: dict[str, Any]) -> None:
        with self._lock:
            if self.browser is None:
                self.browser = {"timestamp_recv": time.time(), "xhr": []}
            self.browser.setdefault("xhr", [])
            self.browser["xhr"].append(event)
            self.browser["xhr"] = self.browser["xhr"][-30:]

    def set_screenshot(self, b64: str | None) -> None:
        with self._lock:
            self.screenshot = {"data": b64, "captured": time.time()} if b64 else None

    def add_flow(self, summary: dict[str, Any], findings: list[dict[str, Any]]) -> int:
        """Record a flow summary + its (deduped) findings. Returns new-finding count."""
        added = 0
        with self._lock:
            self.flows.append(summary)
            for f in findings:
                key = f.get("key")
                if key and key in self._finding_keys:
                    continue
                if key:
                    self._finding_keys.add(key)
                f["count"] = 1
                self.findings.append(f)
                added += 1
            # Cap memory: drop oldest findings (keep newest).
            if len(self.findings) > self._max_findings:
                drop = self.findings[: len(self.findings) - self._max_findings]
                self.findings = self.findings[-self._max_findings:]
                for d in drop:
                    self._finding_keys.discard(d.get("key"))
        return added

    def add_app_log(self, app: str, line: str) -> bool:
        with self._lock:
            if app == "burp":
                self.burp.append(line)
                return True
            if app == "wireshark":
                self.wireshark.append(line)
                return True
            return False

    # --- readers ----------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        """A consistent shallow copy for the renderer."""
        with self._lock:
            return {
                "panes": dict(self.panes),
                "browser": dict(self.browser) if self.browser else None,
                "screenshot": dict(self.screenshot) if self.screenshot else None,
                "burp": list(self.burp),
                "wireshark": list(self.wireshark),
                "flows": list(self.flows),
                "findings": list(self.findings),
                "last_pane_update": self.last_pane_update,
            }

    def get_findings(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.findings)

    def get_scope(self) -> list[str]:
        with self._lock:
            return list(self.scope)

    def set_scope(self, scope: list[str]) -> None:
        with self._lock:
            self.scope = [s.strip().lower() for s in scope if s and s.strip()]

    def in_scope(self, url: str) -> bool:
        with self._lock:
            if not self.scope:
                return True
            u = (url or "").lower()
            return any(s in u for s in self.scope)

    def get_screenshot_b64(self) -> str | None:
        with self._lock:
            return self.screenshot["data"] if self.screenshot else None

    def consume_screenshot(self) -> str | None:
        """Return the pending screenshot and clear it (one-shot attach)."""
        with self._lock:
            if not self.screenshot:
                return None
            data = self.screenshot["data"]
            self.screenshot = None
            return data

    def status(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            return {
                "panes": len(self.panes),
                "active_pane": next(
                    (f"{p['session']}:{p['window']}.{p['pane']}"
                     for p in self.panes.values() if p.get("active")),
                    None,
                ),
                "browser_url": (self.browser or {}).get("url"),
                "browser_fresh": bool(
                    self.browser
                    and (now - self.browser.get("timestamp_recv", 0)) <= config.STALE_AFTER
                ),
                "screenshot_pending": bool(self.screenshot),
                "burp": len(self.burp),
                "wireshark": len(self.wireshark),
                "flows": len(self.flows),
                "findings": len(self.findings),
                "findings_high": sum(1 for f in self.findings if f.get("severity") == "high"),
                "scope": list(self.scope),
                "last_pane_update": self.last_pane_update,
            }


# Module-level singleton.
STATE = State()
