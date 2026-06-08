"""In-memory rolling state shared across requests.

Single-process, single-worker uvicorn: a module-level object guarded by a lock
is plenty. Collectors POST in; /context and /chat read out.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from typing import Any

from . import config, inventory


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
        # Recon inventory + full-flow ring (for the Repeater / agent tools).
        self.endpoints: dict[tuple[str, str], dict[str, Any]] = {}
        self.params: set[str] = set()
        self.links: set[str] = set()
        self.flows_full: deque[dict[str, Any]] = deque(maxlen=80)
        # Per-session engagement tracking (persisted to disk).
        self.session: str = config.SESSION
        self.notes: list[dict[str, Any]] = []
        self.tasks: list[dict[str, Any]] = []
        self.flags: list[str] = []
        # Accumulating knowledge base, auto-populated by the extraction pipeline.
        self.hosts: dict[str, dict[str, Any]] = {}      # host -> {ports, os, hostname}
        self.artifacts: list[dict[str, Any]] = []        # hashes/creds/emails, deduped
        self._artifact_keys: set[str] = set()
        self._last_pane_hash: str | None = None
        self._counter = 0
        self._dirty = False

    def _touch(self) -> None:
        self._dirty = True

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

    def _add_findings_unlocked(self, findings: list[dict[str, Any]]) -> int:
        added = 0
        for f in findings:
            key = f.get("key")
            if key and key in self._finding_keys:
                continue
            if key:
                self._finding_keys.add(key)
            f["count"] = 1
            self.findings.append(f)
            added += 1
            self._dirty = True
        if len(self.findings) > self._max_findings:
            drop = self.findings[: len(self.findings) - self._max_findings]
            self.findings = self.findings[-self._max_findings:]
            for d in drop:
                self._finding_keys.discard(d.get("key"))
        return added

    def add_findings(self, findings: list[dict[str, Any]]) -> int:
        """Add findings not tied to a flow (e.g. hashes pulled from terminal output)."""
        with self._lock:
            return self._add_findings_unlocked(findings)

    def add_flow(self, summary: dict[str, Any], findings: list[dict[str, Any]]) -> int:
        """Record a flow summary + its (deduped) findings. Returns new-finding count."""
        with self._lock:
            self.flows.append(summary)
            return self._add_findings_unlocked(findings)

    def merge_hosts(self, hosts: list[dict[str, Any]]) -> int:
        """Merge parsed nmap hosts into the knowledge base (idempotent)."""
        new = 0
        with self._lock:
            for h in hosts:
                key = h.get("host") or "unknown"
                cur = self.hosts.setdefault(
                    key, {"host": key, "hostname": h.get("hostname", ""), "ports": {}, "os": ""})
                if h.get("hostname"):
                    cur["hostname"] = h["hostname"]
                if h.get("os"):
                    cur["os"] = h["os"]
                for pk, p in h.get("ports", {}).items():
                    if pk not in cur["ports"]:
                        new += 1
                    cur["ports"][pk] = p
            if new or hosts:
                self._dirty = True
        return new

    def add_artifacts(self, artifacts: list[dict[str, Any]]) -> int:
        new = 0
        with self._lock:
            for a in artifacts:
                key = f"{a['type']}|{a['value']}"
                if key in self._artifact_keys:
                    continue
                self._artifact_keys.add(key)
                a["t"] = time.time()
                self.artifacts.append(a)
                new += 1
                self._dirty = True
            if len(self.artifacts) > 1000:
                drop = self.artifacts[:len(self.artifacts) - 1000]
                self.artifacts = self.artifacts[-1000:]
                for d in drop:
                    self._artifact_keys.discard(f"{d['type']}|{d['value']}")
        return new

    def pane_text_changed(self, text: str) -> bool:
        """True if the combined pane text differs from last time (cheap skip)."""
        import hashlib
        h = hashlib.md5(text.encode("utf-8", "replace")).hexdigest()
        with self._lock:
            if h == self._last_pane_hash:
                return False
            self._last_pane_hash = h
            return True

    def get_hosts(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {"host": h["host"], "hostname": h.get("hostname", ""), "os": h.get("os", ""),
                 "ports": sorted(h["ports"].values(), key=lambda p: int(p["port"]))}
                for h in self.hosts.values()]

    def get_artifacts(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.artifacts)

    def update_inventory(self, flow: dict[str, Any]) -> None:
        url = flow.get("url", "")
        if not url:
            return
        with self._lock:
            host, path = inventory.endpoint_key(url)
            params = inventory.query_params(url) | inventory.body_params(flow.get("req_body"))
            ep = self.endpoints.setdefault(
                (host, path), {"host": host, "path": path, "methods": set(),
                               "statuses": set(), "params": set()})
            if flow.get("method"):
                ep["methods"].add(flow["method"])
            if flow.get("status") not in (None, ""):
                ep["statuses"].add(flow["status"])
            ep["params"] |= params
            self.params |= params
            # Passive crawl: links found in HTML/JS bodies we haven't seen as endpoints.
            seen_paths = {p for _, p in self.endpoints}
            for link in inventory.extract_links(flow.get("resp_body")):
                if link not in seen_paths:
                    self.links.add(link)
            if len(self.endpoints) > 1000 or len(self.links) > 1000:
                self.links = set(list(self.links)[:1000])
            # Retain the full flow for replay / agent inspection (bounded body).
            self.flows_full.append({
                "method": flow.get("method", "GET"), "url": url,
                "status": flow.get("status"),
                "req_headers": flow.get("req_headers") or {},
                "req_body": (flow.get("req_body") or "")[:20000] or None,
                "resp_headers": flow.get("resp_headers") or {},
                "resp_body": (flow.get("resp_body") or "")[:20000] or None,
            })
            self._dirty = True

    def _inventory_unlocked(self) -> dict[str, Any]:
        eps = sorted(self.endpoints.values(), key=lambda e: (e["host"], e["path"]))
        return {
            "endpoints": [
                {"host": e["host"], "path": e["path"],
                 "methods": sorted(e["methods"]),
                 "statuses": sorted(str(s) for s in e["statuses"]),
                 "params": sorted(e["params"])}
                for e in eps[:400]
            ],
            "params": sorted(self.params)[:300],
            "links": sorted(self.links)[:300],
        }

    def get_inventory(self) -> dict[str, Any]:
        with self._lock:
            return self._inventory_unlocked()

    def get_flows_full(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.flows_full)

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
                "inventory": self._inventory_unlocked(),
                "hosts": [
                    {"host": h["host"], "hostname": h.get("hostname", ""), "os": h.get("os", ""),
                     "ports": sorted(h["ports"].values(), key=lambda p: int(p["port"]))}
                    for h in self.hosts.values()],
                "artifacts": list(self.artifacts),
                "notes": list(self.notes),
                "tasks": list(self.tasks),
                "flags": list(self.flags),
                "session": self.session,
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
            self._dirty = True

    def in_scope(self, url: str) -> bool:
        with self._lock:
            if not self.scope:
                return True
            u = (url or "").lower()
            return any(s in u for s in self.scope)

    # --- engagement tracking ---------------------------------------------
    def add_note(self, text: str) -> dict[str, Any]:
        with self._lock:
            self._counter += 1
            note = {"id": self._counter, "text": str(text), "t": time.time()}
            self.notes.append(note)
            self._dirty = True
            return note

    def add_task(self, text: str, done: bool = False) -> dict[str, Any]:
        with self._lock:
            self._counter += 1
            task = {"id": self._counter, "text": str(text), "done": bool(done), "t": time.time()}
            self.tasks.append(task)
            self._dirty = True
            return task

    def toggle_task(self, task_id: int, done: bool | None = None) -> bool:
        with self._lock:
            for t in self.tasks:
                if t["id"] == task_id:
                    t["done"] = (not t["done"]) if done is None else bool(done)
                    self._dirty = True
                    return True
            return False

    def add_flag(self, flag: str) -> bool:
        with self._lock:
            if flag and flag not in self.flags:
                self.flags.append(flag)
                self._dirty = True
                return True
            return False

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

    # --- persistence / sessions ------------------------------------------
    def _persist_dict(self) -> dict[str, Any]:
        """Lock-free serializable snapshot of the durable engagement state."""
        return {
            "session": self.session,
            "scope": list(self.scope),
            "findings": list(self.findings),
            "finding_keys": list(self._finding_keys),
            "endpoints": [
                {"host": h, "path": p, "methods": sorted(e["methods"]),
                 "statuses": sorted(str(s) for s in e["statuses"]),
                 "params": sorted(e["params"])}
                for (h, p), e in self.endpoints.items()],
            "params": sorted(self.params),
            "links": sorted(self.links),
            "flows_full": list(self.flows_full),
            "hosts": list(self.hosts.values()),
            "artifacts": list(self.artifacts),
            "notes": list(self.notes),
            "tasks": list(self.tasks),
            "flags": list(self.flags),
            "counter": self._counter,
        }

    def _load_dict(self, d: dict[str, Any]) -> None:
        self.session = d.get("session", self.session)
        self.scope = d.get("scope", [])
        self.findings = d.get("findings", [])
        self._finding_keys = set(d.get("finding_keys", []))
        self.endpoints = {
            (e["host"], e["path"]): {"host": e["host"], "path": e["path"],
                                     "methods": set(e.get("methods", [])),
                                     "statuses": set(e.get("statuses", [])),
                                     "params": set(e.get("params", []))}
            for e in d.get("endpoints", [])}
        self.params = set(d.get("params", []))
        self.links = set(d.get("links", []))
        self.flows_full = deque(d.get("flows_full", []), maxlen=80)
        self.hosts = {h["host"]: {"host": h["host"], "hostname": h.get("hostname", ""),
                                  "os": h.get("os", ""),
                                  "ports": {pk: pv for pk, pv in
                                            (h["ports"].items() if isinstance(h.get("ports"), dict)
                                             else {f"{p['port']}/{p['proto']}": p for p in h.get("ports", [])}.items())}}
                      for h in d.get("hosts", [])}
        self.artifacts = d.get("artifacts", [])
        self._artifact_keys = {f"{a['type']}|{a['value']}" for a in self.artifacts}
        self.notes = d.get("notes", [])
        self.tasks = d.get("tasks", [])
        self.flags = d.get("flags", [])
        self._counter = d.get("counter", 0)

    def _path(self, name: str) -> str:
        safe = "".join(c for c in name if c.isalnum() or c in "-_.") or "default"
        return os.path.join(config.DATA_DIR, f"{safe}.json")

    def save(self, force: bool = False) -> bool:
        with self._lock:
            if not self._dirty and not force:
                return False
            data = self._persist_dict()
            self._dirty = False
        os.makedirs(config.DATA_DIR, exist_ok=True)
        tmp = self._path(data["session"]) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self._path(data["session"]))
        return True

    def load(self, name: str) -> bool:
        path = self._path(name)
        if not os.path.exists(path):
            return False
        with open(path) as f:
            data = json.load(f)
        with self._lock:
            self._load_dict(data)
            self._dirty = False
        return True

    def switch_session(self, name: str) -> dict[str, Any]:
        self.save(force=True)  # persist current
        with self._lock:
            # Reset live + durable state, keep transient collectors (panes/browser).
            self.endpoints, self.params, self.links = {}, set(), set()
            self.flows_full.clear()
            self.findings, self._finding_keys = [], set()
            self.flows.clear()
            self.hosts, self.artifacts, self._artifact_keys = {}, [], set()
            self._last_pane_hash = None
            self.notes, self.tasks, self.flags = [], [], []
            self.scope, self._counter = [], 0
            self.session = name
            self._dirty = False
        self.load(name)  # repopulate if it exists on disk
        return self.status()

    def list_sessions(self) -> list[str]:
        try:
            return sorted(f[:-5] for f in os.listdir(config.DATA_DIR) if f.endswith(".json"))
        except OSError:
            return []

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
                "endpoints": len(self.endpoints),
                "params": len(self.params),
                "session": self.session,
                "notes": len(self.notes),
                "tasks": len(self.tasks),
                "flags": len(self.flags),
                "hosts": len(self.hosts),
                "artifacts": len(self.artifacts),
                "last_pane_update": self.last_pane_update,
            }


# Module-level singleton.
STATE = State()
