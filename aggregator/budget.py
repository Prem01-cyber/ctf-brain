"""Token-budgeted rendering of live context into a prompt block.

The workstation can have 10+ panes, a full browser page, and app logs — far more
than belongs in a prompt. This module renders the most useful slice first and
stops once the budget is hit, so the newest/active data always survives.
"""
from __future__ import annotations

import time
from typing import Any

from . import config, detect


def estimate_tokens(text: str) -> int:
    """Cheap, dependency-free token estimate (~4 chars/token)."""
    return (len(text) + 3) // 4


def _tail(text: str, lines: int) -> str:
    if not text:
        return ""
    parts = text.rstrip("\n").split("\n")
    return "\n".join(parts[-lines:])


def _fresh(updated: float | None, now: float) -> bool:
    return updated is not None and (now - updated) <= config.STALE_AFTER


def build_context(state: dict[str, Any], budget_tokens: int | None = None) -> dict[str, Any]:
    """Render `state` into a budgeted context.

    Returns a dict with:
      - ``rendered``:  the text block to inject into the system prompt
      - ``tokens``:    estimated token count of ``rendered``
      - ``truncated``: True if anything was dropped to fit the budget
      - ``sections``:  machine-readable view of what was included (for the UI)
    """
    budget = budget_tokens if budget_tokens is not None else config.CONTEXT_TOKEN_BUDGET
    now = time.time()
    used = 0
    truncated = False
    chunks: list[str] = []
    sections: dict[str, Any] = {"panes": [], "findings": 0, "browser": None,
                                "screenshot": False, "apps": {}}

    def add(text: str) -> bool:
        """Append a chunk if it fits. Returns False once the budget is exhausted."""
        nonlocal used, truncated
        cost = estimate_tokens(text)
        if used + cost > budget:
            truncated = True
            return False
        chunks.append(text)
        used += cost
        return True

    # --- Priority 1: panes, active first, then most-recently-updated ---------
    panes = list(state.get("panes", {}).values())
    panes.sort(key=lambda p: (not p.get("active"), -(p.get("updated") or 0)))
    for p in panes:
        active = bool(p.get("active"))
        n = config.ACTIVE_PANE_LINES if active else config.OTHER_PANE_LINES
        tail = _tail(p.get("content", ""), n)
        if not tail.strip():
            continue
        loc = f"{p.get('session')}:{p.get('window')}.{p.get('pane')}"
        flag = " (ACTIVE)" if active else ""
        cmd = p.get("command") or "?"
        header = f"### tmux pane {loc} [{cmd}]{flag}"
        block = f"{header}\n```\n{tail}\n```"
        if not add(block):
            break
        sections["panes"].append({"location": loc, "command": cmd, "active": active})

    # --- Priority ~1.5: detection findings (the actionable enumeration gold) -
    findings = state.get("findings", [])
    if findings:
        ranked = sorted(findings, key=lambda f: detect.severity_rank(f.get("severity", "info")))
        lines = ["### detected (auto-flagged from proxied/browser traffic)"]
        shown = 0
        for f in ranked[:40]:
            lines.append(
                f"[{f.get('severity', '?').upper()}] {f.get('title', f.get('rule'))} "
                f"— {f.get('method', '')} {f.get('url', '')} "
                f"({f.get('where', '')}: {f.get('evidence', '')})"
            )
            shown += 1
        if add("\n".join(lines)):
            sections["findings"] = shown

    # --- Priority ~1.7: recon inventory (endpoints + injection candidates) ---
    inv = state.get("inventory") or {}
    params = inv.get("params") or []
    endpoints = inv.get("endpoints") or []
    if params or endpoints:
        lines = ["### recon inventory"]
        if params:
            lines.append("params seen (injection candidates): " + ", ".join(params[:60]))
        if endpoints:
            lines.append("endpoints:")
            for e in endpoints[:40]:
                m = "/".join(e.get("methods", [])) or "?"
                ps = ("?" + ",".join(e["params"])) if e.get("params") else ""
                lines.append(f"  {m} {e.get('host', '')}{e.get('path', '')}{ps}")
        links = inv.get("links") or []
        if links:
            lines.append("discovered (not yet visited): " + ", ".join(links[:30]))
        add("\n".join(lines))

    # --- Priority 2: browser (selection > url/title > visible body) ----------
    browser = state.get("browser")
    if browser and _fresh(browser.get("timestamp_recv"), now):
        url = browser.get("url", "")
        title = browser.get("title", "")
        selected = (browser.get("selected") or "").strip()
        lines = [f"### browser", f"url: {url}", f"title: {title}"]
        if selected:
            lines.append(f"selected text:\n{selected[:1500]}")
        xhr = browser.get("xhr") or []
        if xhr:
            recent = "; ".join(
                f"{x.get('method', 'GET')} {x.get('url', '')} -> {x.get('status', '?')}"
                for x in xhr[-10:]
            )
            lines.append(f"recent requests: {recent}")
        if add("\n".join(lines)):
            sections["browser"] = {"url": url, "title": title, "has_selection": bool(selected)}
        # Visible body text is lower priority — only if there's still room.
        body = (browser.get("bodyText") or "").strip()
        if body:
            add(f"### browser visible text\n{body[:3000]}")

    # --- Priority 3: app logs (burp, wireshark) -----------------------------
    burp = list(state.get("burp", []))[-config.BURP_ENTRIES:]
    if burp:
        if add("### burp recent\n" + "\n".join(str(e) for e in burp)):
            sections["apps"]["burp"] = len(burp)
    wire = list(state.get("wireshark", []))[-config.WIRESHARK_ENTRIES:]
    if wire:
        if add("### wireshark recent\n" + "\n".join(str(e) for e in wire)):
            sections["apps"]["wireshark"] = len(wire)

    # Screenshot isn't rendered as text (it goes in as an image block on /chat),
    # but we flag its availability so the UI/system prompt can mention it.
    sections["screenshot"] = bool(state.get("screenshot"))

    rendered = "\n\n".join(chunks) if chunks else "(no live context captured yet)"
    return {
        "rendered": rendered,
        "tokens": used,
        "truncated": truncated,
        "sections": sections,
    }
