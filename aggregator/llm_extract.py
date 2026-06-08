"""LLM-based parsing of arbitrary tool output.

Tool output isn't standardized (nmap, gobuster, ffuf, nikto, enum4linux, …), so
instead of brittle per-tool regex we hand the text to the model and ask for a
structured JSON object, then merge it into the knowledge base. Used both
on-demand and automatically when a tmux pane's output stabilizes.
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import providers
from .state import STATE

_PROMPT = """You are a parser for penetration-testing tool output. Read the text \
below (it may be from nmap, gobuster, ffuf, nikto, enum4linux, dirb, a shell, etc.) \
and extract what's useful. Return ONLY a JSON object, no prose, with this shape:

{
  "tool": "<best guess of the tool, or empty>",
  "hosts": [{"host": "<ip or hostname>", "ports": [
      {"port": "<num>", "proto": "tcp|udp", "service": "<name>", "version": "<product + version, e.g. 'Apache httpd 2.4.49'>"}]}],
  "endpoints": ["<discovered url paths>"],
  "credentials": ["user=<u>", "password=<p>"],
  "hashes": ["<any password hashes>"],
  "vulns": ["<any vulnerabilities the output itself reports>"],
  "notes": ["<short, high-value observations worth tracking>"]
}

Omit keys you have nothing for. Use the exact product+version string in "version" \
so it can be matched against a CVE database. Do not invent data. TEXT:
---
"""


def _extract_json(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    # Strip ```json fences if present.
    raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.M).strip()
    try:
        return json.loads(raw)
    except ValueError:
        pass
    # Fall back to the first balanced {...} object.
    start = raw.find("{")
    if start < 0:
        return {}
    depth = 0
    for i in range(start, len(raw)):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(raw[start:i + 1])
                except ValueError:
                    return {}
    return {}


async def parse_output(text: str) -> dict[str, Any]:
    """LLM-parse arbitrary tool output into a structured dict (or {} if no key)."""
    text = (text or "").strip()
    if not text:
        return {}
    provider = providers.get_provider()
    if not provider.available():
        provider = next((p for p in providers._REGISTRY.values() if p.available()), None)
        if provider is None:
            return {}
    raw = await provider.complete(
        "You output only JSON. No explanations.", _PROMPT + text[:20000])
    return _extract_json(raw)


def merge(data: dict[str, Any]) -> dict[str, int]:
    """Merge a parsed result into the knowledge base. Returns merge counts."""
    if not isinstance(data, dict):
        return {}
    hosts = []
    for h in data.get("hosts", []) or []:
        if not isinstance(h, dict):
            continue
        ports = {}
        for p in h.get("ports", []) or []:
            if isinstance(p, dict) and p.get("port"):
                pk = f"{p['port']}/{p.get('proto', 'tcp')}"
                ports[pk] = {"port": str(p["port"]), "proto": p.get("proto", "tcp"),
                             "state": "open", "service": p.get("service", ""),
                             "version": (p.get("version") or "").strip()[:120]}
        if h.get("host") or ports:
            hosts.append({"host": h.get("host", "unknown"), "hostname": "",
                          "ports": ports, "os": ""})
    n_hosts = STATE.merge_hosts(hosts) if hosts else 0

    arts = []
    for c in data.get("credentials", []) or []:
        arts.append({"type": "credential", "value": str(c)[:200], "confidence": "medium",
                     "source": "parsed", "context": data.get("tool", "")})
    for hsh in data.get("hashes", []) or []:
        arts.append({"type": "hash", "value": str(hsh)[:200], "confidence": "medium",
                     "source": "parsed", "context": data.get("tool", "")})
    n_arts = STATE.add_artifacts(arts) if arts else 0

    for note in (data.get("notes", []) or [])[:10]:
        STATE.add_note(f"[{data.get('tool', 'parsed')}] {note}")
    return {"hosts": n_hosts, "artifacts": n_arts}
