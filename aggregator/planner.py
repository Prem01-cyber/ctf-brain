"""Dynamic engagement strategist.

Reasons over the *entire* accumulated knowledge base — hosts, ports, versions,
CVEs, findings, artifacts, endpoints, flags, notes — and produces a living
assessment: what we have, what each discovered asset *affords* us (what can be
extracted/exploited from a vulnerable service), and the highest-value next gains.
Nothing here is a hardcoded rule; the model derives it from the current state and
it is re-derived whenever the state materially changes (see maybe_reassess).
"""
from __future__ import annotations

import json
from typing import Any

from . import providers
from .llm_extract import _extract_json

_PROMPT = """You are the lead strategist on an authorized pentest/CTF engagement. \
Below is EVERYTHING gathered so far. Reason over the whole picture — for each \
discovered asset (a port + service + version, an endpoint, a credential, a CVE, a \
flagged anomaly), work out what it *affords*: what an attacker can extract or do \
with it, what it's vulnerable to, and how it connects to the rest. Be specific to \
the actual versions and CVEs present, not generic.

Return ONLY a JSON object:
{
  "summary": "<2-4 sentences: what we know, the foothold picture, where the path leads>",
  "assets": [{
     "name": "<e.g. '443/https on earth.local' or 'CVE-2021-41773 on Apache 2.4.49'>",
     "gives": "<what this affords us / what can be extracted from it>",
     "opportunities": ["<specific avenue to pursue>"]
  }],
  "next_steps": [{
     "title": "<short action>", "why": "<grounded in the evidence>",
     "command": "<exact command/payload, or empty>", "priority": 0,
     "phase": "Recon|Scanning|Enumeration|Exploitation|Post-exploitation"
  }]
}
priority 0 = do now, higher = later. Ground every item in the data below; do not \
invent hosts/versions. KNOWN STATE:
---
"""


def _state_text(snapshot: dict[str, Any]) -> str:
    """Compact, model-friendly dump of the knowledge base."""
    lines: list[str] = []
    hosts = snapshot.get("hosts", [])
    for h in hosts:
        hdr = f"HOST {h.get('host')}" + (f" ({h['hostname']})" if h.get("hostname") else "")
        if h.get("os"):
            hdr += f" os={h['os']}"
        lines.append(hdr)
        for p in h.get("ports", []):
            cves = ", ".join(f"{c.get('id')}{'(KEV)' if c.get('kev') else ''}"
                             for c in (p.get("vulns") or [])[:6])
            lines.append(f"  {p.get('port')}/{p.get('proto')} {p.get('service')} "
                         f"{p.get('version', '')}" + (f"  CVEs: {cves}" if cves else ""))
    inv = snapshot.get("inventory", {}) or {}
    if inv.get("params"):
        lines.append("PARAMS: " + ", ".join(inv["params"][:40]))
    eps = [e.get("path") for e in inv.get("endpoints", [])][:30]
    if eps:
        lines.append("ENDPOINTS: " + ", ".join(eps))
    if inv.get("links"):
        lines.append("DISCOVERED LINKS: " + ", ".join(inv["links"][:20]))
    arts = snapshot.get("artifacts", [])
    if arts:
        lines.append("ARTIFACTS: " + "; ".join(f"{a['type']}={a['value'][:40]}" for a in arts[:25]))
    findings = snapshot.get("findings", [])
    if findings:
        lines.append("FINDINGS:")
        for f in sorted(findings, key=lambda x: x.get("severity", "z"))[:30]:
            lines.append(f"  [{f.get('severity')}] {f.get('title')} ({f.get('url', '')})")
    if snapshot.get("flags"):
        lines.append("FLAGS: " + ", ".join(snapshot["flags"]))
    notes = [n.get("text", "") for n in snapshot.get("notes", [])][-10:]
    if notes:
        lines.append("NOTES:\n  " + "\n  ".join(notes))
    return "\n".join(lines)[:14000] or "(only minimal recon so far)"


async def assess(snapshot: dict[str, Any]) -> dict[str, Any]:
    """LLM strategist pass over the whole state. Returns {} if no provider/key."""
    provider = providers.get_provider()
    if not provider.available():
        provider = next((p for p in providers._REGISTRY.values() if p.available()), None)
        if provider is None:
            return {}
    raw = await provider.complete("You output only JSON. No explanations.",
                                  _PROMPT + _state_text(snapshot))
    data = _extract_json(raw)
    return data if isinstance(data, dict) else {}
