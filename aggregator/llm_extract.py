"""Dynamic LLM analysis of observed content (tool output or a web page).

Rather than a hardcoded ruleset deciding what matters, the model OBSERVES the
content, decides what is *abnormal or interesting* for a CTF/pentest, forms a
hypothesis, and proposes how to progress it — then we record those as findings,
tasks, and structured assets. Nothing about "what counts as interesting" is
hardcoded; the model judges it in context. Used automatically when a tmux pane
or a web page settles, and on demand.
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import providers
from .state import STATE

_PROMPT = """You are an expert CTF / penetration-testing analyst observing live \
content from the operator's session — it may be tool output (nmap, gobuster, …) or \
the text of a web page they just opened.

Think like an analyst: what here is *out of place* or worth pulling on? Treat \
anything abnormal as a signal, not noise — e.g. hashes, encoded/encrypted blobs \
(long hex/base64), tokens, debug info, odd parameters or hidden fields, version \
banners, comments that leak info, or a UI that hints at a mechanism (an encryption \
form, a key field, an admin area). For each, say *why* it's abnormal, your best \
hypothesis about what it is, and the concrete next action to confirm/exploit it. \
Don't just list data — reason about what it lets us claim.

Return ONLY a JSON object (no prose) with any of these keys you have content for:
{
  "summary": "<one line: what is this content / what's going on>",
  "hosts": [{"host": "<ip/hostname>", "ports": [{"port":"","proto":"tcp","service":"","version":"<exact product+version for CVE matching>"}]}],
  "endpoints": ["<url paths>"],
  "credentials": ["user=<u>", "password=<p>"],
  "anomalies": [{
     "observation": "<what you noticed, with the concrete value/snippet>",
     "why_abnormal": "<why this shouldn't normally be here / why it matters>",
     "hypothesis": "<what you think it is, e.g. 'hex looks XOR-encrypted with the Message key field'>",
     "severity": "high|medium|low",
     "next_action": "<exact command or step to progress it>"
  }],
  "notes": ["<short high-value observations to track>"]
}
Do not invent data; ground every claim in the text. CONTENT:
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


async def analyze(text: str, source: str = "content") -> dict[str, Any]:
    """Have the model observe content and judge what's abnormal/interesting."""
    text = (text or "").strip()
    if not text:
        return {}
    provider = providers.get_provider()
    if not provider.available():
        provider = next((p for p in providers._REGISTRY.values() if p.available()), None)
        if provider is None:
            return {}
    raw = await provider.complete(
        "You output only JSON. No explanations.",
        _PROMPT + f"(source: {source})\n" + text[:20000])
    return _extract_json(raw)


# Back-compat alias.
parse_output = analyze


def merge(data: dict[str, Any], source: str = "analysis") -> dict[str, int]:
    """Merge an analysis result into the knowledge base. Anomalies become findings
    (severity judged by the model) + tasks; assets merge into the KB."""
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

    arts = [{"type": "credential", "value": str(c)[:200], "confidence": "medium",
             "source": source, "context": ""} for c in data.get("credentials", []) or []]
    n_arts = STATE.add_artifacts(arts) if arts else 0

    # Model-judged anomalies → findings (dynamic, not rule-based) + follow-up tasks.
    findings, n_anom = [], 0
    for a in data.get("anomalies", []) or []:
        if not isinstance(a, dict) or not a.get("observation"):
            continue
        sev = a.get("severity", "medium")
        sev = sev if sev in ("high", "medium", "low") else "medium"
        obs = str(a["observation"])[:200]
        findings.append({
            "severity": sev, "category": "analysis", "rule": "anomaly",
            "title": obs, "method": "", "url": "", "source": source,
            "where": source,
            "evidence": f"{a.get('why_abnormal', '')} | hypothesis: {a.get('hypothesis', '')}"[:280],
            "key": f"anomaly|{obs[:80]}",
        })
        if a.get("next_action"):
            STATE.add_task(f"{obs[:60]} → {str(a['next_action'])[:160]}")
        n_anom += 1
    STATE.add_findings(findings)

    for note in (data.get("notes", []) or [])[:8]:
        STATE.add_note(f"[{source}] {note}")
    if data.get("summary"):
        STATE.add_note(f"[{source}] {str(data['summary'])[:200]}")
    return {"hosts": n_hosts, "artifacts": n_arts, "anomalies": n_anom}
