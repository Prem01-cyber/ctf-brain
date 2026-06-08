"""Dynamic engagement model — turns the live state into a pentester's situational
picture: what's been discovered, which methodology phase we're in, and the
context-driven next steps. Pure: derive(snapshot) -> dict. The static phase list
in methodology.py is the skeleton; this fills it from what we've actually found.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from . import methodology

_PORT_RE = re.compile(r"\b(\d{1,5})/(tcp|udp)[ \t]+open[ \t]+(\S+)(?:[ \t]+([^\n]+))?")
_PHASES = [p["phase"] for p in methodology.PHASES]  # Recon..Post-exploitation


def _panes_text(snapshot: dict[str, Any]) -> str:
    return "\n".join(p.get("content", "") for p in snapshot.get("panes", {}).values())


def _parse_ports(text: str) -> list[dict[str, str]]:
    seen, out = set(), []
    for m in _PORT_RE.finditer(text):
        port, proto, svc, ver = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip()
        key = (port, proto)
        if key in seen:
            continue
        seen.add(key)
        out.append({"port": port, "proto": proto, "service": svc, "version": ver[:80]})
    return out


def _assets(snapshot: dict[str, Any]) -> dict[str, Any]:
    findings = snapshot.get("findings", [])
    inv = snapshot.get("inventory", {}) or {}
    artifacts = snapshot.get("artifacts", [])

    # Prefer the structured nmap-parsed hosts from the knowledge base; fall back
    # to a live parse of pane text if the pipeline hasn't populated it yet.
    kb_hosts = snapshot.get("hosts", [])
    ports: list[dict[str, str]] = []
    for h in kb_hosts:
        ports.extend(h.get("ports", []))
    if not ports:
        ports = _parse_ports(_panes_text(snapshot))

    hosts = {h.get("host") for h in kb_hosts if h.get("host") and h["host"] != "unknown"}
    hosts |= {e.get("host") for e in inv.get("endpoints", []) if e.get("host")}
    if (snapshot.get("browser") or {}).get("url"):
        hosts.add(urlsplit(snapshot["browser"]["url"]).netloc)

    tech = [f["evidence"] for f in findings if f.get("rule", "").startswith("header_")]
    tech += [f"{p.get('service', '')} {p.get('version', '')}".strip()
             for p in ports if p.get("version")]
    tech += [h["os"] for h in kb_hosts if h.get("os")]

    def arts(*types):
        return [a["value"] for a in artifacts if a["type"] in types]

    hashes = [a for a in artifacts if a["type"] not in ("credential", "email")]
    return {
        "hosts": sorted(h for h in hosts if h),
        "open_ports": ports,
        "services": sorted({p.get("service", "") for p in ports if p.get("service")}),
        "endpoints": len(inv.get("endpoints", [])),
        "params": inv.get("params", []),
        "technologies": sorted(set(tech))[:20],
        "emails": sorted(set(arts("email") +
                            [f["evidence"] for f in findings if f.get("rule") == "email"]))[:20],
        "tokens": [f["evidence"] for f in findings if f.get("rule") == "jwt"][:10],
        "credentials": arts("credential")[:20],
        "hashes": [{"type": a["type"], "value": a["value"]} for a in hashes][:30],
        "secrets": [f["title"] + ": " + f["evidence"]
                    for f in findings if f.get("category") == "secret"][:20],
        "flags": sorted(set(snapshot.get("flags", []) +
                            [f["evidence"] for f in findings if f.get("rule") == "flag"])),
    }


def _infer_phase(assets: dict[str, Any], findings: list[dict]) -> str:
    rules = {f.get("rule") for f in findings}
    if {"sql_error", "stack_trace", "debug_page"} & rules or \
       any(f.get("rule") == "jwt" and f.get("severity") == "high" for f in findings):
        return "Exploitation"
    if assets["endpoints"] or assets["params"] or \
       {"exposed_vcs", "exposed_env", "admin_panel", "backup_file", "api_docs"} & rules:
        return "Enumeration"
    if assets["open_ports"]:
        return "Scanning"
    if assets["hosts"]:
        return "Recon"
    return "Recon"


def _next_steps(assets: dict[str, Any], findings: list[dict]) -> list[dict[str, Any]]:
    """Context-driven suggestions, highest-value first."""
    steps: list[dict[str, Any]] = []
    rules = {f.get("rule"): f for f in findings}
    host = assets["hosts"][0] if assets["hosts"] else "TARGET"

    def add(prio, title, why, command="", phase=""):
        steps.append({"priority": prio, "title": title, "why": why,
                      "command": command, "phase": phase})

    if not assets["open_ports"] and assets["hosts"]:
        add(1, "Port scan the host", "no open ports recorded yet",
            f"nmap -sCV -p- -oA scan {host}", "Scanning")
    if "exposed_vcs" in rules:
        add(0, "Dump the exposed .git", "source/secrets often recoverable",
            f"git-dumper http://{host}/.git/ loot_git", "Enumeration")
    if "exposed_env" in rules:
        add(0, "Fetch the exposed config/.env", "likely DB creds / API keys",
            f"curl -s http://{host}/.env", "Enumeration")
    if "sql_error" in rules:
        f = rules["sql_error"]
        add(0, "Confirm & exploit SQLi", "a SQL error leaked from a parameter",
            f"sqlmap -u '{f.get('url')}' --batch --dump", "Exploitation")
    if any(r == "jwt" and rules[r].get("severity") == "high" for r in rules):
        add(0, "Forge the JWT (alg=none)", "signature isn't enforced",
            "python3 jwt_tool.py <token> -X a", "Exploitation")
    if "admin_panel" in rules:
        add(2, "Attack the admin panel", "management endpoint exposed",
            "hydra -L users.txt -P rockyou.txt <host> http-post-form ...", "Exploitation")
    if assets.get("hashes"):
        h = assets["hashes"][0]
        add(0, f"Crack the captured {h['type']} hash", "password hash recovered",
            "hashcat -a 0 hash.txt /usr/share/wordlists/rockyou.txt  # (pick -m by type)",
            "Exploitation")
    if assets.get("credentials"):
        add(1, "Try the captured credentials", "credential discovered in traffic/output",
            f"# spray {assets['credentials'][0]} against ssh/web/db on {host}", "Exploitation")
    pw = {p.lower() for p in assets["params"]}
    if {"password", "passwd", "pass"} & pw and {"user", "username", "email"} & pw:
        add(1, "Test the login (SQLi bypass / cred spray)",
            "username+password params discovered",
            "try ' OR 1=1-- , then hydra / cred spray", "Exploitation")
    for p in assets["params"][:6]:
        add(3, f"Fuzz parameter '{p}'", "discovered input — injection candidate",
            f"ffuf -u 'http://{host}/PATH?{p}=FUZZ' -w payloads.txt", "Enumeration")
    has_web = any(pt["port"] in ("80", "443", "8080", "8000") for pt in assets["open_ports"])
    if (has_web or assets["hosts"]) and assets["endpoints"] < 5:
        add(2, "Content/dir brute force", "few endpoints discovered so far",
            f"ffuf -u http://{host}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
            "Enumeration")
    for pt in assets["open_ports"]:
        if pt["service"] not in ("http", "https", "http-proxy"):
            add(2, f"Enumerate {pt['service']} ({pt['port']}/{pt['proto']})",
                "open service", f"# enumerate {pt['service']} on {host}:{pt['port']}",
                "Enumeration")
    if not steps:
        add(1, "Recon the target", "no data yet — identify and map the target",
            f"nmap -sCV {host} ; then browse the app with the extension on", "Recon")
    steps.sort(key=lambda s: s["priority"])
    return steps[:12]


def _checklist(phase: str, assets: dict[str, Any], findings: list[dict]) -> list[dict[str, Any]]:
    idx = _PHASES.index(phase) if phase in _PHASES else 0
    out = []
    for i, p in enumerate(methodology.PHASES):
        status = "done" if i < idx else ("active" if i == idx else "pending")
        out.append({"phase": p["phase"], "goal": p["goal"], "status": status})
    return out


def derive(snapshot: dict[str, Any]) -> dict[str, Any]:
    findings = snapshot.get("findings", [])
    assets = _assets(snapshot)
    phase = _infer_phase(assets, findings)
    sev = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev[f.get("severity", "info")] = sev.get(f.get("severity", "info"), 0) + 1
    return {
        "phase": phase,
        "assets": assets,
        "findings_summary": sev,
        "flags": assets["flags"],
        "next_steps": _next_steps(assets, findings),
        "checklist": _checklist(phase, assets, findings),
        "notes": snapshot.get("notes", []),
        "tasks": snapshot.get("tasks", []),
        "session": snapshot.get("session"),
    }
