"""Extractors — turn raw text (tmux output, HTTP bodies, page text) into
structured intel: parsed nmap hosts/ports/services, and "artifacts" (hashes,
crypt strings, credentials, emails) that shouldn't normally be lying around.

Pure functions. The pipeline (main.py) runs these on every collector input and
merges the results into the persistent knowledge base in state.py.
"""
from __future__ import annotations

import re
from typing import Any

# --- nmap -------------------------------------------------------------------
_NMAP_HOST = re.compile(r"Nmap scan report for (?:([^\s()]+) \(([\d.]+)\)|([\d.:a-fA-F]+))")
_NMAP_PORT = re.compile(
    r"^(\d{1,5})/(tcp|udp)[ \t]+(open|filtered|open\|filtered|closed)"
    r"[ \t]+(\S+)(?:[ \t]+([^\n]*))?$",
    re.M)
_NMAP_OS = re.compile(r"(?:Service Info: OS|OS details|Running):\s*([^\n;]+)", re.I)


def parse_nmap(text: str) -> list[dict[str, Any]]:
    """Parse nmap normal output into hosts. Tolerant of partial/streaming output;
    port lines are attributed to the most recent 'scan report' host (or 'unknown')."""
    if "/tcp" not in text and "/udp" not in text and "Nmap scan report" not in text:
        return []
    hosts: dict[str, dict[str, Any]] = {}

    # Pre-locate host headers with their positions so we can attribute ports.
    headers = [(m.start(), (m.group(2) or m.group(1) or m.group(3) or "unknown"),
                m.group(1) or "") for m in _NMAP_HOST.finditer(text)]

    def host_for(pos: int) -> str:
        key = "unknown"
        for start, k, _name in headers:
            if start <= pos:
                key = k
            else:
                break
        return key

    for m in headers:
        hosts.setdefault(m[1], {"host": m[1], "hostname": m[2], "ports": {}, "os": ""})

    for m in _NMAP_PORT.finditer(text):
        key = host_for(m.start())
        h = hosts.setdefault(key, {"host": key, "hostname": "", "ports": {}, "os": ""})
        if "open" not in m.group(3):
            continue
        h["ports"][f"{m.group(1)}/{m.group(2)}"] = {
            "port": m.group(1), "proto": m.group(2), "state": m.group(3),
            "service": m.group(4), "version": (m.group(5) or "").strip()[:120],
        }
    os_m = _NMAP_OS.search(text)
    if os_m and hosts:
        # Best-effort: attach OS to the (single) host most likely scanned.
        list(hosts.values())[-1]["os"] = os_m.group(1).strip()[:120]

    return [h for h in hosts.values() if h["ports"] or h["host"] != "unknown"]


# --- artifacts --------------------------------------------------------------
# (type, confidence, regex). Crypt/argon2 are high-confidence; bare hex is
# "maybe" (could be an etag / git sha) but flagged because it shouldn't usually
# appear in responses/terminals and is cheap to verify.
_ARTIFACTS: list[tuple[str, str, re.Pattern[str]]] = [
    ("bcrypt", "high", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    ("sha512crypt", "high", re.compile(r"\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}")),
    ("sha256crypt", "high", re.compile(r"\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}")),
    ("md5crypt", "high", re.compile(r"\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}")),
    ("argon2", "high", re.compile(r"\$argon2(?:id|i|d)\$[^\s$]+\$[^\s$]+\$[A-Za-z0-9+/]{16,}")),
    ("sha512", "low", re.compile(r"(?<![a-f0-9])[a-f0-9]{128}(?![a-f0-9])")),
    ("sha256", "low", re.compile(r"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])")),
    ("sha1", "low", re.compile(r"(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])")),
    ("md5/ntlm", "low", re.compile(r"(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])")),
]
_CRED = re.compile(
    r"(?i)\b(user(?:name)?|login|pass(?:word|wd)?)\b\s*[:=]\s*[\"']?([^\s\"'&,;:]{3,40})")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_MAX = 200_000


def extract_artifacts(text: str, source: str) -> list[dict[str, Any]]:
    if not text:
        return []
    text = text[:_MAX]
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(typ, value, conf, ctx=""):
        key = (typ, value)
        if key in seen:
            return
        seen.add(key)
        out.append({"type": typ, "value": value[:200], "confidence": conf,
                    "source": source, "context": ctx[:120]})

    for typ, conf, rx in _ARTIFACTS:
        for m in rx.finditer(text):
            add(typ, m.group(0), conf)
            if len(out) > 200:
                return out
    for m in _CRED.finditer(text):
        add("credential", f"{m.group(1).lower()}={m.group(2)}", "medium")
    for m in _EMAIL.finditer(text):
        add("email", m.group(0), "info")
    return out


# Artifact types worth raising as alerts (findings), with severity.
_FINDING_SEV = {"bcrypt": "medium", "sha512crypt": "medium", "sha256crypt": "medium",
                "md5crypt": "medium", "argon2": "medium", "credential": "medium",
                "md5/ntlm": "low", "sha1": "low", "sha256": "low", "sha512": "low"}


def artifacts_to_findings(artifacts: list[dict[str, Any]], url: str = "",
                          method: str = "") -> list[dict[str, Any]]:
    """Surface notable artifacts in the findings/alert feed too."""
    out = []
    for a in artifacts:
        sev = _FINDING_SEV.get(a["type"])
        if not sev:
            continue
        out.append({
            "severity": sev, "category": "loot", "rule": f"artifact_{a['type']}",
            "title": f"{a['type']} found", "evidence": a["value"],
            "where": a["source"], "url": url, "method": method, "source": a["source"],
            "key": f"artifact|{a['type']}|{a['value'][:80]}",
        })
    return out
