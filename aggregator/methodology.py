"""Pentest / CTF methodology — a phase playbook the assistant follows, plus a
checklist the UI can show. Keeps the assistant proposing *phase-appropriate*
next steps (recon → scan → enumerate → exploit → ...) instead of ad-hoc tips.
"""
from __future__ import annotations

from typing import Any

# Ordered phases with concrete, copy-pasteable actions.
PHASES: list[dict[str, Any]] = [
    {"phase": "Recon", "goal": "Map the attack surface.",
     "steps": [
         "Identify scope/targets; resolve hosts (host, dig, whois).",
         "Passive: wappalyzer/whatweb for tech stack; read robots.txt, sitemap.xml, .well-known.",
         "Spider links + JS for endpoints/params (this tool's inventory does it passively)."]},
    {"phase": "Scanning", "goal": "Find open ports and services.",
     "steps": [
         "nmap -sCV -p- -oA scan <target> (then targeted -sU for UDP).",
         "Note versions → search exploits (searchsploit <service> <version>).",
         "For web ports: note vhosts (add to /etc/hosts), TLS info."]},
    {"phase": "Enumeration", "goal": "Dig into each service.",
     "steps": [
         "Web: dir/file brute (ffuf -u http://t/FUZZ -w wordlist), vhost fuzz (-H 'Host: FUZZ.t').",
         "Find params (this tool mines them) → test each input.",
         "Check default creds, exposed .git/.env/backups (auto-flagged here), API docs/graphql.",
         "Services: SMB (enum4linux-ng), SNMP, NFS, LDAP, DBs as found."]},
    {"phase": "Exploitation", "goal": "Get a foothold.",
     "steps": [
         "Web: test SQLi (sqlmap), XSS, SSTI, LFI/RFI, command injection, file upload, auth bypass.",
         "Tamper JWTs (alg=none / weak HMAC — decoded & flagged here).",
         "Use the Repeater to iterate on a single request quickly.",
         "Get a reverse shell; stabilize (python pty, stty raw)."]},
    {"phase": "Post-exploitation", "goal": "Escalate and loot.",
     "steps": [
         "Local enum (linpeas/winpeas), sudo -l, SUID, cron, capabilities.",
         "Loot creds/keys/configs; pivot; collect flags (user.txt/root.txt).",
         "Document everything for the report."]},
]


def system_block() -> str:
    """Compact methodology framing for the chat system prompt."""
    lines = ["METHODOLOGY — always anchor advice to the right phase and name it:"]
    for p in PHASES:
        lines.append(f"- {p['phase']}: {p['goal']}")
    lines.append("When asked 'what next', infer the current phase from the live context "
                 "(open ports, discovered endpoints/params, findings) and give the 2-3 most "
                 "valuable concrete next actions with exact commands.")
    return "\n".join(lines)


def checklist() -> list[dict[str, Any]]:
    return PHASES
