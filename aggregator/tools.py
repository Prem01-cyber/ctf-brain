"""Agent tools — provider-neutral specs + an async executor.

These let the chat model investigate instead of only advising: read findings and
the recon inventory, fetch a captured flow's full body, decode strings, send HTTP
requests (the Repeater), and — only when the operator opts in — run a command in
a tmux pane. Specs are converted to each provider's tool format in providers.py.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from typing import Any

import httpx

from . import decoders, detect, engagement
from .state import STATE

# Provider-neutral tool specs: name, description, JSON-schema properties, required.
TOOLS: list[dict[str, Any]] = [
    {"name": "list_findings",
     "description": "List auto-flagged findings (secrets, flags, injection signals, "
                    "exposed endpoints, misconfig) from observed traffic.",
     "properties": {"severity": {"type": "string",
                                 "enum": ["high", "medium", "low", "info"],
                                 "description": "optional severity filter"}},
     "required": []},
    {"name": "get_inventory",
     "description": "Recon inventory: discovered endpoints, parameters (injection "
                    "candidates), and links found in pages/JS.",
     "properties": {}, "required": []},
    {"name": "get_flow",
     "description": "Fetch the most recent captured HTTP flow whose URL contains the "
                    "given substring, including request/response headers and bodies.",
     "properties": {"match": {"type": "string", "description": "URL substring to match"}},
     "required": ["match"]},
    {"name": "decode",
     "description": "Decode a string: JWT (decoded + weaknesses) and CyberChef-magic "
                    "(base64/hex/url/rot13/gzip chains). Use on tokens/encoded blobs.",
     "properties": {"text": {"type": "string"}}, "required": ["text"]},
    {"name": "http_request",
     "description": "Send an HTTP request and return status, headers, and body (the "
                    "Repeater). Use to probe/verify — e.g. test an injection or hit an "
                    "endpoint. Response is also auto-scanned for findings.",
     "properties": {
         "method": {"type": "string"},
         "url": {"type": "string"},
         "headers": {"type": "object", "description": "header name->value"},
         "body": {"type": "string"}},
     "required": ["method", "url"]},
    {"name": "get_engagement",
     "description": "The dynamic engagement picture: current phase, discovered "
                    "assets (hosts/ports/endpoints/params/creds/flags), and "
                    "context-driven next steps. Read this to plan.",
     "properties": {}, "required": []},
    {"name": "add_note",
     "description": "Record a note/observation in the session's engagement state.",
     "properties": {"text": {"type": "string"}}, "required": ["text"]},
    {"name": "add_task",
     "description": "Add a follow-up task to the session checklist.",
     "properties": {"text": {"type": "string"}}, "required": ["text"]},
    {"name": "record_flag",
     "description": "Record a captured flag for this session.",
     "properties": {"flag": {"type": "string"}}, "required": ["flag"]},
    {"name": "record_finding",
     "description": "Record a confirmed security finding/observation (shows in the "
                    "Signals panel). Use while investigating to persist what you found.",
     "properties": {"title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "medium", "low", "info"]},
                    "detail": {"type": "string"}},
     "required": ["title"]},
    {"name": "read_file",
     "description": "Read a local file (e.g. /etc/hosts, a config, source, loot, scan "
                    "output) to understand the real environment. Read-only; use this "
                    "instead of a shell cat.",
     "properties": {"path": {"type": "string"},
                    "max_bytes": {"type": "integer", "description": "default 20000"}},
     "required": ["path"]},
    {"name": "list_dir",
     "description": "List a local directory to see what files exist (instead of shell ls).",
     "properties": {"path": {"type": "string"}}, "required": ["path"]},
    {"name": "grep_files",
     "description": "Search a regex across files under a directory (instead of shell grep).",
     "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}},
     "required": ["pattern", "path"]},
    {"name": "lookup_vulns",
     "description": "Look up known CVEs for a software product + version (live NVD "
                    "+ CISA known-exploited catalog). Use on discovered service versions.",
     "properties": {"product": {"type": "string", "description": "e.g. 'Apache httpd' or 'OpenSSH'"},
                    "version": {"type": "string"}},
     "required": ["product"]},
    {"name": "parse_output",
     "description": "LLM-parse raw tool output (nmap/gobuster/etc.) into the knowledge "
                    "base (hosts/ports/services/creds). Pass the text to structure.",
     "properties": {"text": {"type": "string"}}, "required": ["text"]},
    {"name": "run_command",
     "description": "Run a shell command in a tmux pane and return its output. Use for "
                    "scans/enumeration (nmap, ffuf, curl). Requires the operator to have "
                    "enabled command execution.",
     "properties": {
         "command": {"type": "string"},
         "pane": {"type": "string", "description": "target like session:win.pane; "
                                                   "defaults to the active pane"}},
     "required": ["command"]},
]


async def replay_request(method: str, url: str, headers: dict | None = None,
                         body: str | None = None) -> dict[str, Any]:
    """Send a request server-side, scan the response, record it. Shared by /replay
    and the http_request tool."""
    method = (method or "GET").upper()
    headers = headers or {}
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=20) as c:
        r = await c.request(method, url, headers=headers, content=body)
    flow = {"source": "replay", "method": method, "url": url, "status": r.status_code,
            "req_headers": headers, "req_body": body,
            "resp_headers": dict(r.headers), "resp_body": r.text}
    findings = detect.scan_flow(flow)
    STATE.update_inventory(flow)
    STATE.add_flow({"method": method, "url": url, "status": r.status_code,
                    "source": "replay", "findings": len(findings)}, findings)
    return {"status": r.status_code, "headers": dict(r.headers), "body": r.text,
            "elapsed_ms": int(r.elapsed.total_seconds() * 1000), "findings": findings}


def _tmux_send(pane: str | None, command: str) -> str:
    target = pane or next(
        (f"{p['session']}:{p['window']}.{p['pane']}"
         for p in STATE.snapshot()["panes"].values() if p.get("active")), None)
    if not target:
        return "error: no active tmux pane found (specify one as session:win.pane)"
    try:
        subprocess.run(["tmux", "send-keys", "-t", target, command, "Enter"],
                       check=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as e:
        return f"error sending to tmux: {e}"
    return target


async def run_tool(name: str, args: dict[str, Any], allow_exec: bool = False) -> str:
    """Execute a tool call and return a compact string result."""
    try:
        if name == "list_findings":
            sev = args.get("severity")
            fs = sorted(STATE.get_findings(), key=lambda f: detect.severity_rank(f["severity"]))
            if sev:
                fs = [f for f in fs if f["severity"] == sev]
            if not fs:
                return "no findings"
            return "\n".join(f"[{f['severity']}] {f['rule']}: {f['title']} — "
                             f"{f['method']} {f['url']} ({f['where']}: {f['evidence']})"
                             for f in fs[:60])

        if name == "get_inventory":
            inv = STATE.get_inventory()
            return json.dumps(inv)[:6000]

        if name == "get_flow":
            match = args.get("match", "")
            flows = [f for f in STATE.get_flows_full() if match in f.get("url", "")]
            if not flows:
                return f"no captured flow matching {match!r}"
            f = flows[-1]
            return json.dumps({
                "method": f["method"], "url": f["url"], "status": f["status"],
                "req_headers": f["req_headers"], "req_body": f["req_body"],
                "resp_headers": f["resp_headers"], "resp_body": (f["resp_body"] or "")[:8000],
            })[:9000]

        if name == "decode":
            text = args.get("text", "")
            jwt = decoders.decode_jwt(text.strip().split()[0]) if text.strip().startswith("eyJ") else None
            magic = decoders.magic(text)
            return json.dumps({"jwt": jwt, "magic": magic})[:6000]

        if name == "http_request":
            res = await replay_request(args.get("method", "GET"), args.get("url", ""),
                                       args.get("headers"), args.get("body"))
            hdrs = {k: res["headers"].get(k) for k in ("content-type", "location", "server")
                    if res["headers"].get(k)}
            return json.dumps({"status": res["status"], "headers": hdrs,
                               "body": res["body"][:8000],
                               "findings": [f["title"] for f in res["findings"]]})[:9000]

        if name == "get_engagement":
            eng = engagement.derive(STATE.snapshot())
            return json.dumps({k: eng[k] for k in
                               ("phase", "assets", "findings_summary", "flags",
                                "next_steps", "tasks")})[:7000]

        if name == "add_note":
            STATE.add_note(args.get("text", ""))
            return "note recorded"

        if name == "add_task":
            STATE.add_task(args.get("text", ""))
            return "task added"

        if name == "record_flag":
            return "flag recorded" if STATE.add_flag(args.get("flag", "")) else "already recorded"

        if name == "record_finding":
            sev = args.get("severity", "medium")
            sev = sev if sev in ("high", "medium", "low", "info") else "medium"
            title = str(args.get("title", ""))[:200]
            STATE.add_findings([{
                "severity": sev, "category": "analysis", "rule": "agent", "title": title,
                "evidence": str(args.get("detail", ""))[:280], "where": "agent",
                "url": "", "method": "", "source": "agent", "key": f"agent|{title[:80]}"}])
            return "finding recorded"

        if name == "read_file":
            path = os.path.expanduser(args.get("path", ""))
            n = int(args.get("max_bytes", 20000) or 20000)
            try:
                with open(path, "rb") as fh:
                    raw = fh.read(n + 1)
            except OSError as e:
                return f"error reading {path}: {e}"
            truncated = len(raw) > n
            try:
                text = raw[:n].decode("utf-8")
            except UnicodeDecodeError:
                return f"{path}: binary file ({len(raw)} bytes); not shown"
            return f"--- {path} ---\n{text}" + ("\n…(truncated)" if truncated else "")

        if name == "list_dir":
            path = os.path.expanduser(args.get("path", "."))
            try:
                entries = sorted(os.listdir(path))
            except OSError as e:
                return f"error listing {path}: {e}"
            rows = []
            for e in entries[:300]:
                full = os.path.join(path, e)
                rows.append(f"{'d' if os.path.isdir(full) else '-'} {e}")
            return f"--- {path} ---\n" + "\n".join(rows)

        if name == "grep_files":
            pattern, path = args.get("pattern", ""), os.path.expanduser(args.get("path", "."))
            argv = (["rg", "-n", "--no-heading", "-S", pattern, path] if shutil.which("rg")
                    else ["grep", "-rnI", "-e", pattern, path])
            try:
                out = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            except (OSError, subprocess.SubprocessError) as e:
                return f"error: {e}"
            return (out.stdout or out.stderr or "no matches")[:5000]

        if name == "lookup_vulns":
            from . import vulndb
            res = await vulndb.lookup(args.get("product", ""), args.get("version", ""))
            return json.dumps({"product": res["product"], "version": res["version"],
                               "kev_count": res["kev_count"],
                               "cves": [{"id": c["id"], "severity": c["severity"],
                                         "cvss": c["cvss"], "kev": c.get("kev"),
                                         "summary": (c.get("summary") or "")[:160]}
                                        for c in res["cves"]]})[:7000]

        if name == "parse_output":
            from . import llm_extract
            data = await llm_extract.parse_output(args.get("text", ""))
            counts = llm_extract.merge(data)
            return json.dumps({"merged": counts, "parsed": data})[:6000]

        if name == "run_command":
            if not allow_exec:
                return ("execution is disabled — the operator must enable the 'allow run' "
                        "toggle. If you only need to READ a file, use read_file/list_dir/"
                        "grep_files instead (those don't require execution). Otherwise "
                        "suggest the command for the operator to run.")
            target = _tmux_send(args.get("pane"), args["command"])
            if target.startswith("error"):
                return target
            await asyncio.sleep(2.0)  # let it produce output
            out = subprocess.run(["tmux", "capture-pane", "-p", "-t", target, "-S", "-40"],
                                 capture_output=True, text=True, timeout=5)
            return f"(ran in {target})\n{out.stdout[-3000:]}"

        return f"unknown tool: {name}"
    except Exception as e:  # noqa: BLE001
        return f"tool error: {e}"
