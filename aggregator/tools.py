"""Agent tools — provider-neutral specs + an async executor.

These let the chat model investigate instead of only advising: read findings and
the recon inventory, fetch a captured flow's full body, decode strings, send HTTP
requests (the Repeater), and — only when the operator opts in — run a command in
a tmux pane. Specs are converted to each provider's tool format in providers.py.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
from typing import Any

import httpx

from . import decoders, detect
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

        if name == "run_command":
            if not allow_exec:
                return ("execution is disabled — the operator must enable the 'allow run' "
                        "toggle before commands can run. Suggest the command instead.")
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
