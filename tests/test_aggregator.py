"""Tests for the aggregator: token budget, state, and the HTTP surface."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

import base64
import json

from aggregator import budget, config, decoders, detect, llm, providers, screenshot, tools
from aggregator.main import app
from aggregator.state import STATE


def _jwt(header, payload):
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}."


@pytest.fixture(autouse=True)
def reset_state():
    """Each test starts from a clean singleton."""
    STATE.panes = {}
    STATE.browser = None
    STATE.screenshot = None
    STATE.burp.clear()
    STATE.wireshark.clear()
    STATE.flows.clear()
    STATE.findings = []
    STATE._finding_keys = set()
    STATE.scope = []
    STATE.endpoints = {}
    STATE.params = set()
    STATE.links = set()
    STATE.flows_full.clear()
    STATE.notes = []
    STATE.tasks = []
    STATE.flags = []
    STATE.hosts = {}
    STATE.artifacts = []
    STATE._artifact_keys = set()
    STATE._last_pane_hash = None
    STATE.session = "default"
    STATE._counter = 0
    STATE._dirty = False
    STATE._vuln_queried = set()
    STATE.last_pane_update = None
    # Don't fire live NVD lookups or LLM parses from the pipeline during tests.
    config.VULN_LOOKUP = False
    config.AUTO_PARSE = False
    import aggregator.main as _m
    _m._pane_track.clear()
    yield


@pytest.fixture
def client():
    return TestClient(app)


def _pane(session, win, pane, cmd, content, active=False):
    return {
        "session": session, "window": win, "pane": pane, "command": cmd,
        "active": active, "content": content, "updated": time.time(),
    }


# --- budget ----------------------------------------------------------------
def test_budget_orders_active_pane_first():
    state = {
        "panes": {
            "a:0:0": _pane("a", "0", "0", "vim", "idle notes here", active=False),
            "a:0:1": _pane("a", "0", "1", "python", "EXPLOIT OUTPUT", active=True),
        },
    }
    ctx = budget.build_context(state)
    a = ctx["rendered"].index("EXPLOIT OUTPUT")
    b = ctx["rendered"].index("idle notes here")
    assert a < b, "active pane should render before inactive"
    assert "(ACTIVE)" in ctx["rendered"]


def test_budget_truncates_to_token_limit():
    big = "\n".join(f"line {i} " + "x" * 80 for i in range(500))
    state = {"panes": {f"s:0:{i}": _pane("s", "0", str(i), "bash", big) for i in range(10)}}
    ctx = budget.build_context(state, budget_tokens=500)
    assert ctx["truncated"] is True
    assert ctx["tokens"] <= 500


def test_budget_drops_stale_browser():
    stale = {"url": "http://old", "title": "old", "timestamp_recv": time.time() - 9999}
    fresh = {"url": "http://new", "title": "new", "timestamp_recv": time.time()}
    assert "old" not in budget.build_context({"browser": stale})["rendered"]
    assert "http://new" in budget.build_context({"browser": fresh})["rendered"]


def test_budget_empty_state():
    ctx = budget.build_context({})
    assert ctx["tokens"] >= 0
    assert "no live context" in ctx["rendered"]


# --- state -----------------------------------------------------------------
def test_state_status_reports_active_pane():
    STATE.set_panes({"x:1:2": _pane("x", "1", "2", "nc", "listening", active=True)})
    st = STATE.status()
    assert st["panes"] == 1
    assert st["active_pane"] == "x:1.2"


def test_state_xhr_window_caps_at_30():
    for i in range(40):
        STATE.add_xhr({"method": "GET", "url": f"/{i}", "status": 200})
    assert len(STATE.browser["xhr"]) == 30


def test_consume_screenshot_is_one_shot():
    STATE.set_screenshot("ZmFrZQ==")
    assert STATE.consume_screenshot() == "ZmFrZQ=="
    assert STATE.consume_screenshot() is None


# --- HTTP ------------------------------------------------------------------
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["model"] == config.MODEL


def test_panes_intake_and_context(client):
    panes = {"s:0:0": _pane("s", "0", "0", "bash", "nmap scan results", active=True)}
    assert client.post("/panes", json={"panes": panes}).json()["ok"] is True
    ctx = client.get("/context").json()
    assert "nmap scan results" in ctx["rendered"]
    assert client.get("/status").json()["active_pane"] == "s:0.0"


def test_browser_and_app_intake(client):
    client.post("/browser", json={"url": "http://target/login", "title": "Login",
                                  "selected": "admin' OR 1=1"})
    client.post("/app/burp", json={"line": "POST /login 200"})
    ctx = client.get("/context").json()["rendered"]
    assert "http://target/login" in ctx
    assert "admin' OR 1=1" in ctx
    assert "POST /login 200" in ctx


def test_app_intake_rejects_unknown(client):
    assert client.post("/app/nonsense", json={"line": "x"}).json()["ok"] is False


def test_chat_streams_with_context(client, monkeypatch):
    client.post("/panes", json={"panes": {"s:0:0": _pane("s", "0", "0", "bash",
                                                          "PORT 8080 open", active=True)}})

    captured = {}

    async def fake_stream(messages, rendered_context, image_b64=None, **kw):
        captured["context"] = rendered_context
        captured["image"] = image_b64
        yield "do "
        yield "this"

    monkeypatch.setattr(llm, "stream_reply", fake_stream)
    r = client.post("/chat", json={"messages": [{"role": "user", "content": "next?"}]})
    assert r.status_code == 200
    assert r.text == "do this"
    assert "PORT 8080 open" in captured["context"]
    assert captured["image"] is None


def test_chat_attaches_screenshot(client, monkeypatch):
    monkeypatch.setattr(screenshot, "capture_b64", lambda: "QUJD")

    async def fake_stream(messages, rendered_context, image_b64=None, **kw):
        assert image_b64 == "QUJD"
        yield "ok"

    monkeypatch.setattr(llm, "stream_reply", fake_stream)
    r = client.post("/chat", json={"messages": [{"role": "user", "content": "see this"}],
                                   "screenshot": True})
    assert r.text == "ok"


def test_screenshot_request_endpoint(client, monkeypatch):
    monkeypatch.setattr(screenshot, "capture_b64", lambda: "UE5H")
    assert client.post("/screenshot/request").json()["ok"] is True
    assert client.get("/status").json()["screenshot_pending"] is True


# --- llm helpers -----------------------------------------------------------
def test_attach_image_wraps_last_user_turn():
    msgs = [{"role": "user", "content": "hello"}]
    out = llm._attach_image(msgs, "aW1n")
    blocks = out[0]["content"]
    assert blocks[0] == {"type": "text", "text": "hello"}
    assert blocks[1]["type"] == "image"
    assert blocks[1]["source"]["data"] == "aW1n"


def test_system_prompt_embeds_context():
    sp = llm.build_system_prompt("PANE DATA HERE")
    assert "PANE DATA HERE" in sp
    assert "CTF-Brain" in sp


# --- providers -------------------------------------------------------------
def test_openai_messages_prepend_system():
    p = providers.OpenAIProvider()
    msgs = p._messages([{"role": "user", "content": "hi"}], "SYS", None)
    assert msgs[0] == {"role": "system", "content": "SYS"}
    assert msgs[1] == {"role": "user", "content": "hi"}


def test_openai_image_uses_data_uri():
    p = providers.OpenAIProvider()
    msgs = p._messages([{"role": "user", "content": "see"}], "SYS", "QUJD")
    blocks = msgs[-1]["content"]
    assert blocks[0] == {"type": "text", "text": "see"}
    assert blocks[1]["type"] == "image_url"
    assert blocks[1]["image_url"]["url"] == "data:image/png;base64,QUJD"


def test_provider_autodetect(monkeypatch):
    monkeypatch.delenv("CTF_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert config._detect_provider() == "openai"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    assert config._detect_provider() == "anthropic"  # anthropic preferred
    monkeypatch.setenv("CTF_PROVIDER", "openai")
    assert config._detect_provider() == "openai"  # explicit wins


def test_get_provider_falls_back_to_anthropic():
    assert providers.get_provider("nonexistent").name == "anthropic"
    assert providers.get_provider("openai").name == "openai"


# --- detection engine ------------------------------------------------------
def _rules(flow):
    return {f["rule"] for f in detect.scan_flow(flow)}


def test_detect_flag_and_secrets_in_body():
    flow = {"url": "http://t/x", "resp_body":
            "welcome flag{w3b_3num} key AKIAIOSFODNN7EXAMPLE done"}
    rules = _rules(flow)
    assert "flag" in rules
    assert "aws_access_key" in rules


def test_detect_private_key_high_severity():
    flow = {"url": "http://t/k", "resp_body": "-----BEGIN RSA PRIVATE KEY-----\nMII..."}
    fs = detect.scan_flow(flow)
    assert any(f["rule"] == "private_key" and f["severity"] == "high" for f in fs)


def test_detect_sql_error_as_injection_signal():
    flow = {"url": "http://t/p?id=1'", "resp_body":
            "You have an error in your SQL syntax near ''' at line 1"}
    assert "sql_error" in _rules(flow)


def test_detect_exposed_endpoints_from_url():
    assert "exposed_vcs" in _rules({"url": "http://t/.git/config"})
    assert "exposed_env" in _rules({"url": "http://t/.env"})
    assert "admin_panel" in _rules({"url": "http://t/admin/"})


def test_detect_cors_and_cookie_misconfig():
    flow = {
        "url": "https://t/api",
        "resp_headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Set-Cookie": "session=abc; Path=/",
        },
    }
    rules = _rules(flow)
    assert "cors_wildcard_creds" in rules
    assert "cookie_no_httponly" in rules
    assert "cookie_no_secure" in rules


def test_detect_clean_flow_is_quiet():
    assert detect.scan_flow({"url": "http://t/style.css", "resp_body": "body{color:red}"}) == []


def test_flag_ignores_minified_js_blocks():
    js = "self.AMP=self.AMP||[];try{n=t.evaluate(r)}finally{r=null}else{x()}"
    assert "flag" not in _rules({"url": "http://t/v0.js", "resp_body": js})


def test_flag_still_matches_real_flag_with_custom_prefix():
    assert "flag" in _rules({"url": "http://t/", "resp_body": "picoCTF{custom_prefix_ok}"})
    assert "flag" in _rules({"url": "http://t/", "resp_body": "HTB{a-real_flag.123}"})


def test_secret_assignment_needs_separator():
    # Prose with a space (no := separator) must not trigger.
    assert "secret_assignment" not in _rules(
        {"url": "http://t/", "resp_body": "manage your password preferences here"})
    assert "secret_assignment" in _rules(
        {"url": "http://t/", "resp_body": 'password="s3cr3tValue"'})


def test_tech_disclosure_dedupes_across_urls():
    # Same Server value on different endpoints → one finding.
    f1 = detect.scan_flow({"url": "http://t/a", "resp_headers": {"Server": "ESF"}})
    f2 = detect.scan_flow({"url": "http://t/b", "resp_headers": {"Server": "ESF"}})
    assert f1[0]["key"] == f2[0]["key"]


def test_finding_key_is_stable_for_dedup():
    flow = {"url": "http://t/x?a=1", "resp_body": "flag{abc}"}
    k1 = detect.scan_flow(flow)[0]["key"]
    flow2 = {"url": "http://t/x?a=2", "resp_body": "flag{abc}"}  # query differs only
    k2 = detect.scan_flow(flow2)[0]["key"]
    assert k1 == k2  # dedup ignores query string


# --- flow ingestion + findings surface -------------------------------------
def test_flow_endpoint_scans_and_dedups(client):
    flow = {"method": "GET", "url": "http://t/.env", "status": 200,
            "resp_body": "DB_PASSWORD=hunter2 flag{env_leak}"}
    r1 = client.post("/flow", json=flow).json()
    assert r1["new"] >= 2  # exposed_env + flag (+ secret_assignment)
    r2 = client.post("/flow", json=flow).json()
    assert r2["new"] == 0  # identical flow → all deduped


def test_findings_appear_in_context_and_endpoint(client):
    client.post("/flow", json={"method": "GET", "url": "http://t/q",
                               "resp_body": "flag{in_context}"})
    assert "flag{in_context}" in client.get("/context").json()["rendered"]
    fr = client.get("/findings").json()
    assert fr["count"] >= 1
    assert fr["findings"][0]["severity"] == "high"  # sorted high-first


def test_status_counts_findings(client):
    client.post("/flow", json={"url": "http://t/.git/config", "method": "GET"})
    st = client.get("/status").json()
    assert st["findings"] >= 1
    assert st["findings_high"] >= 1


# --- target scope ----------------------------------------------------------
def test_scope_filters_out_of_scope_flows(client):
    client.post("/scope", json={"scope": "target.htb"})
    assert client.get("/scope").json()["scope"] == ["target.htb"]
    # Out-of-scope (e.g. your own Gmail) is dropped, no findings.
    r = client.post("/flow", json={"url": "https://mail.google.com/x?key=AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                                   "method": "GET"})
    assert r.json().get("skipped") == "out-of-scope"
    assert client.get("/status").json()["findings"] == 0
    # In-scope target is scanned.
    client.post("/flow", json={"url": "http://target.htb/.git/config", "method": "GET"})
    assert client.get("/status").json()["findings"] >= 1


def test_scope_filters_browser_snapshot(client):
    client.post("/scope", json={"scope": ["target.htb"]})
    client.post("/browser", json={"url": "https://mail.google.com/inbox", "title": "Inbox"})
    assert client.get("/status").json()["browser_url"] is None
    client.post("/browser", json={"url": "http://target.htb/login", "title": "Login"})
    assert client.get("/status").json()["browser_url"] == "http://target.htb/login"


def test_empty_scope_allows_everything(client):
    assert STATE.in_scope("http://anything/") is True


# --- decoders --------------------------------------------------------------
def test_magic_decodes_nested_base64_flag():
    inner = base64.b64encode(b"flag{magic}").decode()
    outer = base64.b64encode(inner.encode()).decode()
    res = decoders.magic(outer)
    assert any(r["flag"] for r in res)


def test_decode_jwt_flags_alg_none():
    d = decoders.decode_jwt(_jwt({"alg": "none"}, {"role": "admin"}))
    assert any("alg=none" in i for i in d["issues"])
    assert d["payload"]["role"] == "admin"


def test_scan_flags_jwt_alg_none_high():
    fs = detect.scan_flow({"url": "http://t/", "resp_body": "t=" + _jwt({"alg": "none"}, {"u": 1})})
    assert any(f["rule"] == "jwt" and f["severity"] == "high" for f in fs)


def test_decode_endpoint(client):
    inner = base64.b64encode(b"flag{endpoint}").decode()
    outer = base64.b64encode(inner.encode()).decode()
    r = client.post("/decode", json={"text": outer}).json()
    assert any(m["flag"] for m in r["magic"])


# --- inventory -------------------------------------------------------------
def test_inventory_mines_params_and_endpoints(client):
    client.post("/flow", json={"method": "POST", "url": "http://t/login?next=/x",
                               "req_body": '{"username":"a","password":"b"}', "status": 200,
                               "resp_body": '<a href="/admin">a</a>'})
    inv = client.get("/inventory").json()
    assert "username" in inv["params"] and "next" in inv["params"]
    assert any(e["path"] == "/login" for e in inv["endpoints"])
    assert "/admin" in inv["links"]
    assert "username" in client.get("/context").json()["rendered"]


def test_methodology_endpoint(client):
    phases = client.get("/methodology").json()["phases"]
    assert [p["phase"] for p in phases][:2] == ["Recon", "Scanning"]


def test_methodology_in_system_prompt():
    assert "METHODOLOGY" in llm.build_system_prompt("ctx")


# --- replay (Repeater) -----------------------------------------------------
def test_replay_resends_and_scans(client, monkeypatch):
    import datetime
    from aggregator import tools as tools_mod

    class FakeResp:
        status_code = 200
        text = "leak flag{replayed}"
        headers = {"content-type": "text/html", "Server": "nginx"}
        elapsed = datetime.timedelta(milliseconds=12)

    class FakeClient:
        def __init__(self, **kw): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, *a, **k): return FakeResp()

    monkeypatch.setattr(tools_mod.httpx, "AsyncClient", FakeClient)
    r = client.post("/replay", json={"method": "GET", "url": "http://t/x"}).json()
    assert r["ok"] and r["status"] == 200
    assert "flag{replayed}" in r["body"]
    assert r["findings"] >= 1


def test_replay_requires_url(client):
    assert client.post("/replay", json={"method": "GET"}).json()["ok"] is False


# --- agent tools -----------------------------------------------------------
def _run(coro):
    import asyncio
    return asyncio.run(coro)


def test_tool_list_findings(client):
    client.post("/flow", json={"url": "http://t/.git/config", "method": "GET"})
    out = _run(tools.run_tool("list_findings", {}))
    assert "exposed_vcs" in out


def test_tool_decode_and_inventory():
    inner = base64.b64encode(b"flag{tool}").decode()
    outer = base64.b64encode(inner.encode()).decode()
    assert "flag{tool}" in _run(tools.run_tool("decode", {"text": outer}))
    assert "endpoints" in _run(tools.run_tool("get_inventory", {}))


def test_tool_run_command_gated():
    out = _run(tools.run_tool("run_command", {"command": "id"}, allow_exec=False))
    assert "disabled" in out


def test_chat_agent_mode_routes_to_stream_agent(client, monkeypatch):
    seen = {}

    async def fake_agent(self, messages, system, image_b64=None, allow_exec=False):
        seen["allow_exec"] = allow_exec
        yield "agent-reply"

    monkeypatch.setattr(providers.OpenAIProvider, "stream_agent", fake_agent)
    monkeypatch.setattr(providers.AnthropicProvider, "stream_agent", fake_agent)
    monkeypatch.setattr(providers.OpenAIProvider, "available", lambda self: True)
    monkeypatch.setattr(providers.AnthropicProvider, "available", lambda self: True)
    r = client.post("/chat", json={"messages": [{"role": "user", "content": "go"}],
                                   "agent": True, "allow_exec": True})
    assert r.text == "agent-reply"
    assert seen["allow_exec"] is True


# --- dynamic engagement ----------------------------------------------------
def test_engagement_phase_and_next_steps(client):
    client.post("/flow", json={"method": "GET", "url": "http://t.htb/p?id=1", "status": 500,
                               "resp_body": "You have an error in your SQL syntax"})
    e = client.get("/engagement").json()
    assert e["phase"] == "Exploitation"
    titles = " ".join(s["title"] for s in e["next_steps"])
    assert "SQLi" in titles
    assert "id" in e["assets"]["params"]


def test_engagement_parses_ports_from_pane(client):
    client.post("/panes", json={"panes": {"a:0:0": _pane("a", "0", "0", "bash",
                "22/tcp open ssh\n80/tcp open http", active=True)}})
    ports = client.get("/engagement").json()["assets"]["open_ports"]
    assert {p["port"] for p in ports} == {"22", "80"}


def test_notes_tasks_flags_tracked(client):
    client.post("/note", json={"text": "LFI on ?file"})
    tid = client.post("/task", json={"text": "run sqlmap"}).json()["task"]["id"]
    client.post("/task/toggle", json={"id": tid, "done": True})
    client.post("/flag", json={"flag": "flag{tracked}"})
    e = client.get("/engagement").json()
    assert e["notes"][0]["text"] == "LFI on ?file"
    assert e["tasks"][0]["done"] is True
    assert "flag{tracked}" in e["flags"]


def test_sessions_isolated_and_persisted(client, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path))
    client.post("/note", json={"text": "alpha note"})        # in 'default'
    client.post("/session", json={"name": "beta"})           # switch (saves default)
    assert client.get("/engagement").json()["notes"] == []   # beta is empty
    client.post("/note", json={"text": "beta note"})
    client.post("/session", json={"name": "default"})        # back
    notes = [n["text"] for n in client.get("/engagement").json()["notes"]]
    assert notes == ["alpha note"]
    assert "beta" in client.get("/sessions").json()["sessions"]


# --- extraction pipeline (auto knowledge base) -----------------------------
NMAP = """Nmap scan report for target.htb (10.10.10.5)
Host is up (0.012s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp   open  http    nginx 1.18.0
3306/tcp open  mysql   MySQL 5.7
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"""


def test_parse_nmap_structured():
    from aggregator import extract
    hosts = extract.parse_nmap(NMAP)
    assert len(hosts) == 1
    h = hosts[0]
    assert h["host"] == "10.10.10.5" and h["hostname"] == "target.htb"
    assert "Linux" in h["os"]
    ports = h["ports"]
    assert ports["80/tcp"]["service"] == "http" and ports["80/tcp"]["version"] == "nginx 1.18.0"
    assert set(p.split("/")[0] for p in ports) == {"22", "80", "3306"}


def test_extract_artifacts_hashes_and_creds():
    from aggregator import extract
    text = ("user:$2a$12$" + "a" * 53 + "\n"
            "md5 5f4dcc3b5aa765d61d8327deb882cf99\n"
            "username = admin\npassword: hunter2\n"
            "contact bob@target.htb")
    arts = {a["type"]: a for a in extract.extract_artifacts(text, "tmux")}
    assert "bcrypt" in arts and arts["bcrypt"]["confidence"] == "high"
    assert "md5/ntlm" in arts
    assert any(a["type"] == "credential" for a in extract.extract_artifacts(text, "tmux"))
    assert "email" in arts


def test_panes_pipeline_builds_host_kb(client):
    client.post("/panes", json={"panes": {"a:0:0": _pane("a", "0", "0", "bash", NMAP, active=True)}})
    hosts = client.get("/hosts").json()["hosts"]
    assert hosts and hosts[0]["host"] == "10.10.10.5"
    svcs = {p["service"] for p in hosts[0]["ports"]}
    assert {"ssh", "http", "mysql"} <= svcs
    e = client.get("/engagement").json()
    assert "mysql" in e["assets"]["services"]
    # mysql is a non-web service → an "enumerate" next-step should appear
    assert any("mysql" in s["title"].lower() for s in e["next_steps"])


def test_flow_pipeline_extracts_and_alerts_hash(client):
    bcrypt = "$2b$10$" + "b" * 53
    r = client.post("/flow", json={"method": "GET", "url": "http://t/dump",
                                   "resp_body": f"row: admin {bcrypt}"}).json()
    assert r["new"] >= 1  # surfaced as a finding too
    arts = client.get("/artifacts").json()["artifacts"]
    assert any(a["type"] == "bcrypt" and a["value"] == bcrypt for a in arts)
    assert any(f["rule"] == "artifact_bcrypt" for f in client.get("/findings").json()["findings"])


def test_artifacts_dedupe_across_calls(client):
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    client.post("/flow", json={"url": "http://t/a", "method": "GET", "resp_body": md5})
    client.post("/flow", json={"url": "http://t/b", "method": "GET", "resp_body": md5})
    vals = [a["value"] for a in client.get("/artifacts").json()["artifacts"]]
    assert vals.count(md5) == 1


# --- vulnerability intelligence --------------------------------------------
_NVD_SAMPLE = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-41773",
    "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
    "references": [{"url": "https://example/advisory"}],
}}]}


def test_vulndb_parses_nvd():
    from aggregator import vulndb
    cves = vulndb._parse_nvd(_NVD_SAMPLE)
    assert cves[0]["id"] == "CVE-2021-41773"
    assert cves[0]["cvss"] == 9.8 and cves[0]["severity"] == "CRITICAL"


def test_vulndb_keyword_candidates_denoise():
    from aggregator import vulndb
    cands = vulndb._keyword_candidates("Apache httpd 2.4.49", "")
    # raw banner kept, plus a denoised variant without 'httpd' that NVD can match
    assert "Apache httpd 2.4.49" in cands
    assert any("httpd" not in c and "2.4.49" in c and "Apache" in c for c in cands)


def test_vulndb_lookup_flags_kev(monkeypatch):
    from aggregator import vulndb

    async def fake_nvd(product, version):
        return vulndb._parse_nvd(_NVD_SAMPLE)
    monkeypatch.setattr(vulndb, "nvd_lookup", fake_nvd)
    monkeypatch.setattr(vulndb, "_kev_by_cve",
                        {"CVE-2021-41773": {"requiredAction": "patch now",
                                            "knownRansomwareCampaignUse": "Known"}})
    res = _run(vulndb.lookup("Apache httpd", "2.4.49"))
    assert res["kev_count"] == 1
    c = res["cves"][0]
    assert c["kev"] is True and c["ransomware"] is True and "patch" in c["exploit"]


def test_vulns_endpoint(client, monkeypatch):
    from aggregator import vulndb

    async def fake_lookup(product, version=""):
        return {"product": product, "version": version, "cves": [{"id": "CVE-1"}], "kev_count": 0}
    monkeypatch.setattr(vulndb, "lookup", fake_lookup)
    assert client.get("/vulns", params={"product": "nginx", "version": "1.18"}).json()["cves"][0]["id"] == "CVE-1"


def test_engagement_surfaces_cve_and_exploit_step(client):
    STATE.merge_hosts([{"host": "10.0.0.1", "ports": {
        "80/tcp": {"port": "80", "proto": "tcp", "state": "open",
                   "service": "http", "version": "Apache httpd 2.4.49"}}}])
    STATE.set_port_vulns("10.0.0.1", "80/tcp", [
        {"id": "CVE-2021-41773", "severity": "CRITICAL", "cvss": 9.8, "kev": True,
         "summary": "Path traversal", "refs": ["https://x"]}])
    e = client.get("/engagement").json()
    assert e["assets"]["vulns"][0]["cve"] == "CVE-2021-41773"
    assert any("CVE-2021-41773" in s["title"] for s in e["next_steps"])


# --- LLM tool-output parsing -----------------------------------------------
def test_llm_extract_json_handles_fences():
    from aggregator import llm_extract
    assert llm_extract._extract_json('```json\n{"a": 1}\n```')["a"] == 1
    assert llm_extract._extract_json('noise {"b": 2} trailing')["b"] == 2
    assert llm_extract._extract_json("not json") == {}


def test_llm_extract_merges_into_kb():
    from aggregator import llm_extract
    counts = llm_extract.merge({"tool": "nmap", "hosts": [
        {"host": "1.2.3.4", "ports": [{"port": "22", "proto": "tcp",
                                       "service": "ssh", "version": "OpenSSH 9.1"}]}],
        "credentials": ["user=root"], "notes": ["box looks like Linux"]})
    assert counts["hosts"] == 1
    assert any(p["service"] == "ssh" for h in STATE.get_hosts() for p in h["ports"])
    assert any(a["value"] == "user=root" for a in STATE.get_artifacts())


def test_parse_endpoint_uses_llm(client, monkeypatch):
    async def fake_complete(self, system, user):
        return '{"hosts": [{"host": "5.6.7.8", "ports": [{"port":"445","proto":"tcp","service":"smb","version":"Samba 4.1"}]}]}'
    monkeypatch.setattr(providers.OpenAIProvider, "complete", fake_complete)
    monkeypatch.setattr(providers.AnthropicProvider, "complete", fake_complete)
    monkeypatch.setattr(providers.OpenAIProvider, "available", lambda self: True)
    monkeypatch.setattr(providers.AnthropicProvider, "available", lambda self: True)
    r = client.post("/parse", json={"text": "443/tcp open ... whatever tool output"}).json()
    assert r["ok"] and r["merged"]["hosts"] == 1
    assert any(h["host"] == "5.6.7.8" for h in client.get("/hosts").json()["hosts"])


def test_tool_lookup_vulns(monkeypatch):
    from aggregator import vulndb

    async def fake_lookup(product, version=""):
        return {"product": product, "version": version, "kev_count": 1,
                "cves": [{"id": "CVE-9", "severity": "HIGH", "cvss": 8.1, "kev": True, "summary": "x"}]}
    monkeypatch.setattr(vulndb, "lookup", fake_lookup)
    assert "CVE-9" in _run(tools.run_tool("lookup_vulns", {"product": "vsftpd", "version": "2.3.4"}))


def test_tool_get_engagement_and_add_note():
    out = _run(tools.run_tool("get_engagement", {}))
    assert "phase" in out
    assert "recorded" in _run(tools.run_tool("add_note", {"text": "from agent"}))
    assert any(n["text"] == "from agent" for n in STATE.notes)
