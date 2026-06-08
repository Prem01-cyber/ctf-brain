"""Tests for the aggregator: token budget, state, and the HTTP surface."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from aggregator import budget, config, detect, llm, providers, screenshot
from aggregator.main import app
from aggregator.state import STATE


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
    STATE.last_pane_update = None
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

    async def fake_stream(messages, rendered_context, image_b64=None):
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

    async def fake_stream(messages, rendered_context, image_b64=None):
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
