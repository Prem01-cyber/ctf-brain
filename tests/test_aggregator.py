"""Tests for the aggregator: token budget, state, and the HTTP surface."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from aggregator import budget, config, llm, providers, screenshot
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
