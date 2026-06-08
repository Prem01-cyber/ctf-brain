"""FastAPI aggregator daemon — the brain.

Collectors POST live state here; the chat UI reads /context and streams /chat.
Run with:  python -m aggregator.main   (or via start.sh / uvicorn)
"""
from __future__ import annotations

import asyncio
import pathlib
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

import contextlib

from . import (budget, config, decoders, detect, engagement, llm, methodology,
               providers, screenshot, tools)
from .state import STATE

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the configured engagement and autosave it periodically + on shutdown.
    STATE.load(config.SESSION)

    async def autosave():
        while True:
            await asyncio.sleep(15)
            await asyncio.to_thread(STATE.save)

    task = asyncio.ensure_future(autosave())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(Exception):
            await asyncio.to_thread(STATE.save, True)


app = FastAPI(title="ctf-brain aggregator", version="0.1.0", lifespan=lifespan)

# Local tool: the browser extension and UI both call cross-origin to localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_UI_INDEX = pathlib.Path(__file__).resolve().parent.parent / "ui" / "index.html"


# --- UI --------------------------------------------------------------------
@app.get("/")
async def index() -> Any:
    if _UI_INDEX.exists():
        return FileResponse(_UI_INDEX)
    return JSONResponse({"error": "ui/index.html not found"}, status_code=404)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "ok": True,
        "provider": config.PROVIDER,
        "model": config.MODEL,
        "api_key": llm.has_api_key(),
        "providers": {name: p.available() for name, p in providers._REGISTRY.items()},
        "screenshot_backend": screenshot.available_backend(),
        "screenshot_working": await asyncio.to_thread(screenshot.probe),
    }


@app.get("/status")
async def status() -> dict[str, Any]:
    # The UI polls this; piggyback the hotkey-triggered screenshot capture here
    # so a WM keybind that `touch`es the flag file just works.
    if screenshot.flag_requested():
        b64 = await asyncio.to_thread(screenshot.capture_b64)
        STATE.set_screenshot(b64)
    return STATE.status()


# --- Collector intake ------------------------------------------------------
@app.post("/panes")
async def recv_panes(payload: dict[str, Any]) -> dict[str, Any]:
    panes = payload.get("panes", payload)  # accept {"panes": {...}} or a bare map
    if not isinstance(panes, dict):
        return {"ok": False, "error": "expected an object of panes"}
    STATE.set_panes(panes)
    return {"ok": True, "panes": len(panes)}


@app.post("/browser")
async def recv_browser(payload: dict[str, Any]) -> dict[str, Any]:
    # Respect target scope so out-of-scope pages (your own browsing) don't leak
    # into the context.
    if not STATE.in_scope(payload.get("url", "")):
        return {"ok": True, "skipped": "out-of-scope"}
    STATE.set_browser(payload)
    return {"ok": True}


@app.post("/xhr")
async def recv_xhr(payload: dict[str, Any]) -> dict[str, Any]:
    STATE.add_xhr(payload)
    return {"ok": True}


@app.post("/flow")
async def recv_flow(payload: dict[str, Any]) -> dict[str, Any]:
    """Ingest an HTTP flow (from the extension hook or the mitmproxy addon),
    scan it for findings, and store a compact summary + any new findings."""
    if not STATE.in_scope(payload.get("url", "")):
        return {"ok": True, "skipped": "out-of-scope"}
    findings = detect.scan_flow(payload)
    summary = {
        "method": payload.get("method", "GET"),
        "url": payload.get("url", ""),
        "status": payload.get("status"),
        "source": payload.get("source", ""),
        "t": payload.get("t"),
        "findings": len(findings),
    }
    # Keep the lightweight recent-requests list (browser context) in sync.
    STATE.add_xhr({
        "method": summary["method"], "url": summary["url"], "status": summary["status"],
    })
    STATE.update_inventory(payload)
    added = STATE.add_flow(summary, findings)
    return {"ok": True, "findings": len(findings), "new": added}


@app.get("/findings")
async def get_findings() -> dict[str, Any]:
    findings = sorted(STATE.get_findings(), key=lambda f: detect.severity_rank(f["severity"]))
    return {"count": len(findings), "findings": findings}


@app.get("/inventory")
async def get_inventory() -> dict[str, Any]:
    return STATE.get_inventory()


@app.get("/methodology")
async def get_methodology() -> dict[str, Any]:
    return {"phases": methodology.checklist()}


@app.get("/engagement")
async def get_engagement() -> dict[str, Any]:
    """Dynamic engagement view: inferred phase, discovered assets, and the
    context-driven next steps + tracked notes/tasks/flags for this session."""
    return engagement.derive(STATE.snapshot())


@app.post("/note")
async def add_note(payload: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "note": STATE.add_note(payload.get("text", ""))}


@app.post("/task")
async def add_task(payload: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "task": STATE.add_task(payload.get("text", ""), payload.get("done", False))}


@app.post("/task/toggle")
async def toggle_task(payload: dict[str, Any]) -> dict[str, Any]:
    return {"ok": STATE.toggle_task(int(payload.get("id", -1)), payload.get("done"))}


@app.post("/flag")
async def add_flag(payload: dict[str, Any]) -> dict[str, Any]:
    return {"ok": STATE.add_flag(str(payload.get("flag", "")))}


@app.get("/sessions")
async def list_sessions() -> dict[str, Any]:
    return {"current": STATE.session, "sessions": STATE.list_sessions()}


@app.post("/session")
async def switch_session(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name", "")).strip() or "default"
    return {"ok": True, "status": await asyncio.to_thread(STATE.switch_session, name)}


@app.post("/decode")
async def decode(payload: dict[str, Any]) -> dict[str, Any]:
    text = str(payload.get("text", ""))
    jwt_part = text.strip().split()[0] if text.strip() else ""
    return {
        "jwt": decoders.decode_jwt(jwt_part) if jwt_part.startswith("eyJ") else None,
        "magic": decoders.magic(text),
    }


@app.post("/replay")
async def replay(payload: dict[str, Any]) -> dict[str, Any]:
    """Repeater: resend a (possibly modified) request server-side and return the
    response (also scanned for findings). The browser can't do this cross-origin."""
    if not payload.get("url"):
        return {"ok": False, "error": "url required"}
    try:
        res = await tools.replay_request(
            payload.get("method", "GET"), payload["url"],
            payload.get("headers"), payload.get("body"))
        return {"ok": True, "status": res["status"], "headers": res["headers"],
                "body": res["body"][:200_000], "elapsed_ms": res["elapsed_ms"],
                "findings": len(res["findings"])}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


@app.get("/flows")
async def get_flows() -> dict[str, Any]:
    """Recent full flows (for seeding the Repeater)."""
    return {"flows": STATE.get_flows_full()}


@app.get("/scope")
async def get_scope() -> dict[str, Any]:
    return {"scope": STATE.get_scope()}


@app.post("/scope")
async def set_scope(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("scope", [])
    items = raw.split(",") if isinstance(raw, str) else list(raw)
    STATE.set_scope(items)
    return {"ok": True, "scope": STATE.get_scope()}


@app.post("/app/{name}")
async def recv_app(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    line = payload.get("line", "")
    ok = STATE.add_app_log(name, str(line))
    return {"ok": ok}


@app.post("/screenshot/request")
async def request_screenshot() -> dict[str, Any]:
    """Capture immediately and hold it as pending for the next chat message."""
    b64 = await asyncio.to_thread(screenshot.capture_b64)
    STATE.set_screenshot(b64)
    return {"ok": bool(b64), "backend": screenshot.available_backend()}


# --- Context + chat --------------------------------------------------------
@app.get("/context")
async def get_context() -> dict[str, Any]:
    ctx = budget.build_context(STATE.snapshot())
    return ctx


@app.post("/chat")
async def chat(payload: dict[str, Any], request: Request) -> Any:
    messages = payload.get("messages", [])
    want_shot = bool(payload.get("screenshot"))
    agent = bool(payload.get("agent"))
    allow_exec = bool(payload.get("allow_exec"))

    ctx = budget.build_context(STATE.snapshot())

    image_b64: str | None = None
    if want_shot:
        image_b64 = await asyncio.to_thread(screenshot.capture_b64)
    else:
        # Use any screenshot already captured via the hotkey/flag.
        image_b64 = STATE.consume_screenshot()

    async def gen():
        async for chunk in llm.stream_reply(messages, ctx["rendered"], image_b64,
                                            agent=agent, allow_exec=allow_exec):
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=config.HOST, port=config.PORT, log_level="info")


if __name__ == "__main__":
    main()
