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

from . import budget, config, llm, providers, screenshot
from .state import STATE

app = FastAPI(title="ctf-brain aggregator", version="0.1.0")

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
    STATE.set_browser(payload)
    return {"ok": True}


@app.post("/xhr")
async def recv_xhr(payload: dict[str, Any]) -> dict[str, Any]:
    STATE.add_xhr(payload)
    return {"ok": True}


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

    ctx = budget.build_context(STATE.snapshot())

    image_b64: str | None = None
    if want_shot:
        image_b64 = await asyncio.to_thread(screenshot.capture_b64)
    else:
        # Use any screenshot already captured via the hotkey/flag.
        image_b64 = STATE.consume_screenshot()

    async def gen():
        async for chunk in llm.stream_reply(messages, ctx["rendered"], image_b64):
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=config.HOST, port=config.PORT, log_level="info")


if __name__ == "__main__":
    main()
