# ctf-brain

A local "situational awareness" assistant for CTFs and authorized pentests. It
watches your workstation — every **tmux** pane, the page open in your **browser**,
recent **HTTP traffic**, and on-demand **screenshots** — and injects that live
context into every question you ask an LLM. Instead of pasting terminal output
into a chat box, you just ask *"what next?"* and it already sees what you see.

Everything runs locally, with pluggable LLM providers (Anthropic, OpenAI, and any
OpenAI-compatible endpoint). Your API key stays on the aggregator — the browser
UI never touches it.

```
   collectors                     aggregator (FastAPI :7331)              UI
 ┌───────────────┐   POST /panes  ┌──────────────────────────┐   GET /context
 │ tmux_poll     │───────────────▶│  rolling state           │◀───────────────┐
 │ browser ext   │──POST /browser▶│  + token-budget trimmer  │                │
 │ tail (burp…)  │──POST /app/*  ▶│                          │   POST /chat   │
 │ screenshot    │  hotkey flag   │  /chat → provider ───────┼──stream──────▶ │
 └───────────────┘                └──────────────────────────┘   (index.html) │
                                              ▲                                 │
                              ANTHROPIC_API_KEY / OPENAI_API_KEY                │
```

## Quick start

```bash
pip install -r requirements.txt          # fastapi, uvicorn, anthropic, openai (+pytest)
cp .env.example .env && $EDITOR .env      # add ANTHROPIC_API_KEY and/or OPENAI_API_KEY
./start.sh                                # launches aggregator + tmux collector, opens the UI
```

Then load the browser extension (optional): `chrome://extensions` → enable
**Developer mode** → **Load unpacked** → select the `extension/` folder.

Without an API key the collectors and UI still run — only chat is disabled.

## Components

| Piece | What it does | Run it |
|---|---|---|
| **aggregator** | FastAPI daemon: collects state, budgets context, proxies chat to Anthropic, serves the UI. | `python -m aggregator.main` |
| **tmux_poll** | Dumps *every* pane across *all* sessions/windows every 2s. Stdlib only. | `python -m aggregator.tmux_poll` |
| **tail** | Follows any log/command (Burp, tshark, nmap…) into the context. Stdlib only. | `python -m aggregator.tail burp --file /tmp/burp.log` |
| **extension** | MV3 browser extension: page snapshots + fetch/XHR interception. | Load unpacked from `extension/` |
| **ui** | Single-file chat UI with live status pills and streaming replies. | served at `http://127.0.0.1:7331/` |

## How context gets built

Every `/chat` (and `/context`) call renders the current state into a
token-budgeted block, **newest/active data first**, stopping once the budget
(`CTF_CONTEXT_TOKENS`, default ~6000) is hit:

1. tmux panes — active pane first (more lines), then most-recently-updated
2. browser — selected text > URL/title > recent requests > visible body
3. app logs — Burp, then Wireshark

Stale browser/app data (older than `CTF_STALE_AFTER`, default 120s) is dropped so
the model isn't shown a tab you closed. Click **"peek at injected context"** in
the UI to see exactly what gets sent.

## LLM providers

Chat is provider-agnostic (see `aggregator/providers.py`):

| Provider | Set | Reaches |
|---|---|---|
| **anthropic** | `ANTHROPIC_API_KEY` | Claude models (adaptive thinking + `CTF_EFFORT`) |
| **openai** | `OPENAI_API_KEY` | GPT models — and, via `OPENAI_BASE_URL`, **any OpenAI-compatible endpoint**: OpenRouter (Gemini/Llama/Mistral/…), Groq, Together, Ollama, local vLLM |

The active provider is `CTF_PROVIDER`, or auto-detected from whichever key is set
(Anthropic preferred). Pick the model with `CTF_MODEL`. Examples:

```bash
# Native OpenAI
OPENAI_API_KEY=sk-...        CTF_MODEL=gpt-4o

# Anything on OpenRouter (Gemini, Llama, DeepSeek, …) through the openai provider
CTF_PROVIDER=openai  OPENAI_API_KEY=sk-or-...  \
  OPENAI_BASE_URL=https://openrouter.ai/api/v1  CTF_MODEL=google/gemini-2.5-pro

# Local Ollama
CTF_PROVIDER=openai  OPENAI_API_KEY=ollama  \
  OPENAI_BASE_URL=http://localhost:11434/v1   CTF_MODEL=llama3.1
```

Vision (screenshots) works on any multimodal model; the image is sent in the
right shape per provider automatically.

## Screenshots (vision)

Capture is on-demand so you control when vision tokens are spent:

- Click **📷** in the UI to attach a screenshot to your next message, or
- Bind a WM hotkey to `touch /tmp/ctf_screenshot_requested` — the aggregator
  picks it up on the next status poll and holds it for your next message.

Capture tries `grim`, `spectacle`, `gnome-screenshot`, `scrot`, `maim`, then
ImageMagick `import`, and silently no-ops if none works.

> **GNOME/Wayland note:** ImageMagick `import` (X11) can't grab a Wayland
> compositor and will return nothing. Install **`gnome-screenshot`** (GNOME) or
> **`grim`** (sway/Hyprland) for working capture. `/health` reports the detected
> backend.

## Configuration

All via env vars (see `.env.example`). Highlights:

| Var | Default | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | — | At least one required for chat. |
| `CTF_PROVIDER` | auto | `anthropic` or `openai`; auto-detected from keys. |
| `CTF_MODEL` | per-provider | `claude-opus-4-8` (anthropic) / `gpt-4o` (openai). |
| `OPENAI_BASE_URL` | — | Point the openai provider at any compatible endpoint. |
| `CTF_EFFORT` | `high` | Anthropic only: `high`/`medium`/`low`. |
| `CTF_CONTEXT_TOKENS` | `6000` | Live-context budget. |
| `CTF_PORT` | `7331` | If you change it, update the extension via its storage key `aggUrl`. |

Replies stream. The Anthropic provider uses adaptive thinking; the OpenAI
provider auto-falls back from `max_tokens` to `max_completion_tokens` for newer
reasoning models.

## Security notes

This tool is for **authorized** testing. It deliberately captures sensitive
material — terminal scrollback, `document.cookie`, page contents — and sends it
to your configured LLM provider as prompt context. Run it only on your own machine for
engagements you're authorized to perform. Everything binds to `127.0.0.1` by
default; don't expose `CTF_PORT` to a network. The browser extension matches
`<all_urls>` — disable it when you're not actively testing.

## Tests

```bash
python -m pytest -q
```

Covers the token budget (prioritization, truncation, staleness), the state
store, and the full HTTP surface (intake, context, streaming chat with mocked
LLM, screenshot attach).
