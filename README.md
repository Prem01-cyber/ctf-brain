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
 │ browser ext   │─POST /browser ▶│  + token-budget trimmer  │                │
 │ browser ext   │─POST /flow ───▶│  + detection engine ─────┼─findings──▶    │
 │ mitmproxy     │─POST /flow ───▶│    (auto-flag findings)  │   POST /chat   │
 │ tail (burp…)  │─POST /app/*  ─▶│  /chat → provider ───────┼──stream──────▶ │
 │ screenshot    │  hotkey flag   │                          │   (index.html) │
 └───────────────┘                └──────────────────────────┘                │
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
| **detect** | Detection engine: scans flows, auto-flags findings (incl. JWT decode). | (library; see Web enumeration) |
| **decoders / tools** | JWT + magic decoders; agent tool layer (findings/inventory/decode/replay/run). | (library; see Assistant tools) |
| **inventory / methodology** | Recon site-map + param mining; phase playbook. | `GET /inventory`, `GET /methodology` |
| **extract / llm_extract** | Auto-extraction: LLM-parse any tool output → hosts/ports/services; regex for hashes/creds. | `POST /parse` |
| **vulndb** | Version → CVE via live NVD (cached) + CISA KEV (exploited-in-wild). | `GET /vulns`, `POST /vulndb/refresh` |
| **engagement / sessions** | Dynamic phase + next-steps; per-session hosts/artifacts/notes/tasks/flags, persisted. | `GET /engagement`, `/hosts`, `/artifacts`, `/sessions` |
| **proxy addon** | mitmproxy addon: Burp-level full-traffic feed. | `mitmdump -s proxy/ctf_addon.py -p 8080` |
| **extension** | MV3 browser extension: page snapshots + request/response **body** capture. | Load unpacked from `extension/` |
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

## Web enumeration: traffic inspection + auto-flagging

ctf-brain inspects HTTP traffic and **auto-flags** suspicious things, then feeds
the findings to the assistant as top-priority context. Two feeds, one detection
engine (`aggregator/detect.py`):

| Feed | Setup | Sees |
|---|---|---|
| **Browser extension** | already loaded | request/response **bodies** of everything the page fetches (XHR/fetch), plus JS-readable headers |
| **mitmproxy addon** (`proxy/ctf_addon.py`) | run a proxy (below) | **everything** — navigations, assets, TLS-decrypted, and JS-hidden headers (`Set-Cookie`, full CORS) |

**What it flags** (severity-ranked): CTF flag patterns; leaked secrets (private
keys, AWS/Google/Slack/GitHub tokens, JWTs, `password=…`); SQL errors and stack
traces / debug pages (**injection & info-leak signals**); exposed endpoints
(`.git`, `.env`, backups, admin panels, swagger/graphql, `phpinfo`); CORS
wildcard-with-credentials and insecure cookies; internal IPs and tech-version
disclosure.

Findings show in the **`find N`** pill (red when high-severity) — click it for the
list — and in the injected context, so you can ask *"what's the most promising
lead here and how do I exploit it?"*

### Target scope (do this first)

Like Burp's scope. Set the **scope** field in the UI (or `CTF_SCOPE`, or
`POST /scope`) to your target host(s) — comma-separated substrings, e.g.
`target.htb, 10.10.10.5`. When set, only matching traffic is scanned, stored, and
shown; your own browsing (Gmail, etc.) is dropped entirely. **Leave it blank and
everything is in scope** — fine for a dedicated CTF browser profile, noisy if you
browse normally. Setting scope is the single biggest noise reducer.

### Turn on the mitmproxy proxy (full coverage)

```bash
pip install mitmproxy
mitmdump -s proxy/ctf_addon.py --listen-host 127.0.0.1 --listen-port 8080
```
Point your browser's HTTP/HTTPS proxy at `127.0.0.1:8080`, then visit
`http://mitm.it` once to install mitmproxy's CA cert. All decrypted traffic now
flows through the detection engine. (Set `CTF_AGG_URL` if the aggregator isn't on
the default port.) Findings from both feeds are deduped, so running both is fine.

> Inspect only targets you're authorized to test — this captures full bodies,
> cookies, and tokens.

## Assistant tools: agent mode, Repeater, decode, inventory, methodology

The footer has a small toolbar:

- **🤖 agent** — a **ReAct loop**: the model reasons, takes one action, observes
  the result, reasons again, and repeats until it can give a clearly-marked
  **Answer:** — refining as it goes (one tool per step, no batched guessing). The
  whole trace renders live in the chat: `💭` thought (summarized thinking on
  Anthropic), `🔧` action (tool call), `📄` observation (result). Tools let it
  *investigate*, not just advise: `read_file`/`list_dir`/`grep_files` (inspect the
  real box — `/etc/hosts`, configs, source), `decode`, `http_request`,
  `lookup_vulns`, `get_flow`, `list_findings`, `parse_output`.
- **▶ run** — additionally lets the agent run a command in your **active tmux pane**
  (`nmap`, `ffuf`, `curl`…) and read the output. Off by default; enabling it is an
  explicit opt-in (and implies agent mode). Only enable on a box/engagement where
  that's acceptable — the model is driving your shell.
- **⏭ next steps** — asks for a methodology-anchored plan (which phase you're in +
  the 2–3 highest-value next actions with exact commands).
- **decode** — JWT (decoded + `alg:none`/weak/expired flags, via PyJWT) and a
  CyberChef-"magic" multi-decoder (base64/hex/url/rot13/gzip chains; flags results
  containing a flag).
- **repeater** — load any captured request, tweak method/URL/headers/body, resend
  it server-side, and see the response (auto-scanned for findings). The Burp
  Repeater equivalent; great for iterating on an injection.
- **inventory** — discovered endpoints, mined parameters (injection candidates),
  and links found in pages/JS. Also injected into the chat context.

The assistant always frames advice against a **methodology** (recon → scanning →
enumeration → exploitation → post-exploitation) and names the current phase.

> **Decoders use established libraries** (PyJWT) and Python's stdlib codecs — no
> hand-rolled crypto. Agent `http_request` and the Repeater can hit any URL you
> give them; that's intentional for testing, but it means the tool is as
> trusted as you are. Keep it to authorized targets.

## Cockpit: dynamic engagement tracking (the dashboard)

### Dynamic strategist — "what we have / what it affords / what's next"

A living assessment ([planner.py](aggregator/planner.py)) reasons over the *entire*
knowledge base — hosts, ports, **versions → CVEs**, findings, artifacts,
endpoints, flags, notes — and derives, for each discovered asset, **what it
affords** (what can be extracted/exploited from it) plus the highest-value next
moves with exact commands. It re-runs automatically whenever the state materially
changes (a new service, an attached CVE, a new finding), debounced. This drives
the dashboard's **Assessment** card and **Next steps** (the static rule-based
steps are only a fallback when offline / no key). Nothing is hardcoded — e.g. an
nmap hit of `Apache httpd 2.4.49` becomes *"vulnerable to CVE-2021-41773/42013 →
path traversal → RCE"* with the real exploit command, on its own. On-demand via
`POST /assess`; tune with `CTF_AUTO_ASSESS=0` / `CTF_REASSESS_INTERVAL`.

### Autonomous web triage

When you **open a page** (in scope), the tool-using agent investigates it on its
own — the same ReAct loop, headless: it reads the captured request/response,
decodes suspicious blobs, fetches linked source if useful, and checks what a web
pentester checks (secrets, encoded data, params, comments, version/tech leaks,
auth/cookies, errors). It records what it finds via `record_finding` / `add_task`
/ `record_flag`, so results land in the **Signals** panel and tasks without you
asking. Runs once per page (deduped), scope-gated. Toggle with `CTF_AUTO_AGENT=0`
(falls back to a cheap single-pass analysis); it costs several LLM calls per page.

### Dynamic analysis — observe → search → claim

The intelligence is **not a hardcoded ruleset**. When a tmux pane settles or you
open a page, an LLM analyst ([llm_extract.py](aggregator/llm_extract.py))
**observes** the content and judges — in context — what is *abnormal or worth
pulling on*: a hash or an encoded/encrypted blob sitting on a page, a "key" field
next to ciphertext, a hidden form, a debug message, an odd parameter. For each it
records the observation, *why* it's abnormal, a hypothesis, and the concrete next
action — surfaced as **Signals** (right panel) + auto-created **tasks**. Nothing
about "what counts as interesting" is hardcoded; the model decides.

It also structures the same content into the **knowledge base**: hosts → ports →
service → version (any tool — nmap, gobuster, nikto…), endpoints, credentials.
Triggers automatically (debounced) and on-demand via **parse pane**. A cheap regex
pass still extracts fixed-format secrets (hashes/crypt strings) for free as a
first signal, but the *judgment* of what matters is the model's.

### Vulnerability intelligence (version → CVE → exploit)

When a service version is discovered, ctf-brain looks up known CVEs automatically
([vulndb.py](aggregator/vulndb.py)) — the step that usually eats a pentester's time:

- **Live NVD** queried by product+version (with keyword normalization, since a
  raw banner like `Apache httpd 2.4.49` doesn't match NVD as-is), **cached to disk**.
- **CISA KEV** catalog downloaded in full (~1.5 MB) and auto-refreshed; any CVE in
  it is **confirmed exploited-in-the-wild** (⚠ flagged) with remediation guidance.

Results attach to the service in the dashboard (CVE chips under each port, KEV in
red) and become top **next steps** (e.g. `Apache httpd 2.4.49` →
*"Exploit http — CVE-2021-41773"* with a `searchsploit` command). Precise and
always current — no multi-GB local mirror. On-demand via `GET /vulns?product=&version=`
or the agent's `lookup_vulns` tool. Set `NVD_API_KEY` for a higher rate limit;
`CTF_VULN_LOOKUP=0` disables auto-lookups.

### The dashboard

Two side panels flank the chat (a cockpit, not a single chat column): the **left**
holds recon/intel (phase, hosts/services + CVEs, assets, artifacts); the **right**
holds action/tracking — a live **⚡ Signals** card (the dynamically-flagged
abnormals + why), next steps, flags, tasks, notes. It's driven by a dynamic
engagement model ([engagement.py](aggregator/engagement.py)) — *not* a fixed
checklist — recomputed from live state:

- **Phase** — inferred from evidence (ports → Scanning, endpoints/params → Enumeration,
  SQL errors / `alg:none` JWTs → Exploitation) with a phase strip showing progress.
- **Next steps** — context-driven, prioritized suggestions with exact commands
  (dump an exposed `.git`, `sqlmap` a parameter that threw a SQL error, brute a
  discovered login, `ffuf` mined params, enumerate an open service…). Click one to
  load it into the chat.
- **Hosts / services** — structured nmap results (port → service → version → OS).
- **Artifacts** — auto-extracted hashes, credentials, and emails.
- **Assets** — endpoints, parameters, tech/versions, tokens, secrets — harvested
  from findings, inventory, and terminals.
- **🚩 Flags**, **Tasks** (add/check off), **Notes** (add) — your tracked state.

**Sessions / persistence.** Each engagement is a named session, isolated and saved
to disk (`CTF_DATA_DIR`, default `~/.ctf-brain/engagements/<name>.json`) — findings,
inventory, scope, notes, tasks, flags. Switch or create from the header dropdown;
state survives restarts (autosaved every 15s and on exit). Pick the session per
target so each box keeps its own picture.

The chat agent shares this state via tools (`get_engagement`, `add_note`,
`add_task`, `record_flag`), so it can plan from — and contribute to — the same
tracker you see.

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
| `CTF_SCOPE` | — | Comma-separated target host filters (Burp-style scope). Blank = all. |
| `CTF_SESSION` | `default` | Engagement/session name to load on start. |
| `CTF_DATA_DIR` | `~/.ctf-brain/engagements` | Where sessions are persisted. |
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
