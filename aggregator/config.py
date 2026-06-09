"""Central configuration, all overridable via environment variables.

Nothing here imports the heavy deps (fastapi/anthropic) so it can be pulled in
from the standalone poller too.
"""
from __future__ import annotations

import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


# --- Network ---------------------------------------------------------------
HOST: str = os.environ.get("CTF_HOST", "127.0.0.1")
PORT: int = _int("CTF_PORT", 7331)
# Base URL the collectors POST to. Keep in sync with HOST/PORT.
AGG_URL: str = os.environ.get("CTF_AGG_URL", f"http://{HOST}:{PORT}")

# --- LLM -------------------------------------------------------------------
# Provider: "anthropic" or "openai" (the latter also drives any OpenAI-compatible
# endpoint via OPENAI_BASE_URL). If CTF_PROVIDER is unset, auto-detect from
# whichever API key is present (preferring Anthropic).
_DEFAULT_MODELS = {"anthropic": "claude-opus-4-8", "openai": "gpt-4o"}


def _detect_provider() -> str:
    explicit = os.environ.get("CTF_PROVIDER", "").strip().lower()
    if explicit in _DEFAULT_MODELS:
        return explicit
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "anthropic"


PROVIDER: str = _detect_provider()
# Default to the most capable model for the active provider; override with CTF_MODEL.
MODEL: str = os.environ.get("CTF_MODEL") or _DEFAULT_MODELS.get(PROVIDER, "claude-opus-4-8")
# Effort controls thinking depth + token spend (Anthropic only). "high" suits
# intelligence-heavy CTF reasoning; drop to "medium"/"low" for snappier replies.
EFFORT: str = os.environ.get("CTF_EFFORT", "high")
# Output cap for a single reply. Streamed, so generous is fine.
MAX_OUTPUT_TOKENS: int = _int("CTF_MAX_OUTPUT_TOKENS", 4096)
# Optional base URL for the OpenAI provider (OpenRouter, Groq, Together, Ollama…).
OPENAI_BASE_URL: str | None = os.environ.get("OPENAI_BASE_URL") or None

# --- Context budget --------------------------------------------------------
# Rough token ceiling for the injected live-context block (~4 chars/token).
CONTEXT_TOKEN_BUDGET: int = _int("CTF_CONTEXT_TOKENS", 6000)
# Per-pane line caps fed into the trimmer.
ACTIVE_PANE_LINES: int = _int("CTF_ACTIVE_PANE_LINES", 120)
OTHER_PANE_LINES: int = _int("CTF_OTHER_PANE_LINES", 40)
# How many recent app-log entries to surface.
BURP_ENTRIES: int = _int("CTF_BURP_ENTRIES", 20)
WIRESHARK_ENTRIES: int = _int("CTF_WIRESHARK_ENTRIES", 30)

# --- Collectors ------------------------------------------------------------
POLL_INTERVAL: float = float(os.environ.get("CTF_POLL_INTERVAL", "2.0"))
PANE_CAPTURE_LINES: int = _int("CTF_PANE_CAPTURE_LINES", 200)
# Flag file a window-manager hotkey can `touch` to request a screenshot.
SCREENSHOT_FLAG: str = os.environ.get("CTF_SCREENSHOT_FLAG", "/tmp/ctf_screenshot_requested")

# --- Target scope ----------------------------------------------------------
# Comma-separated host/URL substrings. When set, only matching flows are scanned
# and stored (Burp-style scope) — keeps your own browsing out of the findings.
# Empty = everything in scope. Settable at runtime via the UI / POST /scope.
SCOPE: list[str] = [s.strip().lower() for s in os.environ.get("CTF_SCOPE", "").split(",")
                    if s.strip()]

# --- Sessions / persistence ------------------------------------------------
# Each engagement (findings, inventory, notes, tasks, flags, scope) is saved here
# as <name>.json so it survives restarts and you can switch between targets.
DATA_DIR: str = os.path.expanduser(os.environ.get("CTF_DATA_DIR", "~/.ctf-brain/engagements"))
SESSION: str = os.environ.get("CTF_SESSION", "default")

# --- Vulnerability intelligence --------------------------------------------
# Version -> CVE lookups via the live NVD API (cached to disk) + the CISA KEV
# (known-exploited) catalog, refreshed periodically.
VULN_DIR: str = os.path.join(DATA_DIR, "vulncache")
NVD_API_KEY: str = os.environ.get("NVD_API_KEY", "")        # optional, higher rate limit
KEV_REFRESH_HOURS: int = _int("CTF_KEV_REFRESH_HOURS", 12)
NVD_CACHE_DAYS: int = _int("CTF_NVD_CACHE_DAYS", 7)
VULN_LOOKUP: bool = os.environ.get("CTF_VULN_LOOKUP", "1") != "0"

# --- LLM tool-output parsing -----------------------------------------------
# Seconds a pane's output must be unchanged before we auto-parse it with the LLM.
PARSE_STABLE_SECONDS: float = float(os.environ.get("CTF_PARSE_STABLE_SECONDS", "6"))
AUTO_PARSE: bool = os.environ.get("CTF_AUTO_PARSE", "1") != "0"
# Autonomously run the tool-using ReAct agent on each opened page (fetch source,
# decode, check what pentesters check, record findings). More LLM calls per page.
AUTO_AGENT: bool = os.environ.get("CTF_AUTO_AGENT", "1") != "0"
# Dynamic strategist: re-derive "what we have / affords / next" when state changes.
AUTO_ASSESS: bool = os.environ.get("CTF_AUTO_ASSESS", "1") != "0"
REASSESS_INTERVAL: float = float(os.environ.get("CTF_REASSESS_INTERVAL", "20"))

# --- Misc ------------------------------------------------------------------
# Browser snapshots/app logs older than this (seconds) are treated as stale and
# dropped from the context so the LLM isn't shown a page you closed an hour ago.
STALE_AFTER: float = float(os.environ.get("CTF_STALE_AFTER", "120"))
