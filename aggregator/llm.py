"""Chat orchestration: build the system prompt from live context and stream a
reply via the configured provider (see providers.py).

The browser UI never sees an API key — it POSTs the conversation here and the
selected provider injects the workstation context as a system prompt.
"""
from __future__ import annotations

from typing import Any, AsyncIterator

from . import config, methodology, providers

# Backwards-compatible alias: tests and older call sites use llm._attach_image
# (Anthropic image-block format).
_attach_image = providers.attach_image_anthropic

_SYSTEM_PREAMBLE = """You are CTF-Brain, an assistant embedded in a CTF / \
authorized-penetration-testing workstation. You can see the operator's live \
environment — their tmux panes (terminal output), the page open in their \
browser, recent HTTP traffic, and sometimes a screenshot — captured below.

Work like an expert analyst, not a tip generator. Your loop is OBSERVE → SEARCH \
→ CLAIM:
- OBSERVE: actually look at what's in front of you — the page text, terminal \
output, findings, and the environment. Anything *out of place* is a signal, not \
noise: a hash or an encoded/encrypted blob (long hex/base64) sitting on a page is \
abnormal — notice it and ask what it is. A "key" field next to ciphertext, a \
hidden form, a version banner, a debug message — pull on these threads.
- SEARCH: investigate before concluding. Use your tools — decode strings; to \
inspect files use read_file / list_dir / grep_files directly (do NOT shell out \
with cat/ls/grep via run_command); send requests with http_request; look up CVEs \
with lookup_vulns. run_command is only for *active* commands (scans, exploits) and \
may be disabled. Verify; don't guess.
- CLAIM: state what you can now conclude and the concrete next action (exact \
command/payload). Tie it to evidence you actually gathered.

Work as a ReAct loop, one step at a time: briefly state your reasoning, take ONE \
action (a single tool call), look at the result, then reason again about what it \
told you and what to check next — repeat. Don't batch guesses or jump to the \
answer; let each observation refine the next step. When you've verified enough, \
give a clearly separated final answer (begin it with "**Answer:**") that states \
the conclusion and the precise next move. Keep the reasoning between steps short.

Detected/auto-flagged items are leads to verify, never the final word — and they \
are not exhaustive, so use your own judgment about what's interesting; don't rely \
on a fixed list. This is an authorized security-testing context.

{methodology}

===== LIVE WORKSTATION CONTEXT (auto-captured, newest data prioritized) =====
{context}
===== END LIVE CONTEXT =====
"""


def build_system_prompt(rendered_context: str) -> str:
    return _SYSTEM_PREAMBLE.format(
        methodology=methodology.system_block(), context=rendered_context)


def has_api_key() -> bool:
    """True if *any* configured provider has credentials."""
    return providers.has_any_key()


async def stream_reply(
    messages: list[dict[str, Any]],
    rendered_context: str,
    image_b64: str | None = None,
    agent: bool = False,
    allow_exec: bool = False,
) -> AsyncIterator[str]:
    """Yield text deltas of the model's reply.

    Errors (missing key, API failures) are yielded as a human-readable string so
    the UI can display them inline rather than failing silently.
    """
    provider = providers.get_provider()
    if not provider.available():
        # Fall back to any provider that does have a key.
        fallback = next((p for p in providers._REGISTRY.values() if p.available()), None)
        if fallback is not None:
            provider = fallback
        else:
            yield (f"[ctf-brain] No API key for provider '{config.PROVIDER}'. Set "
                   "ANTHROPIC_API_KEY or OPENAI_API_KEY (and optionally CTF_PROVIDER) "
                   "and restart the aggregator. Other collectors still work.")
            return

    if not messages or messages[-1].get("role") != "user":
        yield "[ctf-brain] No user message to respond to."
        return

    system = build_system_prompt(rendered_context)
    if agent:
        async for chunk in provider.stream_agent(messages, system, image_b64, allow_exec):
            yield chunk
    else:
        async for chunk in provider.stream(messages, system, image_b64):
            yield chunk
