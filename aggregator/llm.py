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

A proxy/extension also auto-flags suspicious things in the HTTP traffic — leaked \
secrets, JWTs, stack traces, SQL errors (possible injection points), exposed \
files/endpoints, cookie/CORS misconfig — shown in the "detected" section. Treat \
those as leads to investigate and verify, not conclusions; call out the highest- \
value ones and suggest how to confirm/exploit them.

Use that context to give specific, actionable next steps: concrete commands to \
run, payloads to try, things to notice in the output. Prefer precise answers \
grounded in what you can actually see over generic advice. If the context \
doesn't contain what you'd need, say so and ask for it (e.g. "run X and show me \
the output"). This is an authorized security-testing context.

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
