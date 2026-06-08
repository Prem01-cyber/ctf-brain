"""LLM provider backends.

Each provider takes a provider-agnostic chat history (a list of
``{"role", "content"}`` dicts), a system prompt string, and an optional base64
PNG, and streams back text deltas. Per-provider concerns (Anthropic's adaptive
thinking / effort, OpenAI's chat-completions format and token-param quirks) are
contained here so the rest of the app stays provider-neutral.

The OpenAI provider honors ``OPENAI_BASE_URL``, so it also drives any
OpenAI-compatible endpoint — OpenRouter (Gemini/Llama/Mistral/...), Groq,
Together, Ollama, local vLLM — giving broad "all LLMs" coverage with one backend.
"""
from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator

from . import config, tools

_MAX_AGENT_ITERS = 8


def _anthropic_tools() -> list[dict[str, Any]]:
    return [{"name": t["name"], "description": t["description"],
             "input_schema": {"type": "object", "properties": t["properties"],
                              "required": t["required"]}} for t in tools.TOOLS]


def _openai_tools() -> list[dict[str, Any]]:
    return [{"type": "function", "function": {
        "name": t["name"], "description": t["description"],
        "parameters": {"type": "object", "properties": t["properties"],
                       "required": t["required"]}}} for t in tools.TOOLS]


# --- image attachment helpers (format differs per provider) ----------------
def attach_image_anthropic(messages: list[dict[str, Any]], image_b64: str) -> list[dict[str, Any]]:
    """Add the screenshot to the last user turn as an Anthropic image block."""
    out = [dict(m) for m in messages]
    for i in range(len(out) - 1, -1, -1):
        if out[i].get("role") == "user":
            content = out[i].get("content", "")
            blocks: list[dict[str, Any]] = []
            if isinstance(content, str):
                if content:
                    blocks.append({"type": "text", "text": content})
            elif isinstance(content, list):
                blocks.extend(content)
            blocks.append({
                "type": "image",
                "source": {"type": "base64", "media_type": "image/png", "data": image_b64},
            })
            out[i] = {"role": "user", "content": blocks}
            break
    return out


def attach_image_openai(messages: list[dict[str, Any]], image_b64: str) -> list[dict[str, Any]]:
    """Add the screenshot to the last user turn as an OpenAI image_url data URI."""
    out = [dict(m) for m in messages]
    data_uri = f"data:image/png;base64,{image_b64}"
    for i in range(len(out) - 1, -1, -1):
        if out[i].get("role") == "user":
            content = out[i].get("content", "")
            blocks: list[dict[str, Any]] = []
            if isinstance(content, str):
                if content:
                    blocks.append({"type": "text", "text": content})
            elif isinstance(content, list):
                blocks.extend(content)
            blocks.append({"type": "image_url", "image_url": {"url": data_uri}})
            out[i] = {"role": "user", "content": blocks}
            break
    return out


class Provider:
    name = "base"

    def available(self) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    async def stream(
        self,
        messages: list[dict[str, Any]],
        system: str,
        image_b64: str | None = None,
    ) -> AsyncIterator[str]:  # pragma: no cover - interface
        raise NotImplementedError
        yield ""  # make this an async generator for type-checkers

    async def stream_agent(
        self,
        messages: list[dict[str, Any]],
        system: str,
        image_b64: str | None = None,
        allow_exec: bool = False,
    ) -> AsyncIterator[str]:  # pragma: no cover - interface
        raise NotImplementedError
        yield ""


class AnthropicProvider(Provider):
    name = "anthropic"

    def available(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))

    async def stream(self, messages, system, image_b64=None):
        import anthropic

        if image_b64:
            messages = attach_image_anthropic(messages, image_b64)
        try:
            client = anthropic.AsyncAnthropic()
            async with client.messages.stream(
                model=config.MODEL,
                max_tokens=config.MAX_OUTPUT_TOKENS,
                thinking={"type": "adaptive"},
                output_config={"effort": config.EFFORT},
                system=system,
                messages=messages,
            ) as stream:
                async for text in stream.text_stream:
                    yield text
        except anthropic.APIStatusError as e:
            yield f"\n[ctf-brain] anthropic API error {e.status_code}: {e.message}"
        except Exception as e:  # noqa: BLE001
            yield f"\n[ctf-brain] anthropic error: {e}"

    async def stream_agent(self, messages, system, image_b64=None, allow_exec=False):
        import anthropic

        msgs = [dict(m) for m in messages]
        if image_b64:
            msgs = attach_image_anthropic(msgs, image_b64)
        atools = _anthropic_tools()
        try:
            client = anthropic.AsyncAnthropic()
            for _ in range(_MAX_AGENT_ITERS):
                # Thinking disabled in agent mode to avoid thinking-block re-submission.
                resp = await client.messages.create(
                    model=config.MODEL, max_tokens=config.MAX_OUTPUT_TOKENS,
                    system=system, messages=msgs, tools=atools,
                    thinking={"type": "disabled"},
                )
                assistant: list[dict[str, Any]] = []
                tool_uses = []
                for b in resp.content:
                    if b.type == "text":
                        if b.text:
                            yield b.text
                        assistant.append({"type": "text", "text": b.text})
                    elif b.type == "tool_use":
                        assistant.append({"type": "tool_use", "id": b.id,
                                          "name": b.name, "input": b.input})
                        tool_uses.append(b)
                if resp.stop_reason != "tool_use" or not tool_uses:
                    return
                msgs.append({"role": "assistant", "content": assistant})
                results = []
                for tu in tool_uses:
                    yield f"\n🔧 {tu.name}({json.dumps(tu.input)[:120]})\n"
                    out = await tools.run_tool(tu.name, tu.input, allow_exec)
                    results.append({"type": "tool_result", "tool_use_id": tu.id,
                                    "content": out})
                msgs.append({"role": "user", "content": results})
            yield "\n[ctf-brain] agent reached max iterations."
        except anthropic.APIStatusError as e:
            yield f"\n[ctf-brain] anthropic API error {e.status_code}: {e.message}"
        except Exception as e:  # noqa: BLE001
            yield f"\n[ctf-brain] anthropic agent error: {e}"


class OpenAIProvider(Provider):
    name = "openai"

    def available(self) -> bool:
        return bool(os.environ.get("OPENAI_API_KEY"))

    def _messages(self, messages, system, image_b64):
        msgs: list[dict[str, Any]] = [{"role": "system", "content": system}]
        msgs.extend(dict(m) for m in messages)
        if image_b64:
            msgs = [msgs[0]] + attach_image_openai(msgs[1:], image_b64)
        return msgs

    async def stream(self, messages, system, image_b64=None):
        import openai
        from openai import AsyncOpenAI

        msgs = self._messages(messages, system, image_b64)
        base = dict(model=config.MODEL, messages=msgs, stream=True)
        try:
            client = AsyncOpenAI(base_url=config.OPENAI_BASE_URL)
            try:
                stream = await client.chat.completions.create(
                    max_tokens=config.MAX_OUTPUT_TOKENS, **base
                )
            except openai.BadRequestError as e:
                # Newer models reject max_tokens and want max_completion_tokens.
                if "max_tokens" in str(e) or "max_completion_tokens" in str(e):
                    stream = await client.chat.completions.create(
                        max_completion_tokens=config.MAX_OUTPUT_TOKENS, **base
                    )
                else:
                    raise
            async for chunk in stream:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except openai.APIStatusError as e:
            yield f"\n[ctf-brain] openai API error {e.status_code}: {e.message}"
        except Exception as e:  # noqa: BLE001
            yield f"\n[ctf-brain] openai error: {e}"

    async def _create(self, client, **kw):
        import openai

        try:
            return await client.chat.completions.create(
                max_tokens=config.MAX_OUTPUT_TOKENS, **kw)
        except openai.BadRequestError as e:
            if "max_tokens" in str(e) or "max_completion_tokens" in str(e):
                return await client.chat.completions.create(
                    max_completion_tokens=config.MAX_OUTPUT_TOKENS, **kw)
            raise

    async def stream_agent(self, messages, system, image_b64=None, allow_exec=False):
        import openai
        from openai import AsyncOpenAI

        msgs = self._messages(messages, system, image_b64)
        otools = _openai_tools()
        try:
            client = AsyncOpenAI(base_url=config.OPENAI_BASE_URL)
            for _ in range(_MAX_AGENT_ITERS):
                resp = await self._create(client, model=config.MODEL, messages=msgs,
                                          tools=otools)
                msg = resp.choices[0].message
                if msg.content:
                    yield msg.content
                if not msg.tool_calls:
                    return
                msgs.append({
                    "role": "assistant", "content": msg.content or "",
                    "tool_calls": [{"id": tc.id, "type": "function",
                                    "function": {"name": tc.function.name,
                                                 "arguments": tc.function.arguments}}
                                   for tc in msg.tool_calls]})
                for tc in msg.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    yield f"\n🔧 {tc.function.name}({json.dumps(args)[:120]})\n"
                    out = await tools.run_tool(tc.function.name, args, allow_exec)
                    msgs.append({"role": "tool", "tool_call_id": tc.id, "content": out})
            yield "\n[ctf-brain] agent reached max iterations."
        except openai.APIStatusError as e:
            yield f"\n[ctf-brain] openai API error {e.status_code}: {e.message}"
        except Exception as e:  # noqa: BLE001
            yield f"\n[ctf-brain] openai agent error: {e}"


_REGISTRY: dict[str, Provider] = {
    "anthropic": AnthropicProvider(),
    "openai": OpenAIProvider(),
}


def get_provider(name: str | None = None) -> Provider:
    return _REGISTRY.get(name or config.PROVIDER, _REGISTRY["anthropic"])


def has_any_key() -> bool:
    return any(p.available() for p in _REGISTRY.values())
