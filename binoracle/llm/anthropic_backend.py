"""Claude via the official Anthropic API. No local model, no server to run -- just an API key.

Added as a real alternative to the local-model backends (ollama/openai-compat) after live
testing in a resource-constrained sandbox confirmed a hard ceiling: a 3B local model
hallucinates or misclassifies the vulnerability it just gathered evidence for, and a 7B model
either gets OOM-killed by the container's memory cgroup or (at a context window small enough
to fit) can't even hold the tool-schema overhead needed for real exploit execution
(dbg_run_input) before the very first request. Claude has none of those constraints: no local
RAM/VRAM budget, no context-window tradeoff against the tool registry's own schema size.

Uses the official `anthropic` SDK (not an OpenAI-compatible shim) per Anthropic's own
guidance -- `pip install binoracle[anthropic]` or `pip install anthropic` to enable."""
from __future__ import annotations

import json
from typing import List, Optional

from .base import LLMBackend, LLMUnavailable, Message

_INSTALL_HINT = "Claude backend needs the 'anthropic' package: pip install binoracle[anthropic]"


class AnthropicBackend(LLMBackend):
    name = "anthropic"
    _supports_native_tools = True

    def __init__(self, config):
        self.config = config
        self._client = None
        self._import_error = None
        try:
            import anthropic
            # api_key="local" is Config's generic local-server default (meaningless here) --
            # only pass it through when the user actually set BINORACLE_API_KEY themselves;
            # otherwise let the SDK resolve ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN/an `ant auth
            # login` profile on its own, exactly as a bare `anthropic.Anthropic()` would.
            key = getattr(config, "api_key", "") or ""
            kwargs = {} if key in ("", "local") else {"api_key": key}
            self._client = anthropic.Anthropic(**kwargs)
            self._anthropic = anthropic
        except Exception as e:
            self._import_error = e

    def available(self) -> bool:
        if self._client is None:
            return False
        try:
            # Cheap (no tokens billed): lists models instead of sending a chat request, with
            # a short timeout so a transient network hiccup doesn't hang doctor/startup checks.
            self._client.with_options(timeout=5.0).models.list(limit=1)
            return True
        except Exception:
            return False

    def chat(self, messages: List[Message], *, json_mode: bool = False,
             tools: Optional[list] = None) -> str:
        if self._client is None:
            raise LLMUnavailable(f"{_INSTALL_HINT} ({self._import_error})")
        # binoracle's own Message list always puts the (single) system prompt at index 0 --
        # see AgentLoop.run()'s construction -- so this generalizes to "any leading system
        # messages" without assuming exactly one, but never emits a mid-conversation
        # role="system" entry into `messages` (not every model accepts that, and binoracle
        # never needs it: the portable protocol's own nudges are plain user turns).
        system_parts, rest = [], []
        for m in messages:
            if m.role == "system" and not rest:
                system_parts.append(m.content)
            else:
                rest.append(m)
        system_text = "\n\n".join(system_parts)
        use_native = bool(tools) and getattr(self.config, "native_tools", False)
        if json_mode and getattr(self.config, "json_mode", True) and not use_native:
            system_text += ("\n\nRespond with exactly one valid JSON object and nothing else "
                            "-- no prose, no markdown fences.")
        kwargs = {
            "model": self.config.model,
            "max_tokens": 4096,
            "system": system_text,
            "messages": [{"role": m.role, "content": m.content} for m in rest],
        }
        if use_native:
            # OpenAI-style {"type": "function", "function": {name, description, parameters}}
            # -> Anthropic's {"name", "description", "input_schema"} -- same conversion
            # principle as OllamaBackend/OpenAICompatBackend: `tools` only changes HOW the
            # model is asked to act, never the shape chat() hands back.
            kwargs["tools"] = [
                {"name": t["function"]["name"], "description": t["function"]["description"],
                 "input_schema": t["function"]["parameters"]}
                for t in tools
            ]
        try:
            response = self._client.with_options(
                timeout=self.config.request_timeout).messages.create(**kwargs)
        except self._anthropic.APIStatusError as e:
            raise LLMUnavailable(f"Claude API rejected the request (HTTP {e.status_code}): "
                                 f"{e.message}") from e
        except self._anthropic.APIConnectionError as e:
            raise LLMUnavailable(f"Claude API unreachable: {e}") from e
        if response.stop_reason == "refusal":
            cat = getattr(response.stop_details, "category", None) if response.stop_details else None
            raise LLMUnavailable(f"Claude declined the request (refusal, category={cat})")
        if use_native:
            tool_use = next((b for b in response.content if b.type == "tool_use"), None)
            if tool_use is not None:
                # Converted back into the SAME portable JSON text extract_action already
                # parses -- see base.LLMBackend's docstring.
                return json.dumps({"name": tool_use.name, "arguments": tool_use.input})
        text = next((b.text for b in response.content if b.type == "text"), "")
        return text

    def info(self) -> str:
        if self._client is None:
            return f"anthropic (not installed: {self._import_error})"
        status = "up" if self.available() else "down"
        return f"anthropic (model={self.config.model}, {status})"
