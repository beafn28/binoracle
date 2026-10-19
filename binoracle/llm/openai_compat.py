"""OpenAI-compatible local server backend (llama.cpp server, LM Studio, vLLM).

Uses stdlib urllib. Targets the /chat/completions endpoint."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import List, Optional

from .base import LLMBackend, LLMUnavailable, Message


class OpenAICompatBackend(LLMBackend):
    name = "openai-compat"
    _supports_native_tools = True

    def __init__(self, config):
        self.config = config
        self.base = config.resolved_base_url()

    def available(self) -> bool:
        try:
            req = urllib.request.Request(self.base + "/models", method="GET",
                                         headers={"Authorization": f"Bearer {self.config.api_key}"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def chat(self, messages: List[Message], *, json_mode: bool = False,
             tools: Optional[list] = None) -> str:
        payload = {
            "model": self.config.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": self.config.temperature,
            "stream": False,
        }
        # Native tool-calling (opt-in, see base.LLMBackend's docstring): only sent when the
        # caller actually wants it, so a server that doesn't support "tools" never sees one
        # unless the user asserted native_tools themselves.
        use_native = bool(tools) and getattr(self.config, "native_tools", False)
        if use_native:
            payload["tools"] = tools
        # JSON mode: most OpenAI-compatible servers (llama.cpp, vLLM, LM Studio) honor
        # response_format to constrain output to a JSON object. Prose calls leave it off.
        # Skipped alongside native tool-calling: a function-calling response is already
        # structured, and response_format+tools together have no agreed meaning across servers.
        if json_mode and getattr(self.config, "json_mode", True) and not use_native:
            payload["response_format"] = {"type": "json_object"}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base + "/chat/completions",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.request_timeout) as resp:
                out = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise LLMUnavailable(f"openai-compat server unreachable at {self.base}: {e}") from e
        msg = out["choices"][0]["message"]
        if use_native:
            calls = msg.get("tool_calls") or []
            if calls:
                fn = calls[0].get("function", {}) or {}
                args = fn.get("arguments", {})
                if isinstance(args, str):   # OpenAI's real API always pre-serializes this
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                # Converted back into the SAME portable JSON text extract_action already
                # parses (see base.LLMBackend's docstring) -- native tool-calling only changes
                # how the model is ASKED to act, never the shape chat() hands back.
                return json.dumps({"name": fn.get("name", ""), "arguments": args})
        return msg.get("content", "")

    def info(self) -> str:
        status = "up" if self.available() else "down"
        return f"openai-compat ({self.base}, model={self.config.model}, {status})"
