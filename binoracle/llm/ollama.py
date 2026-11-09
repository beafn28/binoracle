"""Ollama backend using only the stdlib (urllib). No third-party HTTP client needed."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import List, Optional

from .base import LLMBackend, LLMUnavailable, Message


class OllamaBackend(LLMBackend):
    name = "ollama"
    _supports_native_tools = True

    def __init__(self, config):
        self.config = config
        self.base = config.resolved_base_url()

    def _post(self, path: str, payload: dict, timeout: int) -> dict:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def available(self) -> bool:
        try:
            req = urllib.request.Request(self.base + "/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def chat(self, messages: List[Message], *, json_mode: bool = False,
             tools: Optional[list] = None) -> str:
        payload = {
            "model": self.config.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": self.config.temperature},
        }
        # Native tool-calling (opt-in, see base.LLMBackend's docstring): only sent when the
        # caller actually wants it, so a model/server that chokes on an unknown "tools" field
        # never sees one unless the user asserted native_tools themselves.
        use_native = bool(tools) and getattr(self.config, "native_tools", False)
        if use_native:
            payload["tools"] = tools
        # Native JSON mode: forces the model to emit one valid JSON value, so a small model
        # cannot narrate around its action. Prompt still asks for JSON (Ollama requirement).
        # Skipped when native tool-calling is in play: Ollama's own tool-calling path returns
        # structured tool_calls, not freeform content, and format=json alongside tools has no
        # defined meaning for the function-calling response shape.
        if json_mode and getattr(self.config, "json_mode", True) and not use_native:
            payload["format"] = "json"
        try:
            out = self._post("/api/chat", payload, self.config.request_timeout)
        except urllib.error.URLError as e:
            raise LLMUnavailable(f"ollama unreachable at {self.base}: {e}") from e
        msg = out.get("message", {})
        if use_native:
            calls = msg.get("tool_calls") or []
            if calls:
                fn = calls[0].get("function", {}) or {}
                args = fn.get("arguments", {})
                if isinstance(args, str):   # some servers return the arguments pre-serialized
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
        return f"ollama ({self.base}, model={self.config.model}, {status})"
