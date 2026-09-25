"""OpenAI-compatible local server backend (llama.cpp server, LM Studio, vLLM).

Uses stdlib urllib. Targets the /chat/completions endpoint."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import List

from .base import LLMBackend, LLMUnavailable, Message


class OpenAICompatBackend(LLMBackend):
    name = "openai-compat"

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

    def chat(self, messages: List[Message], *, json_mode: bool = False) -> str:
        payload = {
            "model": self.config.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": self.config.temperature,
            "stream": False,
        }
        # JSON mode: most OpenAI-compatible servers (llama.cpp, vLLM, LM Studio) honor
        # response_format to constrain output to a JSON object. Prose calls leave it off.
        if json_mode and getattr(self.config, "json_mode", True):
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
        return out["choices"][0]["message"]["content"]

    def info(self) -> str:
        status = "up" if self.available() else "down"
        return f"openai-compat ({self.base}, model={self.config.model}, {status})"
