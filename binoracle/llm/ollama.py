"""Ollama backend using only the stdlib (urllib). No third-party HTTP client needed."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import List

from .base import LLMBackend, LLMUnavailable, Message


class OllamaBackend(LLMBackend):
    name = "ollama"

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

    def chat(self, messages: List[Message]) -> str:
        payload = {
            "model": self.config.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": self.config.temperature},
        }
        try:
            out = self._post("/api/chat", payload, self.config.request_timeout)
        except urllib.error.URLError as e:
            raise LLMUnavailable(f"ollama unreachable at {self.base}: {e}") from e
        msg = out.get("message", {})
        return msg.get("content", "")

    def info(self) -> str:
        status = "up" if self.available() else "down"
        return f"ollama ({self.base}, model={self.config.model}, {status})"
