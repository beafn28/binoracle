"""Backend-agnostic LLM interface. We deliberately keep it tiny: chat(messages) -> text.

Tool calling is implemented one layer up (agent/) using a portable JSON-action protocol
instead of relying on native function-calling, because many local models do not support
native tools reliably. This keeps binoracle model-agnostic."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


class LLMUnavailable(RuntimeError):
    pass


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str


class LLMBackend:
    name = "base"

    def available(self) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    def chat(self, messages: List[Message], *, json_mode: bool = False) -> str:  # pragma: no cover - overridden
        """Return the model's reply. When json_mode is set, the backend constrains the
        output to a single valid JSON value (Ollama `format:json` / OpenAI
        `response_format`), which the agent loop uses to stop small models from wrapping
        their action in prose. Prose calls (summaries, enrichment) leave it False."""
        raise NotImplementedError

    def info(self) -> str:
        return self.name
