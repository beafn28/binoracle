"""Backend-agnostic LLM interface. We deliberately keep it tiny: chat(messages) -> text.

Tool calling is implemented one layer up (agent/) using a portable JSON-action protocol
instead of relying on native function-calling, because many local models do not support
native tools reliably. This keeps binoracle model-agnostic."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List


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

    def chat(self, messages: List[Message]) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def info(self) -> str:
        return self.name
