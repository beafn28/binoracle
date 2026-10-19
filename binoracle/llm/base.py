"""Backend-agnostic LLM interface. We deliberately keep it tiny: chat(messages) -> text.

Tool calling is implemented one layer up (agent/) using a portable JSON-action protocol
instead of relying on native function-calling, because many local models do not support
native tools reliably. This keeps binoracle model-agnostic.

ROADMAP "[M] Model quality" -- "better native tool-calling for capable local models": the
optional `tools` parameter on `chat()` lets a backend use the model's OWN native function-
calling (Ollama's `tools` field / OpenAI `tools`+`tool_calls`) INSTEAD of hoping the model's
free-text reply happens to parse as the portable JSON-action protocol -- deliberately
opt-in (`config.native_tools`, off by default) since it only helps on models that actually
support it well; every other model keeps working through the portable protocol exactly as
before. Critically, this does NOT introduce a second, parallel protocol: a backend that uses
native tool-calling converts the result BACK into the exact same portable JSON text
(`{"name": ..., "arguments": {...}}`, which `agent/tools.py`'s `extract_action` already
parses) before returning it from `chat()` -- so every other consumer of `chat()`'s return
value, and the agent loop's own anti-repeat/anti-spam/gating logic, is unaffected and
untested-risk-free; native tool-calling only replaces "ask a plain-text model to emit valid
JSON and hope" with "ask the model's own function-calling layer to emit it", for models
where that layer actually ships."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


class LLMUnavailable(RuntimeError):
    pass


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str


class LLMBackend:
    name = "base"
    # Overridden by a backend that can honor `chat()`'s `tools` parameter via the model's own
    # native function-calling. Checked by the agent loop before it bothers building the tool
    # schema at all -- a backend that can't use it should never receive it.
    _supports_native_tools = False

    def available(self) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    def chat(self, messages: List[Message], *, json_mode: bool = False,
             tools: Optional[list] = None) -> str:  # pragma: no cover - overridden
        """Return the model's reply. When json_mode is set, the backend constrains the
        output to a single valid JSON value (Ollama `format:json` / OpenAI
        `response_format`), which the agent loop uses to stop small models from wrapping
        their action in prose. Prose calls (summaries, enrichment) leave it False.

        `tools`: an optional OpenAI-style function-calling schema (list of
        `{"type": "function", "function": {"name", "description", "parameters"}}`). Only
        acted on when the backend supports native tool-calling AND the caller's config opted
        in (`config.native_tools`); otherwise ignored, and `chat()` behaves exactly as if it
        had not been passed. A backend that does act on it converts the model's native
        tool-call response back into the portable `{"name": ..., "arguments": {...}}` JSON
        text `agent/tools.py.extract_action` already understands, rather than returning some
        new shape -- so `tools` only changes HOW the model is asked to act, never the shape
        of what `chat()` hands back."""
        raise NotImplementedError

    def info(self) -> str:
        return self.name
