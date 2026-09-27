"""Local LLM backends."""
from .base import LLMBackend, LLMUnavailable, Message
from .ollama import OllamaBackend
from .openai_compat import OpenAICompatBackend


def make_backend(config) -> LLMBackend:
    if config.backend == "ollama":
        return OllamaBackend(config)
    if config.backend in ("openai", "openai-compat", "llamacpp", "lmstudio", "vllm"):
        return OpenAICompatBackend(config)
    # unknown/disabled backend -> a no-op backend that is simply "unavailable",
    # so the rest of the tool degrades gracefully instead of crashing.
    class _NullBackend(LLMBackend):
        name = "none"
        def available(self):
            return False
        def chat(self, messages, *, json_mode: bool = False):
            raise LLMUnavailable("no LLM backend configured")
        def info(self):
            return "none (no local model configured)"
    return _NullBackend()
