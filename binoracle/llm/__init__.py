"""LLM backends: local (ollama/openai-compat) or Claude via the official Anthropic API."""
from .base import LLMBackend, LLMUnavailable, Message
from .ollama import OllamaBackend
from .openai_compat import OpenAICompatBackend
from .anthropic_backend import AnthropicBackend

__all__ = ["LLMBackend", "LLMUnavailable", "Message", "OllamaBackend", "OpenAICompatBackend",
          "AnthropicBackend", "make_backend", "make_fast_backend"]

_OLLAMA_DEFAULT_MODEL = "qwen2.5-coder:7b"


def make_backend(config) -> LLMBackend:
    if config.backend == "ollama":
        return OllamaBackend(config)
    if config.backend in ("openai", "openai-compat", "llamacpp", "lmstudio", "vllm"):
        return OpenAICompatBackend(config)
    if config.backend in ("anthropic", "claude"):
        # Config.model defaults to the ollama-style "qwen2.5-coder:7b" regardless of backend
        # (see Config.model's own default_factory) -- only override it when the user never
        # set BINORACLE_MODEL themselves for this backend, so an explicit choice always wins.
        if config.model == _OLLAMA_DEFAULT_MODEL:
            config.model = "claude-sonnet-5-5"
        return AnthropicBackend(config)
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


def make_fast_backend(config) -> LLMBackend:
    """Return a faster/cheaper backend for lightweight tasks (classification, grading).

    Uses BINORACLE_FAST_MODEL if set; falls back to the main model so the system works
    without change when only one model is configured.

    For Anthropic: fast model maps to claude-haiku-5-5 by default.
    For Ollama: use a smaller model like qwen2.5-coder:1.5b.
    """
    fast_model = getattr(config, "fast_model", "") or ""
    if not fast_model:
        # Default fast models per backend
        if config.backend in ("anthropic", "claude"):
            fast_model = "claude-haiku-5-5"
        else:
            return make_backend(config)  # no fast model configured → reuse main
    # Build a copy of config with fast_model swapped in
    import copy as _copy
    fast_cfg = _copy.copy(config)
    fast_cfg.model = fast_model
    if config.backend == "ollama":
        return OllamaBackend(fast_cfg)
    if config.backend in ("openai", "openai-compat", "llamacpp", "lmstudio", "vllm"):
        return OpenAICompatBackend(fast_cfg)
    if config.backend in ("anthropic", "claude"):
        return AnthropicBackend(fast_cfg)
    return make_backend(config)  # unknown backend → fallback
