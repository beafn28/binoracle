"""Local LLM backends."""
from .base import LLMBackend, LLMUnavailable, Message
from .ollama import OllamaBackend
from .openai_compat import OpenAICompatBackend


def make_backend(config) -> LLMBackend:
    if config.backend == "ollama":
        return OllamaBackend(config)
    if config.backend in ("openai", "openai-compat", "llamacpp", "lmstudio", "vllm"):
        return OpenAICompatBackend(config)
    raise LLMUnavailable(f"unknown backend '{config.backend}'")
