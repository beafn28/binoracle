"""Runtime configuration. Everything is overridable by environment variables so the
tool stays portable and local-first."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Config:
    # --- LLM backend (all local) ---
    # backend: "ollama" (default) or "openai" (any OpenAI-compatible local server:
    # llama.cpp --server, LM Studio, vLLM).
    backend: str = field(default_factory=lambda: _env("BINORACLE_BACKEND", "ollama"))
    model: str = field(default_factory=lambda: _env("BINORACLE_MODEL", "qwen2.5-coder:7b"))
    base_url: str = field(default_factory=lambda: _env("BINORACLE_BASE_URL", ""))
    api_key: str = field(default_factory=lambda: _env("BINORACLE_API_KEY", "local"))
    temperature: float = field(default_factory=lambda: float(_env("BINORACLE_TEMPERATURE", "0.1")))
    lang: str = field(default_factory=lambda: _env("BINORACLE_LANG", "es"))  # es | en
    # Constrain agent-loop replies to valid JSON (Ollama format:json / OpenAI response_format).
    # On by default; set BINORACLE_JSON_MODE=0 for a model whose server does not support it.
    json_mode: bool = field(default_factory=lambda: _env("BINORACLE_JSON_MODE", "1") != "0")
    # Opt-in, never auto-detected: native function-calling (Ollama's `tools` field / OpenAI
    # `tools`+`tool_calls`) works well on SOME local models (Llama 3.1+, Qwen2.5+, and others
    # tagged "tools" in `ollama show`) and unreliably or not at all on others -- there is no
    # cheap, safe way to probe which from here, so the user asserts it for a model they KNOW
    # supports it. Off by default: every model keeps working through the portable JSON-action
    # protocol (agent/tools.py's extract_action) unless this is explicitly turned on.
    native_tools: bool = field(default_factory=lambda: _env("BINORACLE_NATIVE_TOOLS", "0") == "1")
    request_timeout: int = field(default_factory=lambda: int(_env("BINORACLE_TIMEOUT", "600")))

    # --- agent budget (keeps the loop from running away) ---
    max_steps: int = field(default_factory=lambda: int(_env("BINORACLE_MAX_STEPS", "24")))
    max_tool_output_chars: int = field(default_factory=lambda: int(_env("BINORACLE_MAX_TOOL_CHARS", "6000")))

    # --- storage ---
    state_dir: Path = field(default_factory=lambda: Path(_env("BINORACLE_STATE_DIR", ".binoracle")))

    def resolved_base_url(self) -> str:
        if self.base_url:
            return self.base_url.rstrip("/")
        if self.backend == "ollama":
            return "http://localhost:11434"
        return "http://localhost:8080/v1"  # common llama.cpp server default

    def db_path(self) -> Path:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        return self.state_dir / "sessions.sqlite"


def load_config() -> Config:
    return Config()
