"""Ollama backend using only the stdlib (urllib). No third-party HTTP client needed."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import List, Optional

from .base import LLMBackend, LLMUnavailable, Message

# Max seconds between tokens before we consider Ollama stuck.
_PER_TOKEN_TIMEOUT = 45
# Hard wall-clock cap per chat() call regardless of token pace.
_DEFAULT_WALL_CAP = 300


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

    def _post_streaming(self, path: str, payload: dict) -> str:
        """Stream from Ollama with per-token and hard wall-clock timeouts.

        Uses ndjson streaming (stream=True) so each generated token arrives
        as a separate line.  Two guards prevent hangs:
          1. Per-token socket timeout (_PER_TOKEN_TIMEOUT s): if the model
             stops emitting tokens for that long, the socket read raises
             socket.timeout → LLMUnavailable.
          2. Wall-clock cap (config.request_timeout, default 300 s): total
             time the call is allowed to run regardless of token pace.
        """
        import socket as _socket

        payload = dict(payload)
        payload["stream"] = True
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        wall_cap = getattr(self.config, "request_timeout", _DEFAULT_WALL_CAP)
        deadline = time.monotonic() + wall_cap
        parts: List[str] = []
        tool_calls_raw: Optional[list] = None

        try:
            with urllib.request.urlopen(req, timeout=_PER_TOKEN_TIMEOUT) as resp:
                # Set socket timeout for each individual readline() call.
                try:
                    sock = resp.fp.raw._sock  # CPython implementation detail
                    sock.settimeout(_PER_TOKEN_TIMEOUT)
                except Exception:
                    pass  # If we can't reach the socket, rely on urlopen timeout only

                while True:
                    if time.monotonic() > deadline:
                        raise LLMUnavailable(
                            f"Ollama LLM hit wall-clock limit ({wall_cap}s) — "
                            "probably stuck in a reasoning loop; raise BINORACLE_TIMEOUT "
                            "or reduce prompt complexity"
                        )
                    try:
                        line = resp.readline()
                    except _socket.timeout as _tout:
                        raise LLMUnavailable(
                            f"Ollama LLM stalled: no token for {_PER_TOKEN_TIMEOUT}s — "
                            "model may be stuck; check Ollama logs"
                        ) from _tout
                    if not line:
                        break
                    try:
                        chunk = json.loads(line.decode("utf-8"))
                    except Exception:
                        continue
                    msg = chunk.get("message") or {}
                    # Accumulate tool_calls if present (native tool-calling path)
                    if msg.get("tool_calls") and tool_calls_raw is None:
                        tool_calls_raw = msg["tool_calls"]
                    parts.append(msg.get("content", ""))
                    if chunk.get("done"):
                        break
        except urllib.error.URLError as e:
            raise LLMUnavailable(f"ollama unreachable at {self.base}: {e}") from e

        if tool_calls_raw:
            # Return serialised tool_calls so the base class can parse them.
            fn = tool_calls_raw[0].get("function", {}) or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            return json.dumps({"name": fn.get("name", ""), "arguments": args})

        return "".join(parts)

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

        # Use streaming so we get per-token + wall-clock hang protection.
        # (stream=False holds the socket open until the full response arrives with
        # no intermediate data, so the urllib socket timeout never fires mid-generation.)
        return self._post_streaming("/api/chat", payload)

    def info(self) -> str:
        st = "up" if self.available() else "down"
        return f"ollama ({self.base}, model={self.config.model}, {st})"
