"""Bridge between the LLM's JSON action and the oracle ToolRegistry."""
from __future__ import annotations

import json
import re
from typing import Optional, Tuple

from ..oracles.base import ToolRegistry, ToolResult


def extract_action(text: str) -> Optional[dict]:
    """Robustly pull the first JSON object out of a local model's reply.

    Local models wrap JSON in prose or code fences; this scans for the first balanced
    {...} block and parses it."""
    if not text:
        return None
    # strip code fences
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = []
    if fenced:
        candidates.append(fenced.group(1))
    # balanced-brace scan
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                candidates.append(text[start:i + 1])
                start = None
    for cand in candidates:
        try:
            obj = json.loads(cand)
            if isinstance(obj, dict) and "action" in obj:
                return obj
        except json.JSONDecodeError:
            continue
    return None


def execute_action(registry: ToolRegistry, action: dict, max_chars: int) -> Tuple[str, Optional[ToolResult]]:
    """Run the tool named in `action` and return (observation_text, result)."""
    tool_name = action.get("tool", "")
    args = action.get("args", {}) or {}
    tool = registry.get(tool_name)
    if tool is None:
        avail = ", ".join(t.name for t in registry.available_tools())
        return (f"ERROR: unknown tool '{tool_name}'. Available: {avail}", None)
    # map args by parameter name, applying defaults
    kwargs = {}
    for p in tool.params:
        if p.name in args:
            kwargs[p.name] = args[p.name]
        elif p.required:
            return (f"ERROR: tool '{tool_name}' requires argument '{p.name}'", None)
        else:
            if p.default is not None:
                kwargs[p.name] = p.default
    try:
        result = tool.run(**kwargs)
    except TypeError as e:
        return (f"ERROR calling {tool_name}: {e}", None)
    except Exception as e:
        return (f"ERROR: tool '{tool_name}' raised: {e}", None)
    result = result.truncated(max_chars)
    header = f"[{result.source}]"
    if not result.ok:
        return (f"{header}\nTOOL FAILED: {result.error}", result)
    return (f"{header}\n{result.data}", result)
