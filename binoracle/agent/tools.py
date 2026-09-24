"""Bridge between the LLM's JSON action and the oracle ToolRegistry."""
from __future__ import annotations

import json
import re
from typing import Optional, Tuple

from ..oracles.base import ToolRegistry, ToolResult


# Claves alternativas que los modelos locales usan para lo mismo (estilo OpenAI/custom).
_TOOL_KEYS = ("tool", "name", "function", "tool_name", "action_input_tool")
_ARGS_KEYS = ("args", "arguments", "params", "parameters", "input", "tool_input", "action_input")


def _repair_json(s: str) -> str:
    """Arregla los errores JSON tipicos de modelos pequenos: comas finales y comillas simples."""
    s = re.sub(r",\s*([}\]])", r"\1", s)          # coma final antes de } o ]
    # comillas simples -> dobles solo si no hay ya dobles (evita romper strings validos)
    if "'" in s and '"' not in s:
        s = s.replace("'", '"')
    return s


def _normalize(obj: dict) -> Optional[dict]:
    """Lleva cualquier forma razonable al esquema {action: tool|final, ...} que espera el loop.

    Tolera que el modelo omita 'action' o use claves estilo OpenAI (name/arguments): si hay una
    herramienta, es una llamada; si hay answer/findings, es el final. Asi el LLM conduce como un
    pentester sin pelearse con el formato exacto."""
    if not isinstance(obj, dict):
        return None
    act = str(obj.get("action") or obj.get("type") or "").lower().strip()
    # localiza tool y args por cualquiera de las claves alternativas
    tool = next((obj[k] for k in _TOOL_KEYS if isinstance(obj.get(k), str) and obj.get(k)), None)
    args = next((obj[k] for k in _ARGS_KEYS if isinstance(obj.get(k), dict)), None)
    has_final = ("answer" in obj) or ("findings" in obj) or act in ("final", "answer", "finish", "done")
    # 'final' explicito o por forma (trae answer/findings y no una tool)
    if act in ("final", "answer", "finish", "done") or (has_final and not tool):
        return {"action": "final", "answer": obj.get("answer", obj.get("final", "")),
                "findings": obj.get("findings", [])}
    # 'tool' explicito o por forma (hay una herramienta identificable)
    if act in ("tool", "call", "tool_call", "use_tool", "function", "function_call") or tool:
        if not tool:
            return None
        return {"action": "tool", "tool": tool, "args": args or {}}
    return None


def extract_action(text: str) -> Optional[dict]:
    """Extrae la accion del reply de un modelo local, con tolerancia.

    Los modelos pequenos envuelven el JSON en prosa/fences, omiten 'action', usan claves estilo
    OpenAI (name/arguments) o meten comas finales. Reunimos candidatos {..} (incluidos los de
    code fences), reparamos errores tipicos y normalizamos la forma al esquema del loop."""
    if not text:
        return None
    candidates = []
    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
        candidates.append(m.group(1))
    # escaneo de llaves balanceadas (respeta strings y escapes para no cortar en un } de un string)
    depth = 0; start = None; in_str = False; esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    candidates.append(text[start:i + 1])
                    start = None
    for cand in candidates:
        for attempt in (cand, _repair_json(cand)):
            try:
                obj = json.loads(attempt)
            except json.JSONDecodeError:
                continue
            norm = _normalize(obj)
            if norm is not None:
                return norm
            break
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
