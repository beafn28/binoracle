"""Grounded function-explanation workflow: disassemble a function and let the local model
explain it, strictly citing the disassembly it was given.

v2 adds structured ExplainResult, batch_explain, render_explain, and explain_cve_context.
For AUTHORIZED targets / CTF only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from ..agent.loop import AgentLoop, AgentResult
from ..oracles.base import ToolRegistry

_DANGEROUS = [
    "gets", "sprintf", "vsprintf", "strcpy", "strcat", "scanf",
    "recv", "recvfrom", "read", "memcpy", "strncpy", "popen", "system",
]

_CVE_HINTS = {
    "gets":     "unbounded stdin read — classic stack overflow, check CVE patterns for BOF",
    "sprintf":  "unsized format write — possible overflow if format is attacker-controlled",
    "vsprintf": "unsized format write — same risk as sprintf with variadic args",
    "strcpy":   "unbounded string copy — stack/heap overflow if src is attacker-controlled",
    "strcat":   "unbounded string append — overflow if concatenated length exceeds buffer",
    "scanf":    "unbounded scan — overflow if %s used without field width",
    "recv":     "network input without length guard — overflow if size not validated",
    "recvfrom": "network input without length guard — same risk as recv",
    "memcpy":   "copy with explicit size — overflow if size derived from attacker input",
    "strncpy":  "bounded copy but no NUL guarantee — off-by-one or info-leak possible",
    "popen":    "shell command injection if argument is user-controlled",
    "system":   "command injection if argument is user-controlled",
}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ExplainResult:
    func_name:       str
    binary:          str
    disasm:          str             = ""
    callers:         List[str]       = field(default_factory=list)
    callees:         List[str]       = field(default_factory=list)
    dangerous_calls: List[str]       = field(default_factory=list)
    strings_used:    List[str]       = field(default_factory=list)
    llm_explanation: str             = ""
    cve_hints:       List[str]       = field(default_factory=list)
    error:           str             = ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_tool(registry: ToolRegistry, name: str, **kwargs) -> str:
    tool = registry.get(name)
    if tool is None:
        return ""
    try:
        res = tool.run(**kwargs) if kwargs else tool.run()
        return res.data if res.ok else ""
    except Exception:
        return ""


def _detect_dangerous(disasm: str) -> tuple[List[str], List[str]]:
    found_calls: List[str] = []
    hints: List[str] = []
    for line in disasm.splitlines():
        for sink in _DANGEROUS:
            if re.search(r"\b" + re.escape(sink) + r"\b", line):
                if sink not in found_calls:
                    found_calls.append(sink)
                    hints.append(_CVE_HINTS[sink])
    return found_calls, hints


def _extract_callees(disasm: str) -> List[str]:
    callees = []
    for line in disasm.splitlines():
        m = re.search(r"(?:call|bl|blx)\s+(?:sym\.|plt\.|fcn\.|0x)?([^\s;]+)", line, re.I)
        if m:
            name = m.group(1).lstrip("sym.").lstrip("plt.")
            if name not in callees:
                callees.append(name)
    return callees[:20]


def _extract_strings(disasm: str) -> List[str]:
    strings = []
    for m in re.finditer(r'"([^"]{3,60})"', disasm):
        s = m.group(1)
        if s not in strings:
            strings.append(s)
    return strings[:15]


def _llm_explain(llm, func_name: str, disasm: str, lang: str = "es") -> str:
    if llm is None or not hasattr(llm, "available") or not llm.available():
        return ""
    try:
        from ..llm.base import Message
        if lang == "es":
            sys_msg = (
                "Eres un analista de reversing. Explica en espanol que hace la funcion dada, "
                "citando SOLO las instrucciones del desensamblado. No inventes instrucciones. "
                "Menciona: proposito, entradas, operaciones peligrosas (si las hay), "
                "como puede ser alcanzada. Maximo 10 frases."
            )
        else:
            sys_msg = (
                "You are a reverse engineering analyst. Explain what the function does, "
                "citing ONLY instructions from the disassembly. Do not invent any instruction. "
                "Cover: purpose, inputs, dangerous ops (if any), how it can be reached. Max 10 sentences."
            )
        user_msg = f"Function: {func_name}\n\nDisassembly:\n{disasm[:3000]}"
        return llm.chat([Message("system", sys_msg), Message("user", user_msg)]).strip()
    except Exception:
        return ""


# ── Core API ──────────────────────────────────────────────────────────────────

def explain_function(
    registry: ToolRegistry,
    binary: str,
    func_name: str,
    llm=None,
    store=None,
    on_step=None,
    lang: str = "es",
) -> ExplainResult:
    """
    Build a structured explanation of `func_name` in `binary`.
    Static-only if llm is None; adds Qwen natural-language explanation when provided.
    For AUTHORIZED targets / CTF only.
    """
    r = ExplainResult(func_name=func_name, binary=binary)

    if on_step:
        on_step(f"explain: disassembling {func_name}...")

    # Disassembly
    disasm = _run_tool(registry, "r2_disasm", target=func_name)
    if not disasm:
        # Fallback: try r2_disasm without keyword argument
        tool = registry.get("r2_disasm")
        if tool is not None:
            try:
                res = tool.run(func_name)
                disasm = res.data if res.ok else ""
            except Exception:
                pass
    r.disasm = disasm

    # Callers / callees from xrefs
    xrefs = _run_tool(registry, "r2_xrefs", target=func_name)
    if xrefs:
        for line in xrefs.splitlines():
            if "call" in line.lower() and func_name in line:
                m = re.search(r"(sym\.[^\s]+|fcn\.[^\s]+)", line)
                if m and m.group(1) not in r.callers:
                    r.callers.append(m.group(1))

    if disasm:
        r.callees = _extract_callees(disasm)
        r.strings_used = _extract_strings(disasm)
        r.dangerous_calls, r.cve_hints = _detect_dangerous(disasm)

    if store and disasm:
        try:
            store.add_fact(f"disasm:{func_name}", "r2_disasm", disasm)
        except Exception:
            pass

    # LLM explanation (optional)
    if llm is not None and disasm:
        if on_step:
            on_step(f"explain: asking Qwen about {func_name}...")
        r.llm_explanation = _llm_explain(llm, func_name, disasm, lang=lang)

    return r


def batch_explain(
    registry: ToolRegistry,
    binary: str,
    func_names: List[str],
    llm=None,
    on_step=None,
    lang: str = "es",
) -> List[ExplainResult]:
    """Explain multiple functions sequentially, calling on_step between each."""
    results = []
    for i, name in enumerate(func_names):
        if on_step:
            on_step(f"explain [{i+1}/{len(func_names)}]: {name}")
        results.append(explain_function(registry, binary, name, llm=llm, lang=lang))
    return results


def render_explain(r: ExplainResult, lang: str = "es") -> str:
    """Render an ExplainResult as a markdown section."""
    es = lang == "es"
    out = [
        f"## {'Función' if es else 'Function'}: `{r.func_name}`\n",
        f"- {'binario' if es else 'binary'}: `{r.binary}`\n",
    ]
    if r.error:
        out.append(f"\n**{'Error' if es else 'Error'}:** {r.error}\n")
        return "".join(out)

    if r.dangerous_calls:
        badge = "PELIGROSO" if es else "DANGEROUS"
        out.append(f"- **{badge}:** `{'`, `'.join(r.dangerous_calls)}`\n")

    if r.callers:
        lbl = "Llamada desde" if es else "Called from"
        out.append(f"- {lbl}: `{'`, `'.join(r.callers[:5])}`\n")

    if r.callees:
        lbl = "Llama a" if es else "Calls"
        out.append(f"- {lbl}: `{'`, `'.join(r.callees[:8])}`\n")

    if r.strings_used:
        lbl = "Strings" if es else "Strings"
        out.append(f"- {lbl}: `{'`, `'.join(r.strings_used[:6])}`\n")

    if r.disasm:
        hdr = "Desensamblado" if es else "Disassembly"
        out.append(f"\n### {hdr}\n```asm\n{r.disasm[:1500]}\n```\n")

    if r.cve_hints:
        hdr = "Pistas CVE" if es else "CVE hints"
        out.append(f"\n### {hdr}\n")
        for h in r.cve_hints:
            out.append(f"- {h}\n")

    if r.llm_explanation:
        hdr = "Explicación (Qwen)" if es else "Explanation (Qwen)"
        out.append(f"\n### {hdr}\n{r.llm_explanation}\n")

    return "".join(out)


def explain_cve_context(
    registry: ToolRegistry,
    binary: str,
    cve_id: str,
    affected_func: Optional[str],
    llm=None,
    lang: str = "es",
) -> str:
    """
    Return a markdown string explaining what `affected_func` does in this binary,
    prefixed with CVE context. Ready to include in a CVE report section.
    """
    if not affected_func:
        return (
            f"## Contexto {cve_id}\n\nFunción afectada no especificada.\n"
            if lang == "es" else
            f"## {cve_id} context\n\nAffected function not specified.\n"
        )
    r = explain_function(registry, binary, affected_func, llm=llm, lang=lang)
    if lang == "es":
        prefix = (
            f"## Contexto {cve_id}\n\n"
            f"{cve_id} afecta a la función `{affected_func}`. "
            f"Aquí está lo que hace esa función en este binario:\n\n"
        )
    else:
        prefix = (
            f"## {cve_id} context\n\n"
            f"{cve_id} affects function `{affected_func}`. "
            f"Here is what that function does in this binary:\n\n"
        )
    return prefix + render_explain(r, lang=lang)


# ── Backwards-compatible entry point ─────────────────────────────────────────

def run_explain(registry: ToolRegistry, target: str, llm, config, store=None, on_step=None) -> AgentResult:
    task = (
        f"Explain what the function '{target}' does. First disassemble it with r2_disasm "
        f"(target={target}), then, citing only that disassembly, describe its behavior, its "
        f"inputs, any dangerous operations, and how it could be reached. Do not invent "
        f"instructions you did not see."
    )
    loop = AgentLoop(llm, registry, config, store=store, on_step=on_step)
    return loop.run(task, mode="ask")
