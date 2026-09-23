"""Exploit-primitive reasoner.

Given a binary, combine mitigations + gift functions + gadgets + sinks into a grounded
exploitation strategy. Heuristic core (deterministic, no model), with an optional LLM pass
that reasons on top of the same evidence. Never claims exploitability it did not observe."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..oracles.base import ToolRegistry
from ..agent.grounding import GroundingLedger
from ..agent.loop import AgentLoop, AgentResult
from ..store.session import Finding


PRIMITIVE_TASK = (
    "Determine the most likely exploitation primitive for this binary. Use r2_checksec for "
    "mitigations, r2_win for gift functions and shell strings, r2_sinks for the overflow/"
    "format entry point, r2_rop (e.g. filter 'pop rdi') for ROP building blocks, and "
    "r2_stackframe on the vulnerable function for the offset-to-return. If angr is present, "
    "test reachability. Conclude with a concrete, evidence-backed strategy (ret2win / "
    "ret2libc / ret2syscall / shellcode / format-string) and exactly what is still needed."
)


@dataclass
class Strategy:
    primitive: str
    confidence: str            # low | medium | high
    reasoning: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


def run_primitives(registry: ToolRegistry, binary: str, llm=None, config=None,
                   store=None, on_step=None) -> AgentResult:
    """Always compute the deterministic, grounded heuristic strategy first (this is the
    source of truth and cannot contradict the evidence). If a local model is available, we
    ONLY let it add narrative on top of that same evidence, never override the findings."""
    result = _heuristic_primitives(registry, store)
    if llm is not None and llm.available():
        narrative = _llm_narrative(llm, result)
        if narrative:
            result.answer += "\n\n---\n\n### analyst narrative (LLM, on top of the evidence above)\n\n" + narrative
    return result


def _llm_narrative(llm, result) -> str:
    from ..llm.base import Message
    evidence = result.ledger.evidence_trail()
    sys = ("You are an exploitation analyst. A deterministic tool already produced the "
           "grounded strategy and evidence below. Add a concise narrative: confirm or refine "
           "the primitive, and state the exact next concrete step. Use ONLY the evidence "
           "shown; never contradict a tool result (e.g. if r2_sinks lists gets, gets IS used). "
           "Cite sources as [src: <source>].")
    kb_ctx = _kb_context(result.answer)
    if kb_ctx:
        sys += ("\n\nReference cheat sheets (technique knowledge base; use to refine the "
                "plan, but it is reference not proof — do not present it as observed):\n"
                + kb_ctx)
    user = f"{result.answer}\n\n{evidence}"
    try:
        return llm.chat([Message("system", sys), Message("user", user)])
    except Exception:
        return ""


def _kb_context(query: str, k: int = 3, max_chars: int = 1600) -> str:
    """Retrieve relevant exploitation cheat sheets from the local RAG. Never raises."""
    try:
        from ..rag import get_kb
        return get_kb().context_for(query, k=k, max_chars=max_chars)
    except Exception:
        return ""


def _tool(registry, name):
    t = registry.get(name)
    return t.run() if t else None


def _heuristic_primitives(registry: ToolRegistry, store=None) -> AgentResult:
    ledger = GroundingLedger()
    strat = Strategy(primitive="unknown", confidence="low")

    checksec = _tool(registry, "r2_checksec")
    win = _tool(registry, "r2_win")
    sinks = _tool(registry, "r2_sinks")

    nx = pic = canary = "unknown"
    if checksec and checksec.ok:
        ledger.record(0, "r2_checksec", checksec.source, checksec.data)
        nx = checksec.meta.get("nx", "unknown")
        pic = checksec.meta.get("pic", "unknown")
        canary = checksec.meta.get("canary", "unknown")
        strat.evidence.append(checksec.data)

    has_win = False
    if win and win.ok:
        ledger.record(1, "r2_win", win.source, win.data)
        has_win = win.meta.get("win_funcs", 0) > 0 or "/bin/sh" in win.data
        if has_win:
            strat.evidence.append(win.data)

    sink_names = []
    if sinks and sinks.ok:
        ledger.record(2, "r2_sinks", sinks.source, sinks.data)
        sink_names = sinks.meta.get("sinks", [])
        strat.evidence.append(sinks.data)

    fmt = any(s in ("printf", "fprintf", "snprintf", "sprintf") for s in sink_names)
    overflow = any(s in ("gets", "strcpy", "strcat", "read", "scanf", "memcpy") for s in sink_names)

    # ---- decision tree, each step justified by observed evidence ----
    if fmt and "printf" in sink_names:
        strat.primitive = "format-string"
        strat.confidence = "medium"
        strat.reasoning.append("printf-family sink present -> possible %n write / %p leak.")
        strat.reasoning.append("Use fmtstr_offset to find the arg index once you know the byte offset.")

    if overflow:
        if str(nx).lower() in ("false", "nx_off", "0"):
            strat.primitive = "shellcode-on-stack"
            strat.confidence = "medium"
            strat.reasoning.append("Overflow sink + NX disabled -> classic shellcode injection viable.")
        elif has_win:
            strat.primitive = "ret2win"
            strat.confidence = "high" if str(pic).lower() in ("false", "0") else "medium"
            strat.reasoning.append("Overflow sink + a gift/shell function present -> ret2win.")
            if str(pic).lower() not in ("false", "0"):
                strat.blockers.append("PIE/PIC on: need an address leak before jumping to the win function.")
        else:
            strat.primitive = "rop (ret2libc / ret2syscall)"
            strat.confidence = "medium"
            strat.reasoning.append("Overflow sink + NX on + no gift function -> ROP chain required.")
            rop = registry.get("r2_rop")
            if rop:
                g = rop.run(filter="pop rdi")
                if g.ok and g.meta.get("count", 0) > 0:
                    ledger.record(3, "r2_rop", g.source, g.data)
                    strat.reasoning.append("Found 'pop rdi' gadget(s) (see evidence) -> ret2libc arg control feasible.")
                    strat.evidence.append(g.data)
                else:
                    strat.blockers.append("No 'pop rdi' gadget found by r2; consider ret2syscall or a libc gadget.")

        if str(canary).lower() in ("true", "1"):
            strat.blockers.append("Stack canary present: overflow will trip __stack_chk_fail unless you leak/avoid the canary.")

    if strat.primitive == "unknown" and not overflow and not fmt:
        strat.reasoning.append("No classic overflow or format-string sink observed statically.")

    # ---- render as a finding + answer ----
    finding = Finding(
        title=f"Suggested exploitation primitive: {strat.primitive}",
        severity="info",
        verdict="grounded",
        location=", ".join(sink_names) or "n/a",
        evidence="\n\n".join(strat.evidence) or "(none)",
        rationale="\n".join(f"- {r}" for r in strat.reasoning) or "(insufficient evidence)",
        recommendation=("Remaining blockers:\n" + "\n".join(f"- {b}" for b in strat.blockers)
                        if strat.blockers else "No blockers observed; build the PoC and verify with dbg_run_input."),
    )
    if store:
        store.add_finding(finding)

    answer = (
        f"## Exploitation strategy (heuristic)\n\n"
        f"- primitive: **{strat.primitive}**\n"
        f"- confidence: {strat.confidence}\n"
        f"- mitigations: NX={nx} PIE/PIC={pic} canary={canary} [src: r2_checksec]\n\n"
        f"### reasoning\n" + ("\n".join(f"- {r}" for r in strat.reasoning) or "- (none)") + "\n\n"
        f"### blockers\n" + ("\n".join(f"- {b}" for b in strat.blockers) or "- none observed") + "\n\n"
        f"Bring up a local model for deeper multi-step reasoning, or run angr/debugger to verify."
    )
    return AgentResult(ledger.annotate(answer), [finding], ledger, 1, "heuristic")
