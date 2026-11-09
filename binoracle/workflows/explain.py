"""Grounded function-explanation workflow: disassemble a function and let the local model
explain it, strictly citing the disassembly it was given."""
from __future__ import annotations

from ..agent.loop import AgentLoop, AgentResult
from ..oracles.base import ToolRegistry


def run_explain(registry: ToolRegistry, target: str, llm, config, store=None, on_step=None) -> AgentResult:
    task = (
        f"Explain what the function '{target}' does. First disassemble it with r2_disasm "
        f"(target={target}), then, citing only that disassembly, describe its behavior, its "
        f"inputs, any dangerous operations, and how it could be reached. Do not invent "
        f"instructions you did not see."
    )
    loop = AgentLoop(llm, registry, config, store=store, on_step=on_step)
    return loop.run(task, mode="ask")
