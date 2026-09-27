"""Oracle framework.

An Oracle is a ground-truth analyzer wrapping a real tool (radare2, angr, a debugger,
an ELF parser). Each Oracle exposes one or more Tools. A Tool call always returns a
ToolResult carrying the evidence AND its provenance (`source`), which is what lets the
agent attribute every claim to something real."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class ToolParam:
    name: str
    description: str
    required: bool = True
    default: Any = None


@dataclass
class ToolResult:
    ok: bool
    source: str                       # provenance, e.g. "radare2: pdf @ sym.main"
    data: str                         # the evidence text the model is allowed to cite
    meta: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def truncated(self, limit: int) -> "ToolResult":
        if len(self.data) <= limit:
            return self
        head = self.data[:limit]
        return ToolResult(
            ok=self.ok,
            source=self.source,
            data=head + f"\n...[truncated {len(self.data) - limit} chars]",
            meta={**self.meta, "truncated": True},
            error=self.error,
        )


@dataclass
class Tool:
    name: str
    description: str
    params: List[ToolParam]
    run: Callable[..., ToolResult]
    oracle: str = "unknown"

    def schema_line(self) -> str:
        args = ", ".join(
            f"{p.name}{'' if p.required else '?'}" for p in self.params
        )
        return f"- {self.name}({args}): {self.description}"


class Oracle:
    name = "base"

    def available(self) -> bool:  # pragma: no cover - overridden
        return False

    def why_unavailable(self) -> str:
        return "not available"

    def tools(self) -> List[Tool]:  # pragma: no cover - overridden
        return []


class ToolRegistry:
    """Aggregates the tools of every available oracle."""

    def __init__(self, oracles: List[Oracle]):
        self.oracles = oracles
        self._tools: Dict[str, Tool] = {}
        for oc in oracles:
            if oc.available():
                for t in oc.tools():
                    self._tools[t.name] = t

    def available_tools(self) -> List[Tool]:
        return list(self._tools.values())

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def catalog(self) -> str:
        if not self._tools:
            return "(no oracle tools available)"
        return "\n".join(t.schema_line() for t in self._tools.values())

    def status(self) -> List[str]:
        lines = []
        for oc in self.oracles:
            if oc.available():
                n = len([t for t in oc.tools()])
                lines.append(f"[ok]   {oc.name}: {n} tool(s)")
            else:
                lines.append(f"[--]   {oc.name}: {oc.why_unavailable()}")
        return lines
