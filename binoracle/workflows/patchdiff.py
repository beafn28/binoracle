"""Patch-diffing workflow for n-day analysis.

Structural diff (radiff2) is the oracle: it tells us WHICH functions changed and by how
much. The LLM (optional) reasons about WHICH change looks like a silent security fix and
what bug it implies. The model never invents a diff; it only interprets radiff2 output."""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from ..llm.base import Message


@dataclass
class DiffResult:
    old: str
    new: str
    changed: List[str] = field(default_factory=list)
    raw: str = ""
    narrative: str = ""


def _radiff2(old: str, new: str) -> Optional[str]:
    exe = shutil.which("radiff2")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-A", "-C", old, new],
                             capture_output=True, text=True, timeout=300)
        return out.stdout or out.stderr
    except subprocess.TimeoutExpired:
        return "[radiff2 timed out]"


def run_patchdiff(old: str, new: str, llm=None, config=None) -> DiffResult:
    res = DiffResult(old=old, new=new)
    raw = _radiff2(old, new)
    if raw is None:
        res.raw = "radiff2 not found (ships with radare2). Install radare2 to enable patch-diffing."
        return res
    res.raw = raw
    # radiff2 -C columns: "<name> <size> <addr> | <TYPE> (<sim>) | <addr> <size> <name>".
    # A function changed if similarity < 1.0, or it is NEW / UNMATCH (added/removed).
    for line in raw.splitlines():
        if not line.strip():
            continue
        changed = False
        m = re.search(r"\(([01]\.\d+)\)", line)
        if m and float(m.group(1)) < 1.0:
            changed = True
        if re.search(r"\b(NEW|UNMATCH)\b", line):
            changed = True
        if changed:
            res.changed.append(line.strip())
    if llm is not None and llm.available():
        res.narrative = _explain_diff(llm, res)
    return res


def _explain_diff(llm, res: DiffResult) -> str:
    changed = "\n".join(res.changed[:60]) or "(no changed functions detected)"
    sys = (
        "You are a vulnerability researcher doing n-day patch analysis. You are given the "
        "radiff2 function-level diff between an OLD and a NEW build. Using ONLY this diff, "
        "identify which changed function most likely contains a silent security fix, explain "
        "what class of bug the fix implies (bounds check added, integer check, use-after-free "
        "guard, etc.), and how a reviewer would confirm it on the OLD build. Do not invent "
        "function bodies you were not shown; reason from names, sizes and similarity."
    )
    user = (
        f"OLD: {res.old}\nNEW: {res.new}\n\nChanged functions (similarity < 1.0):\n{changed}\n\n"
        f"Which one is the likely security fix, and why?"
    )
    return llm.chat([Message("system", sys), Message("user", user)])


def render_patchdiff(res: DiffResult) -> str:
    out = [
        "# binoracle patch-diff\n",
        f"- old: `{res.old}`\n- new: `{res.new}`\n- changed functions: {len(res.changed)}\n",
        "## Changed functions (radiff2, similarity < 1.0)\n",
        "```\n" + ("\n".join(res.changed) if res.changed else "(none detected)") + "\n```\n",
    ]
    if res.narrative:
        out.append("## Likely security fix (LLM interpretation of the diff)\n")
        out.append(res.narrative + "\n")
    out.append("## Raw radiff2 -A -C\n")
    snippet = res.raw if len(res.raw) < 6000 else res.raw[:6000] + "\n...[truncated]"
    out.append("```\n" + snippet + "\n```")
    return "\n".join(out)
