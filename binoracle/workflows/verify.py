"""Automatic, deterministic verification pass.

This is what promotes a finding from 'grounded' to 'verified' WITHOUT relying on the model
deciding to call angr. For each candidate sink, we extract its call-site address from the
static evidence and ask angr to prove the site is reachable from entry, synthesizing a
concrete input. Reachability of the sink call with attacker input is an observable fact,
not a claim, so the promotion carries no false-positive risk."""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ..oracles.base import ToolRegistry
from ..store.session import Finding

_ADDR = re.compile(r"0x[0-9a-fA-F]+")


def verify_address(registry: ToolRegistry, addr: str) -> Tuple[bool, Optional[str], str]:
    """Ask angr whether `addr` is reachable from entry. Returns (reachable, input, evidence)."""
    tool = registry.get("angr_reachable")
    if tool is None:
        return (False, None, "angr not available")
    res = tool.run(addr=addr)
    if not res.ok:
        return (False, None, res.error or "angr error")
    reachable = bool(res.meta.get("reachable"))
    return (reachable, None, f"[{res.source}]\n{res.data}")


def _callsite_addr(evidence: str) -> Optional[str]:
    """Pull the call-site address out of an r2 xref/sink evidence line."""
    for line in evidence.splitlines():
        if "bl " in line or "call" in line.lower() or "CALL" in line:
            m = _ADDR.search(line)
            if m:
                return m.group(0)
    m = _ADDR.search(evidence)
    return m.group(0) if m else None


def auto_verify(registry: ToolRegistry, findings: List[Finding],
                store=None, on_step=None) -> Tuple[List[Finding], List[str]]:
    """Try to promote each finding to 'verified' via angr reachability. Deterministic."""
    notes: List[str] = []
    if registry.get("angr_reachable") is None:
        return findings, ["angr not installed: cannot auto-verify reachability (findings stay 'grounded')"]
    for f in findings:
        if f.verdict == "verified":
            continue
        addr = _callsite_addr(f.evidence or "")
        if not addr:
            continue
        if on_step:
            on_step(f"angr: verificando reachability de {addr} ({f.title})...")
        reachable, _inp, ev = verify_address(registry, addr)
        if reachable:
            f.verdict = "verified"
            f.evidence = (f.evidence or "") + f"\n\n--- angr verification ---\n{ev}"
            f.rationale = (f.rationale or "") + (
                f"\n\nVERIFIED: angr proved the sink call site {addr} is reachable from entry "
                f"with attacker-controlled input (concrete input synthesized above)."
            )
            notes.append(f"promoted '{f.title}' grounded->verified (angr: {addr} reachable)")
            if store:
                store.add_finding(f)
        else:
            notes.append(f"'{f.title}': angr could NOT prove {addr} reachable within bounds (stays grounded)")
    return findings, notes
