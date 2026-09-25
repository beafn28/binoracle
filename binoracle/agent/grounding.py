"""Grounding ledger: the audit trail that makes binoracle trustworthy.

Every oracle result the agent consulted is recorded with its provenance. The final answer
is checked for at least one citation, and the full evidence trail is appended so a human
can verify each claim against real tool output."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class LedgerEntry:
    step: int
    tool: str
    source: str
    data: str


@dataclass
class GroundingLedger:
    entries: List[LedgerEntry] = field(default_factory=list)

    def record(self, step: int, tool: str, source: str, data: str) -> None:
        self.entries.append(LedgerEntry(step, tool, source, data))

    def sources(self) -> List[str]:
        return [e.source for e in self.entries]

    def has_citations(self, answer: str) -> bool:
        return bool(re.search(r"\[src:", answer))

    def evidence_trail(self) -> str:
        if not self.entries:
            return "_No oracle tools were consulted._"
        out = ["## Evidence trail (grounding ledger)\n"]
        for e in self.entries:
            snippet = e.data if len(e.data) < 1200 else e.data[:1200] + "\n...[truncated]"
            out.append(f"### step {e.step}: `{e.tool}`\nsource: `{e.source}`\n\n```\n{snippet}\n```\n")
        return "\n".join(out)

    def annotate(self, answer: str) -> str:
        if not answer.strip():
            return "_(model produced no answer)_"
        if not self.has_citations(answer):
            banner = ("> [!warning] This answer contains no explicit `[src: ...]` citations. "
                      "Treat unverified statements with caution and cross-check the evidence "
                      "trail below.\n\n")
            return banner + answer
        return answer


# Sources that constitute *dynamic/symbolic proof* (allow verdict=verified):
#  - angr reachability, or a debugger-observed crash (lldb/gdb/dbg), or
#  - an exploit actually executed and confirmed in the sandbox. The "sandbox-verified" /
#    "sandbox-confirmed" markers are emitted ONLY on a real, execution-confirmed success
#    (try_ret2win/try_rop/try_fmt/try_ret2libc/try_heap), which is the strongest proof of all
#    -- stronger than reachability -- so it must not be downgraded to 'grounded'.
_PROOF_SOURCES = ("angr", "lldb", "gdb", "dbg", "sandbox-verified", "sandbox-confirmed")


def gate_findings(findings, ledger: "GroundingLedger"):
    """Code-enforced anti-false-positive layer.

    The model does not get the final say on a finding's verdict. We downgrade based on the
    evidence actually present in the grounding ledger:

      - verdict=verified requires a proof source (angr reachability or a debugger crash) in
        the ledger; otherwise it is capped at 'grounded'.
      - a finding with empty/untraceable evidence is capped at 'unverified' and flagged.

    Returns (gated_findings, notes)."""
    ledger_sources = " ".join(ledger.sources()).lower()
    ledger_blob = " ".join(e.data for e in ledger.entries).lower()
    have_proof = any(k in ledger_sources for k in _PROOF_SOURCES)
    gated = []
    notes = []
    for f in findings:
        ev = (f.evidence or "").strip()
        # 1) evidence must be non-empty and correspond to something we actually observed.
        traceable = bool(ev) and (any(tok and tok.lower() in ledger_blob
                                      for tok in _evidence_tokens(ev)) or "src" in ev.lower())
        if not ev or not traceable:
            if f.verdict != "unverified":
                notes.append(f"downgraded '{f.title}' to unverified (evidence not traceable to a tool result)")
            f.verdict = "unverified"
        # 2) verified requires a proof source.
        if f.verdict == "verified" and not have_proof:
            f.verdict = "grounded"
            notes.append(f"downgraded '{f.title}' verified->grounded (no angr/debugger proof "
                         "of reachability nor a sandbox-verified exploit)")
        gated.append(f)
    return gated, notes


def _evidence_tokens(ev: str):
    import re as _re
    # pull address- and symbol-like tokens that should also appear in the ledger data
    toks = _re.findall(r"(0x[0-9a-fA-F]+|sym\.[\w.]+|[a-zA-Z_][a-zA-Z0-9_]{3,})", ev)
    return toks[:12]
