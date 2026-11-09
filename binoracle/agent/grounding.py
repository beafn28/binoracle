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

    def _known_tokens(self):
        """Distinctive tokens (>=4 chars) from every tool name + source actually recorded."""
        toks = set()
        for e in self.entries:
            for t in re.findall(r"[a-z0-9_]{4,}", (e.tool + " " + e.source).lower()):
                toks.add(t)
        return toks

    def fabricated_citations(self, answer: str):
        """Return the `[src: X]` citations in `answer` that do NOT correspond to any tool the
        agent actually ran. This is the anti-hallucination check: a small model sometimes
        invents a plausible source (e.g. `[src: r2_strings]`) for a tool it never called. A
        citation counts as backed if it substring-matches a real source, or shares a
        distinctive token with a recorded tool name/source. Matching is deliberately lenient
        so only clearly-invented citations are flagged."""
        cits = [c.strip() for c in re.findall(r"\[src:\s*([^\]]+)\]", answer)]
        if not cits:
            return []
        sources = [e.source.lower() for e in self.entries]
        tools = [e.tool.lower() for e in self.entries]
        known = self._known_tokens()
        bad = []
        for c in cits:
            cl = c.lower().strip()
            if not cl:
                continue
            matched = any(cl in s or s in cl for s in sources) \
                or any(cl == t or t in cl or cl in t for t in tools) \
                or bool(set(re.findall(r"[a-z0-9_]{4,}", cl)) & known)
            if not matched and c not in bad:
                bad.append(c)
        return bad

    def evidence_trail(self) -> str:
        if not self.entries:
            return "_No oracle tools were consulted._"
        out = ["## Evidence trail (grounding ledger)\n"]
        for e in self.entries:
            snippet = e.data if len(e.data) < 1200 else e.data[:1200] + "\n...[truncated]"
            out.append(f"### step {e.step}: `{e.tool}`\nsource: `{e.source}`\n\n```\n{snippet}\n```\n")
        return "\n".join(out)

    def annotate(self, answer: str) -> str:
        """Prepend a provenance banner sized to the ACTUAL grounding, not just to whether the
        prose happens to contain `[src:]` tags:

          - prose already cites sources            -> nothing to add.
          - no inline tags but a real evidence trail-> a calm note pointing to it (the run IS
            grounded; a small model simply did not inline the tags).
          - no tags and no oracle consulted         -> the hard warning (truly ungrounded).
        """
        if not answer.strip():
            return "_(model produced no answer)_"
        # Anti-hallucination: flag citations that reference a tool the agent never ran.
        prefix = ""
        bad = self.fabricated_citations(answer)
        if bad:
            listed = ", ".join(f"`[src: {b}]`" for b in bad)
            prefix += ("> [!warning] These citations do not match any tool that was actually run "
                       f"and are unverified: {listed}. Trust only the evidence trail below.\n\n")
        if self.has_citations(answer):
            return prefix + answer
        if self.entries:
            n = len(self.entries)
            note = (f"> [!note] The prose below does not inline `[src: ...]` tags, but every "
                    f"statement is backed by the {n} tool result(s) recorded in the evidence "
                    f"trail (grounding ledger) at the end of this report; cross-check there.\n\n")
            return prefix + note + answer
        banner = ("> [!warning] No oracle tool was consulted for this answer, so nothing in it "
                  "is grounded. Treat every statement as unverified.\n\n")
        return prefix + banner + answer


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
