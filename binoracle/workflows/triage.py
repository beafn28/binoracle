"""Triage workflow: run cheap grounding oracles (NO model required) and produce a
facts-only report. Deliberately deterministic and offline.

v2 additions:
  - `triage_cve(cve_id, binary)` — combines CVE lookup with binary triage in one call,
    scoring how well the binary matches the CVE (version check, affected symbols)
  - `TriageScore` — structured confidence score with rationale
  - `render_triage(report)` — markdown render
  - `quick_triage(binary)` — minimal fast triage (elf_info + checksec + imports only)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..oracles.base import ToolRegistry


@dataclass
class TriageReport:
    binary:  str
    sections: List[tuple] = field(default_factory=list)  # (title, source, text)
    score:    Optional["TriageScore"] = None

    def add(self, title: str, source: str, text: str) -> None:
        self.sections.append((title, source, text))

    def get(self, tool_name: str) -> Optional[str]:
        """Return text of the first section matching tool_name."""
        for _title, source, text in self.sections:
            if source == tool_name:
                return text
        return None


@dataclass
class TriageScore:
    """How confident are we that this binary is the right target for the CVE?"""
    confidence:  float          # 0.0 – 1.0
    version_ok:  Optional[bool] # None = could not check
    symbols_hit: List[str]      = field(default_factory=list)   # affected symbols found
    reasons:     List[str]      = field(default_factory=list)
    blockers:    List[str]      = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.confidence >= 0.8:
            return "HIGH"
        if self.confidence >= 0.5:
            return "MEDIUM"
        if self.confidence >= 0.2:
            return "LOW"
        return "NONE"


# Tools we run unconditionally during triage, in order, if available.
TRIAGE_TOOLS = [
    ("elf_info",         "File / ELF header"),
    ("elf_mitigations",  "Exploit mitigations (checksec)"),
    ("r2_info",          "radare2 binary info"),
    ("r2_checksec",      "Exploit mitigations (cross-format: ELF/PE/Mach-O)"),
    ("r2_hardening",     "Modern hardening (FORTIFY/ASan/CFI/SafeStack)"),
    ("r2_imports",       "Imports"),
    ("r2_sinks",         "Dangerous sinks and their callers"),
    ("r2_vtables",       "C++ / vtables"),
    ("r2_heap",          "Heap attack surface (UAF/double-free candidates)"),
    ("r2_indirect",      "Control de flujo indirecto (punteros a funcion / vtables)"),
]

QUICK_TRIAGE_TOOLS = [
    ("elf_info",        "File / ELF header"),
    ("elf_mitigations", "Exploit mitigations (checksec)"),
    ("r2_imports",      "Imports"),
]


def run_triage(registry: ToolRegistry, binary: str, store=None, on_step=None) -> TriageReport:
    """Run the full triage tool suite on `binary`."""
    report = TriageReport(binary=binary)
    for tool_name, title in TRIAGE_TOOLS:
        tool = registry.get(tool_name)
        if tool is None:
            continue
        if on_step:
            on_step(f"triage: {title} ({tool_name})...")
        try:
            res = tool.run()
        except Exception as e:
            report.add(title, tool_name, f"[error running {tool_name}: {e}]")
            continue
        if res.ok:
            report.add(title, res.source, res.data)
            if store:
                store.add_fact(tool_name, res.source, res.data)
        else:
            report.add(title, res.source, f"[unavailable: {res.error}]")
    return report


def quick_triage(registry: ToolRegistry, binary: str) -> TriageReport:
    """Fast triage: elf_info + checksec + imports only. No sandboxing."""
    report = TriageReport(binary=binary)
    for tool_name, title in QUICK_TRIAGE_TOOLS:
        tool = registry.get(tool_name)
        if tool is None:
            continue
        try:
            res = tool.run()
            if res.ok:
                report.add(title, res.source, res.data)
        except Exception:
            pass
    return report


def triage_cve(
    cve_id: str,
    binary: str,
    registry: Optional[ToolRegistry] = None,
    affected_versions: Optional[List[str]] = None,
    affected_symbols:  Optional[List[str]] = None,
    on_step=None,
) -> TriageReport:
    """
    Combined CVE + binary triage.

    1. Runs quick_triage to collect binary facts
    2. Checks if the binary version matches `affected_versions` (from CVE metadata)
    3. Checks if `affected_symbols` (from CVE / NVD reference) exist in the binary
    4. Produces a TriageScore: how likely is this the right target?

    `affected_versions` and `affected_symbols` come from the CVE lookup / NVD entry.
    If not provided, the score reflects only what can be inferred from the binary itself.
    """
    if registry is None:
        # Build a minimal registry (no config needed for static tools)
        try:
            from ..oracles.base import ToolRegistry as _TR
            registry = _TR()
        except Exception:
            registry = None  # type: ignore

    report = TriageReport(binary=binary)
    if registry is not None:
        for tool_name, title in QUICK_TRIAGE_TOOLS:
            tool = registry.get(tool_name)
            if tool is None:
                continue
            if on_step:
                on_step(f"triage_cve {cve_id}: {title}...")
            try:
                res = tool.run()
                if res.ok:
                    report.add(title, res.source, res.data)
            except Exception:
                pass

    report.score = _score_cve_match(
        report, cve_id, affected_versions or [], affected_symbols or []
    )
    return report


def _score_cve_match(
    report: TriageReport,
    cve_id: str,
    affected_versions: List[str],
    affected_symbols:  List[str],
) -> TriageScore:
    """Score how well this binary matches the CVE."""

    score = TriageScore(confidence=0.0, version_ok=None)

    # Base score: binary loaded at all
    if report.sections:
        score.confidence += 0.2
        score.reasons.append("binary loaded and triaged")
    else:
        score.blockers.append("binary could not be loaded")
        return score

    # Version check
    if affected_versions:
        elf_text = report.get("elf_info") or ""
        for ver in affected_versions:
            if ver in elf_text:
                score.version_ok = True
                score.confidence += 0.4
                score.reasons.append(f"affected version {ver!r} found in binary metadata")
                break
        if score.version_ok is None:
            score.version_ok = False
            score.confidence -= 0.1
            score.blockers.append(
                f"could not confirm affected version ({', '.join(affected_versions[:3])}) "
                f"in binary — may be wrong build"
            )
    else:
        score.reasons.append("no version constraint to check")
        score.confidence += 0.1

    # Symbol check
    if affected_symbols:
        imports_text = (report.get("r2_imports") or "") + (report.get("elf_info") or "")
        for sym in affected_symbols:
            if sym in imports_text:
                score.symbols_hit.append(sym)
        if score.symbols_hit:
            score.confidence += min(0.4, 0.15 * len(score.symbols_hit))
            score.reasons.append(f"affected symbols found: {', '.join(score.symbols_hit)}")
        else:
            score.blockers.append(
                f"affected symbols NOT found: {', '.join(affected_symbols[:5])} — "
                f"may be statically linked, stripped, or wrong binary"
            )

    # Mitigation context
    chk = report.get("elf_mitigations") or report.get("r2_checksec") or ""
    if "pie" in chk.lower():
        score.reasons.append("PIE enabled — need infoleak before exploit")
    if "canary" in chk.lower():
        score.reasons.append("stack canary — may need infoleak to bypass")

    score.confidence = max(0.0, min(1.0, score.confidence))
    return score


def render_triage(report: TriageReport, lang: str = "es") -> str:
    """Render a TriageReport as markdown."""
    es = lang == "es"
    hdr = "# Triage\n\n" if not es else "# Triage\n\n"
    out = [hdr, f"- binary: `{report.binary}`\n"]

    if report.score:
        s = report.score
        badge = {"HIGH": "ALTO", "MEDIUM": "MEDIO", "LOW": "BAJO", "NONE": "NULO"}.get(s.label, s.label) if es else s.label
        out.append(f"- confianza objetivo: **{badge}** ({s.confidence:.0%})\n" if es else
                   f"- target confidence: **{badge}** ({s.confidence:.0%})\n")
        if s.reasons:
            out.append(("## Señales positivas\n" if es else "## Positive signals\n"))
            for r in s.reasons:
                out.append(f"- {r}\n")
        if s.blockers:
            out.append(("## Bloqueadores\n" if es else "## Blockers\n"))
            for b in s.blockers:
                out.append(f"- {b}\n")
        if s.symbols_hit:
            out.append(f"- símbolos afectados encontrados: `{'`, `'.join(s.symbols_hit)}`\n")

    out.append("\n## Datos del binario\n")
    for title, _source, text in report.sections:
        out.append(f"\n### {title}\n```\n{text[:800]}\n```\n")

    return "".join(out)
