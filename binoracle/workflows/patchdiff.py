"""Patch-diffing v2 — n-day analysis.

ROADMAP v0.4: "Patch-diff v2 (n-day) — compare vuln vs patched code, isolate patch delta."

radiff2 is the oracle (same convention as before): it tells us WHICH functions changed and
by how much. The LLM (optional) reasons about WHICH change is the security fix and what
class of bug it hides. The model never invents a diff; it only interprets radiff2 output.

New in v2:
  - PatchType classification: BOUNDS_CHECK, INTEGER_OVERFLOW, FORMAT_STRING, UAF_GUARD, etc.
  - Security-relevance scoring: functions with size increases near typical check patterns
  - Exploit-hypothesis derivation: given the patch type, what should we look for in the
    old build?
  - `diff_cve(cve_id, old_path, new_path)` — CVE-driven entry point wires it all together
"""
from __future__ import annotations

import enum
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..llm.base import Message


# ── Patch type taxonomy ──────────────────────────────────────────────────────

class PatchType(str, enum.Enum):
    BOUNDS_CHECK      = "bounds_check"        # +size for added if(len > MAX) guard
    INTEGER_OVERFLOW  = "integer_overflow"     # multiplication replaced with safe_mul
    FORMAT_STRING     = "format_string"        # printf(user) → printf("%s", user)
    UAF_GUARD         = "uaf_guard"            # added NULL-after-free or flag
    DOUBLE_FREE_GUARD = "double_free_guard"
    NULL_DEREF_GUARD  = "null_deref_guard"
    TYPE_CONFUSION    = "type_confusion"       # added type tag / union discriminant
    UNINITIALIZED     = "uninitialized"        # variable explicitly zeroed
    INJECTION         = "injection"            # added sanitization / escape
    RACE_CONDITION    = "race_condition"       # added mutex/lock around critical section
    AUTH_CHECK        = "auth_check"           # added permission / role check
    DESERIALIZATION   = "deserialization"      # added class whitelist / type check
    MEMORY_LEAK       = "memory_leak"          # added free() / decrement refcount
    UNKNOWN           = "unknown"


# Heuristics: size delta thresholds and name patterns per patch type
# (absolute size delta of the changed function; positive = new code added)
_PATCH_SIGNALS: List[tuple] = [
    # (PatchType, name_pattern, min_size_delta, max_size_delta)
    (PatchType.BOUNDS_CHECK,      re.compile(r"parse|read|copy|memcpy|strlen|snprintf|sprintf|write", re.I), 4, 80),
    (PatchType.INTEGER_OVERFLOW,  re.compile(r"alloc|size|len|count|num|calc|mul|add", re.I), 2, 60),
    (PatchType.FORMAT_STRING,     re.compile(r"log|print|format|msg|err|warn|debug", re.I), 2, 40),
    (PatchType.UAF_GUARD,         re.compile(r"free|destroy|release|delete|close|deinit", re.I), 2, 50),
    (PatchType.DOUBLE_FREE_GUARD, re.compile(r"free|destroy|release|delete|close", re.I), 1, 30),
    (PatchType.NULL_DEREF_GUARD,  re.compile(r"get|find|lookup|fetch|load|init", re.I), 2, 40),
    (PatchType.AUTH_CHECK,        re.compile(r"auth|check|perm|access|cap|priv|role|verify", re.I), 4, 100),
    (PatchType.INJECTION,         re.compile(r"exec|run|sql|query|cmd|shell|input|user|param", re.I), 4, 80),
    (PatchType.RACE_CONDITION,    re.compile(r"lock|mutex|atomic|sync|concurrent|thread", re.I), 4, 60),
]

_EXPLOIT_HYPOTHESIS: Dict[PatchType, str] = {
    PatchType.BOUNDS_CHECK: (
        "Look for a stack/heap overflow: probe with a payload longer than the buffer and "
        "confirm a crash (SIGSEGV/SIGABRT) on the old build. Find the offset with a cyclic "
        "pattern. The patched version will return an error or truncate; old will crash."
    ),
    PatchType.INTEGER_OVERFLOW: (
        "Trigger an integer overflow: supply a very large count/size so that the allocation "
        "(count * element_size) wraps to a small number, then write more data than allocated. "
        "Compare malloc argument on old vs new build with ltrace/strace."
    ),
    PatchType.FORMAT_STRING: (
        "Probe with '%p.%p.%p' as user input: on the old build you should see stack addresses "
        "in the output. On the new build the string is passed as a format arg, so %p is "
        "printed literally. Confirm with a '%n' write-what-where on the old build."
    ),
    PatchType.UAF_GUARD: (
        "Trigger use-after-free: free the object, then call a method on the stale pointer. "
        "On the old build the vtable/data is still accessible (may be reused by next malloc); "
        "on the new build a NULL check or flag should block the second access."
    ),
    PatchType.AUTH_CHECK: (
        "Attempt the operation without the required token/session: on the old build the "
        "operation should succeed; on the new build it returns 401/403. Test with curl and a "
        "missing or forged Authorization header."
    ),
    PatchType.INJECTION: (
        "Inject metacharacters: SQL — a single quote; command — '; id #'; template — {{7*7}}. "
        "On the old build look for an error that leaks the query structure or command output. "
        "Compare HTTP responses between old and new build."
    ),
    PatchType.DESERIALIZATION: (
        "Send a crafted serialized payload (ysoserial/URLDNS chain for a quick canary). "
        "On the old build a DNS lookup or RCE should fire; on the new build the class "
        "is rejected before deserialization."
    ),
    PatchType.UNKNOWN: (
        "No clear signal from function names and size deltas. Inspect the changed functions "
        "manually: look for the first instruction that differs between old and new using "
        "`radiff2 -g <func> old new | xdot -` or `r2 -A -q -c 'pdf @ sym.<func>' old`."
    ),
}


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class ChangedFunc:
    name:        str
    old_size:    int = 0
    new_size:    int = 0
    similarity:  float = 1.0
    kind:        str = "CHANGE"   # CHANGE | NEW | REMOVED | UNMATCH

    @property
    def size_delta(self) -> int:
        return self.new_size - self.old_size

    @property
    def security_score(self) -> float:
        """0-1 score: how likely is this the security-relevant change?"""
        score = 0.0
        if self.similarity < 0.9:
            score += 0.4
        if abs(self.size_delta) > 8:
            score += 0.2
        if self.kind in ("NEW",):
            score += 0.1
        for _ptype, pat, _mn, _mx in _PATCH_SIGNALS:
            if pat.search(self.name or ""):
                score += 0.3
                break
        return min(score, 1.0)


@dataclass
class DiffResult:
    old:            str
    new:            str
    cve_id:         str = ""
    changed:        List[ChangedFunc] = field(default_factory=list)
    patch_type:     PatchType = PatchType.UNKNOWN
    top_suspect:    Optional[ChangedFunc] = None
    hypothesis:     str = ""
    raw:            str = ""
    narrative:      str = ""    # LLM interpretation, if available

    @property
    def changed_names(self) -> List[str]:
        return [f.name for f in self.changed]


# ── Core diff ────────────────────────────────────────────────────────────────

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


_RADIFF_LINE = re.compile(
    r"^(?P<old_name>\S+)\s+(?P<old_size>\d+)\s+\S+\s*\|\s*"
    r"(?P<kind>CHANGE|NEW|REMOVED|UNMATCH)\s*(?:\((?P<sim>[01]\.\d+)\))?\s*\|\s*"
    r"\S+\s+(?P<new_size>\d+)\s+(?P<new_name>\S+)"
)


def _parse_radiff2(raw: str) -> List[ChangedFunc]:
    funcs: List[ChangedFunc] = []
    for line in raw.splitlines():
        m = _RADIFF_LINE.match(line.strip())
        if m:
            d = m.groupdict()
            sim = float(d["sim"]) if d["sim"] else (1.0 if d["kind"] == "CHANGE" else 0.0)
            if sim < 1.0 or d["kind"] in ("NEW", "REMOVED", "UNMATCH"):
                funcs.append(ChangedFunc(
                    name       = d["new_name"] or d["old_name"],
                    old_size   = int(d["old_size"]),
                    new_size   = int(d["new_size"]),
                    similarity = sim,
                    kind       = d["kind"],
                ))
        else:
            # Fallback: old-style similarity-only lines
            sim_m = re.search(r"\(([01]\.\d+)\)", line)
            if sim_m and float(sim_m.group(1)) < 1.0:
                name = line.strip().split()[0] if line.strip() else ""
                funcs.append(ChangedFunc(name=name, similarity=float(sim_m.group(1))))
    return funcs


def _classify_patch(funcs: List[ChangedFunc]) -> tuple[PatchType, Optional[ChangedFunc]]:
    """Return best-guess PatchType and the most suspicious function."""
    if not funcs:
        return PatchType.UNKNOWN, None

    scored = sorted(funcs, key=lambda f: f.security_score, reverse=True)
    top = scored[0]

    for ptype, pat, min_delta, max_delta in _PATCH_SIGNALS:
        if pat.search(top.name or ""):
            delta = abs(top.size_delta)
            if min_delta <= delta <= max_delta or top.similarity < 0.85:
                return ptype, top

    return PatchType.UNKNOWN, top


# ── Public API ───────────────────────────────────────────────────────────────

def run_patchdiff(old: str, new: str, llm=None, config=None) -> DiffResult:
    """Compare two binaries. Returns a DiffResult with patch type + exploit hypothesis."""
    res = DiffResult(old=old, new=new)
    raw = _radiff2(old, new)
    if raw is None:
        res.raw = "radiff2 not found (ships with radare2). Install radare2 to enable patch-diffing."
        return res
    res.raw = raw
    res.changed = _parse_radiff2(raw)
    res.patch_type, res.top_suspect = _classify_patch(res.changed)
    res.hypothesis = _EXPLOIT_HYPOTHESIS.get(res.patch_type, _EXPLOIT_HYPOTHESIS[PatchType.UNKNOWN])
    if llm is not None and llm.available():
        res.narrative = _explain_diff(llm, res)
    return res


def diff_cve(cve_id: str, old_path: str, new_path: str, llm=None) -> DiffResult:
    """
    CVE-driven entry point: compare the vulnerable binary (old_path) against the patched
    build (new_path), tag the result with the CVE ID, and derive an exploit hypothesis.

    Both paths must exist locally (download them before calling).
    """
    res = run_patchdiff(old_path, new_path, llm=llm)
    res.cve_id = cve_id
    return res


def _explain_diff(llm, res: DiffResult) -> str:
    top_lines = "\n".join(
        f"  {f.name:<40} sim={f.similarity:.2f}  delta={f.size_delta:+d}  kind={f.kind}"
        for f in res.changed[:40]
    ) or "(no changed functions detected)"
    sys = (
        "You are a vulnerability researcher doing n-day patch analysis. "
        "You are given the radiff2 function-level diff between an OLD (vulnerable) and "
        "a NEW (patched) build. Using ONLY this diff, identify which changed function most "
        "likely contains the silent security fix, explain what class of bug the fix implies "
        "(bounds check added, integer overflow guard, format-string hardened, UAF guard, etc.), "
        "and describe the most direct way to confirm the bug in the OLD build. "
        "Do not invent function bodies you were not shown; reason from names, sizes and similarity."
    )
    cve_line = f"CVE: {res.cve_id}\n" if res.cve_id else ""
    user = (
        f"{cve_line}OLD: {res.old}\nNEW: {res.new}\n\n"
        f"Changed functions (similarity < 1.0, top {min(40, len(res.changed))}):\n{top_lines}\n\n"
        f"Automated classification: {res.patch_type.value}\n"
        f"Top suspect: {res.top_suspect.name if res.top_suspect else 'none'}\n\n"
        "Confirm, refine or correct the classification. Then: given the OLD build, what is "
        "the simplest proof-of-concept that would trigger the bug?"
    )
    return llm.chat([Message("system", sys), Message("user", user)])


def render_patchdiff(res: DiffResult) -> str:
    cve_hdr = f" ({res.cve_id})" if res.cve_id else ""
    out = [
        f"# binoracle patch-diff v2{cve_hdr}\n",
        f"- old: `{res.old}`\n- new: `{res.new}`\n"
        f"- changed functions: {len(res.changed)}\n"
        f"- patch type: **{res.patch_type.value}**\n",
    ]
    if res.top_suspect:
        t = res.top_suspect
        out.append(
            f"- top suspect: `{t.name}` "
            f"(sim={t.similarity:.2f}, delta={t.size_delta:+d}B, "
            f"score={t.security_score:.2f})\n"
        )
    out.append("## Exploit hypothesis\n")
    out.append(res.hypothesis + "\n")
    out.append("## Changed functions (radiff2, security score)\n")
    rows = sorted(res.changed, key=lambda f: f.security_score, reverse=True)[:20]
    out.append("```\n")
    out.append(f"{'function':<42} sim   delta  score\n")
    for f in rows:
        out.append(f"{f.name:<42} {f.similarity:.2f}  {f.size_delta:+5d}  {f.security_score:.2f}\n")
    out.append("```\n")
    if res.narrative:
        out.append("## LLM interpretation\n")
        out.append(res.narrative + "\n")
    out.append("## Raw radiff2 -A -C\n")
    snippet = res.raw if len(res.raw) < 6000 else res.raw[:6000] + "\n...[truncated]"
    out.append("```\n" + snippet + "\n```")
    return "\n".join(out)
