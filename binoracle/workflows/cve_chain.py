"""Multi-CVE exploit chains — web RCE → local privilege escalation.

Orchestrates sequential CVE investigations where the output of one stage
feeds the next. Classic chain pattern:

  Stage 0  Web RCE        (CVE-XXXX-AAAA) → remote shell as www-data
  Stage 1  Local privesc  (CVE-XXXX-BBBB) → root/SYSTEM via kernel/sudo/SUID bug
  Stage 2  Persistence    (optional)       → establish implant / pivot

Each stage is an independent CVE pipeline run. The chain runner:
  1. Fetches NVD descriptions for all CVEs.
  2. Groups them by stage role (web_rce | local_privesc | persistence | other)
     using simple heuristics on the description + vuln_class.
  3. Runs each stage in dependency order, passing the assumed "pre-condition"
     (attacker foothold) forward to the next stage's hypothesis prompt.
  4. Produces a chain report: per-stage summary + overall narrative.

SOLO USO AUTORIZADO — solo contra contenedores Docker que tu mismo aprovisionas
localmente o sistemas para los que tienes autorización escrita explícita.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

STAGE_ROLES = ("web_rce", "local_privesc", "persistence", "lateral", "other")


@dataclass
class ChainStage:
    cve_id: str
    role: str = "other"            # web_rce | local_privesc | persistence | lateral | other
    description: str = ""
    vuln_class: str = ""
    precondition: str = ""         # assumed attacker state going into this stage
    postcondition: str = ""        # assumed attacker state after this stage
    verified: bool = False
    report_path: str = ""
    summary: str = ""
    error: str = ""
    duration_s: float = 0.0


@dataclass
class ChainResult:
    cves: List[str]
    stages: List[ChainStage] = field(default_factory=list)
    narrative: str = ""
    ok: bool = False
    total_s: float = 0.0
    note: str = ""


# ---------------------------------------------------------------------------
# Stage role classifier
# ---------------------------------------------------------------------------

_WEB_RCE_SIGNALS = (
    "ssti", "template injection", "server-side", "remote code execution", "rce",
    "deserialization", "command injection", "path traversal", "lfi", "sqli",
    "sql injection", "xxe", "ssrf", "file upload", "webshell", "jinja",
    "struts", "spring", "log4j", "drupal", "wordpress", "joomla",
    "php", "node.js", "ruby on rails", "django", "flask",
)
_LOCAL_PRIVESC_SIGNALS = (
    "privilege escalation", "privesc", "local exploit", "sudo", "suid", "setuid",
    "kernel exploit", "kernel vulnerability", "uaf in", "use-after-free",
    "arbitrary write", "heap overflow", "race condition",
    "linux kernel", "windows kernel", "netfilter", "nftables", "io_uring",
    "dirty pipe", "dirty cow", "pkexec", "polkit", "dbus",
)
_PERSISTENCE_SIGNALS = (
    "persistence", "backdoor", "implant", "cron", "startup", "autorun",
    "registry", "scheduled task", "service installation",
)
_LATERAL_SIGNALS = (
    "lateral movement", "credential", "pass-the-hash", "kerberos", "ldap",
    "smb", "mimikatz", "ticket", "golden ticket",
)


def classify_role(description: str, vuln_class: str = "") -> str:
    """Classify a CVE's stage role in an exploit chain."""
    blob = (description + " " + vuln_class).lower()
    if any(s in blob for s in _WEB_RCE_SIGNALS):
        return "web_rce"
    if any(s in blob for s in _LOCAL_PRIVESC_SIGNALS):
        return "local_privesc"
    if any(s in blob for s in _PERSISTENCE_SIGNALS):
        return "persistence"
    if any(s in blob for s in _LATERAL_SIGNALS):
        return "lateral"
    return "other"


_ROLE_ORDER = {"web_rce": 0, "lateral": 1, "local_privesc": 2, "persistence": 3, "other": 4}


def _stage_precondition(role: str, prev_stage: Optional[ChainStage]) -> str:
    if prev_stage and prev_stage.postcondition:
        return prev_stage.postcondition
    defaults = {
        "web_rce":       "Attacker has network access to the target web service.",
        "lateral":       "Attacker has code execution on the initial web host (e.g. www-data shell).",
        "local_privesc": "Attacker has an unprivileged local shell on the target (e.g. www-data).",
        "persistence":   "Attacker has root/SYSTEM on the target.",
        "other":         "Attacker has some level of access on the target.",
    }
    return defaults.get(role, "")


def _stage_postcondition(role: str, cve_id: str) -> str:
    postconds = {
        "web_rce":       f"Attacker has remote code execution via {cve_id} (unprivileged shell, e.g. www-data).",
        "lateral":       f"Attacker can move to adjacent systems via {cve_id}.",
        "local_privesc": f"Attacker has root/SYSTEM privileges via {cve_id}.",
        "persistence":   f"Attacker has persistent access via {cve_id}.",
        "other":         f"Attacker has exploited {cve_id}.",
    }
    return postconds.get(role, f"Attacker has exploited {cve_id}.")


# ---------------------------------------------------------------------------
# Chain runner
# ---------------------------------------------------------------------------

def run_chain(cve_ids: List[str],
              config=None,
              store=None,
              on_step: Optional[Callable] = None,
              out_dir: str = ".") -> ChainResult:
    """Run a multi-CVE exploit chain in dependency order."""
    from .cvelookup import fetch_cve
    from .cve_agent import run_cve_investigation

    def step(msg: str):
        if on_step:
            on_step(msg)

    t0 = time.time()
    result = ChainResult(cves=list(cve_ids))

    if not cve_ids:
        result.note = "no CVEs provided"
        return result

    step(f"[chain] fetching NVD descriptions for {len(cve_ids)} CVEs...")

    stages: List[ChainStage] = []
    for cid in cve_ids:
        info = fetch_cve(cid)
        role = classify_role(info.description or "", "")
        s = ChainStage(
            cve_id=cid,
            role=role,
            description=info.description or "",
            postcondition=_stage_postcondition(role, cid),
        )
        stages.append(s)
        step(f"[chain]   {cid} → role={role}")

    stages.sort(key=lambda s: _ROLE_ORDER.get(s.role, 4))

    prev: Optional[ChainStage] = None
    for s in stages:
        s.precondition = _stage_precondition(s.role, prev)
        step(f"[chain] stage {s.role} — investigating {s.cve_id}...")
        t_stage = time.time()
        try:
            inv = run_cve_investigation(
                s.cve_id,
                config=config,
                store=store,
                on_step=lambda msg, _cid=s.cve_id: step(f"  [{_cid}] {msg}"),
                out_dir=out_dir,
                extra_context=f"Chain context — precondition: {s.precondition}",
            )
            s.verified = getattr(inv, "verified", False)
            s.vuln_class = getattr(inv, "vuln_class", "") or s.vuln_class
            s.report_path = getattr(inv, "report_path", "") or ""
            s.summary = (
                f"{s.cve_id} ({s.role}): "
                + (f"verified={s.verified}, class={s.vuln_class}" if s.vuln_class
                   else "investigated")
            )
        except Exception as e:
            s.error = str(e)
            s.summary = f"{s.cve_id} ({s.role}): error — {e}"
            step(f"[chain]   {s.cve_id} failed: {e}")
        s.duration_s = time.time() - t_stage
        result.stages.append(s)
        prev = s

    result.ok = any(s.verified for s in result.stages) or all(not s.error for s in result.stages)
    result.total_s = time.time() - t0
    result.narrative = _build_narrative(result.stages)
    return result


def _build_narrative(stages: List[ChainStage]) -> str:
    if not stages:
        return "No stages in chain."
    lines = ["## Exploit chain narrative\n"]
    for i, s in enumerate(stages):
        icon = {"web_rce": "🌐", "local_privesc": "⬆️", "persistence": "🔒",
                "lateral": "↔️", "other": "•"}.get(s.role, "•")
        status = "✅ VERIFIED" if s.verified else ("❌ ERROR" if s.error else "⚠️ attempted")
        lines.append(f"**Stage {i+1}: {icon} {s.role.upper()} — {s.cve_id}** {status}")
        if s.precondition:
            lines.append(f"  - Pre: _{s.precondition}_")
        if s.postcondition and not s.error:
            lines.append(f"  - Post: _{s.postcondition}_")
        if s.error:
            lines.append(f"  - Error: `{s.error}`")
        if s.report_path:
            lines.append(f"  - Report: `{s.report_path}`")
        lines.append("")

    n_verified = sum(1 for s in stages if s.verified)
    n_total = len(stages)
    if n_verified == n_total:
        lines.append(f"**Chain fully verified** — all {n_total} stages confirmed in sandbox.")
    elif n_verified > 0:
        lines.append(f"**Chain partially verified** — {n_verified}/{n_total} stages confirmed.")
    else:
        lines.append(f"**Chain investigated** — {n_total} stages analyzed, none sandbox-verified.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def render_chain(result: ChainResult) -> str:
    out = [f"## Multi-CVE exploit chain ({len(result.cves)} CVEs)\n"]
    out.append(f"CVEs: {', '.join(result.cves)}")
    out.append(f"Duration: {result.total_s:.1f}s\n")
    if result.note:
        out.append(f"_{result.note}_\n")
    if result.stages:
        out.append("| Stage | CVE | Role | Verified | Duration |")
        out.append("|-------|-----|------|:--------:|---------|")
        for i, s in enumerate(result.stages):
            vflag = "✅" if s.verified else ("❌" if s.error else "—")
            out.append(f"| {i+1} | `{s.cve_id}` | {s.role} | {vflag} | {s.duration_s:.1f}s |")
    out.append("")
    out.append(result.narrative)
    out.append("\n_SOLO USO AUTORIZADO — solo contra entornos propios o con permiso escrito._")
    return "\n".join(out)
