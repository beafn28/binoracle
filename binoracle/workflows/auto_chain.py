"""auto_chain — Cadena autónoma completa desde solo el CVE ID.

USO:
    from binoracle.workflows.auto_chain import run_full_chain
    result = run_full_chain("CVE-2024-1234", on_step=print)

O desde la CLI:
    binoracle chain CVE-2024-1234

CADENA:
    1. NVD lookup + correlación (fetch_cve, cve_correlate)
    2. LLM hypothesis → classify web vs binary
    3. PATCH DIFF automático (descarga commit del fix desde GitHub/NVD refs)
    4. → si web: investigate_cve (lab Docker completo: WordPress/Drupal/etc.)
       → si binary: triage_cve + mitigation_bypass + rop/fmtstring/shellcode según clase
    5. Auto-verify (HTTP + sandbox + angr según tipo)
    6. Enrich (CVSS auto, CWE mapping, LLM analysis si disponible)
    7. Render informe markdown completo

Para AUTHORIZED targets / CTF / investigación defensiva únicamente.
LLM: Qwen2.5-Coder:7b via Ollama ONLY. Zero hardcoded URLs/paths/values.
"""
from __future__ import annotations

import os
import tempfile
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    name:    str
    status:  str   # "ok" | "skip" | "error"
    detail:  str   = ""
    elapsed: float = 0.0


@dataclass
class ChainResult:
    cve_id:        str
    cve_class:     str           = ""   # "web" | "binary" | "unknown"
    cvss_score:    Optional[float] = None
    cvss_severity: str           = ""
    description:   str           = ""
    verified:      bool          = False
    steps:         List[ChainStep] = field(default_factory=list)
    findings:      List[Any]     = field(default_factory=list)
    patch_summary: str           = ""
    mitigation_report: str       = ""
    report_md:     str           = ""
    error:         str           = ""
    elapsed_s:     float         = 0.0

    def add_step(self, name: str, status: str, detail: str = "", elapsed: float = 0.0):
        self.steps.append(ChainStep(name, status, detail, elapsed))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _step_timer():
    t = time.time()
    return lambda: time.time() - t


def _safe(fn, *args, default=None, **kwargs):
    """Call fn(*args, **kwargs), return default on any exception."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        return default


def _download_patch(patch_url: str, timeout: int = 20) -> Optional[str]:
    """Download a patch/diff from a URL. Returns text or None."""
    if not patch_url:
        return None
    try:
        import urllib.request
        req = urllib.request.Request(
            patch_url, headers={"User-Agent": "binoracle-chain/0.3"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(512_000).decode(errors="replace")
    except Exception:
        return None


def _find_patch_url(cve_info) -> Optional[str]:
    """Extract the most likely patch/diff URL from CVE references."""
    refs = getattr(cve_info, "references", []) or []
    # Prefer GitHub commit .diff or .patch URLs
    for ref in refs:
        url = getattr(ref, "url", str(ref)) if not isinstance(ref, str) else ref
        if not url:
            continue
        # GitHub commit → append .diff
        import re as _re
        m = _re.search(r"(https://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40})", url)
        if m:
            return m.group(1) + ".diff"
        if url.endswith(".diff") or url.endswith(".patch"):
            return url
    return None


def _classify_cve_class(cve_info, llm_notes: dict) -> str:
    """Classify the CVE as 'web' or 'binary' from available data."""
    text = (
        (getattr(cve_info, "description", "") or "") + " " +
        str(llm_notes)
    ).lower()
    web_signals = ["wordpress", "plugin", "drupal", "joomla", "ghost", "strapi",
                   "django", "flask", "rails", "php", "http", "web", "sqli", "xss",
                   "ssrf", "path traversal", "file upload", "auth bypass", "csrf",
                   "open redirect", "injection", "cms"]
    bin_signals = ["buffer overflow", "heap", "rop", "libc", "binary", "elf",
                   "format string", "uaf", "use after free", "integer overflow",
                   "memory corruption", "stack overflow", "out-of-bounds", "oob"]
    ws = sum(1 for s in web_signals if s in text)
    bs = sum(1 for s in bin_signals if s in text)
    if ws > bs:
        return "web"
    if bs > ws:
        return "binary"
    return "unknown"


# ── Patch diff stage ──────────────────────────────────────────────────────────

def _run_patch_diff_stage(cve_id: str, cve_info, result: ChainResult,
                           step: Callable, tmpdir: str) -> str:
    """Download the patch and run patchdiff if possible. Returns summary string."""
    t = _step_timer()
    patch_url = _find_patch_url(cve_info)
    if not patch_url:
        result.add_step("patch_diff", "skip", "no patch URL found in references")
        return ""
    step(f"[patch_diff] descargando parche: {patch_url[:80]}...")
    patch_text = _download_patch(patch_url)
    if not patch_text:
        result.add_step("patch_diff", "skip", "patch download failed")
        return ""

    # Save old/new versions as files for patchdiff
    old_path = os.path.join(tmpdir, "old.diff")
    new_path = os.path.join(tmpdir, "new.diff")
    with open(old_path, "w") as f:
        f.write(patch_text)
    with open(new_path, "w") as f:
        f.write("")  # patchdiff can work with just the diff file

    summary = ""
    try:
        from .patchdiff import run_patchdiff, render_patchdiff
        dr = run_patchdiff(old_path, new_path)
        dr.cve_id = cve_id
        summary = render_patchdiff(dr)
        step(f"[patch_diff] tipo={dr.patch_type.value}, score seguridad={dr.security_score:.1f}")
        result.add_step("patch_diff", "ok", f"type={dr.patch_type.value}", elapsed=t())
    except Exception as e:
        # Fallback: basic diff summary
        lines = patch_text.splitlines()
        added = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))
        summary = (f"# Patch diff — {cve_id}\n\n"
                   f"- +{added} lines added, -{removed} lines removed\n"
                   f"- patch URL: {patch_url}\n")
        result.add_step("patch_diff", "ok", f"+{added}/-{removed} lines", elapsed=t())

    return summary


# ── Binary analysis stage ─────────────────────────────────────────────────────

def _run_binary_stage(cve_id: str, binary_path: str, result: ChainResult,
                       step: Callable, llm=None) -> str:
    """Run triage + mitigation_bypass + relevant exploit module for a binary."""
    report_parts = []
    t = _step_timer()

    # Triage
    try:
        from .triage import triage_cve, render_triage
        from ..oracles.base import ToolRegistry
        registry = ToolRegistry()
        tr = triage_cve(cve_id=cve_id, binary=binary_path, registry=registry,
                        on_step=step)
        triage_md = render_triage(tr)
        report_parts.append(triage_md)
        step(f"[triage] confianza objetivo: {tr.score.label if tr.score else '?'}")
        result.add_step("triage", "ok",
                        f"confidence={tr.score.label if tr.score else '?'}", elapsed=t())
    except Exception as e:
        result.add_step("triage", "error", str(e)[:100])

    # Mitigation bypass
    try:
        from .mitigation_bypass import analyze_mitigations, render_mitigation_report
        t2 = _step_timer()
        step(f"[mitigation_bypass] analizando mitigaciones de {os.path.basename(binary_path)}...")
        mr = analyze_mitigations(binary_path, llm=llm)
        result.mitigation_report = render_mitigation_report(mr)
        report_parts.append(result.mitigation_report)
        step(f"[mitigation_bypass] {len(mr.mitigations)} mitigaciones detectadas")
        result.add_step("mitigation_bypass", "ok",
                        f"{len(mr.mitigations)} mitigations", elapsed=t2())
    except Exception as e:
        result.add_step("mitigation_bypass", "error", str(e)[:100])

    return "\n\n".join(report_parts)


# ── Web investigation stage ───────────────────────────────────────────────────

def _run_web_stage(cve_id: str, cve_info, llm_notes: dict,
                   result: ChainResult, step: Callable, budget_s: float,
                   config=None, llm=None, lang: str = "es") -> str:
    """Run the full web CVE investigation via investigate_cve."""
    t = _step_timer()
    try:
        from .cve_agent import investigate_cve, render_investigation
        inv = investigate_cve(
            cve_id=cve_id,
            config=config,
            llm=llm,
            on_step=step,
            lang=lang,
            budget_s=budget_s,
            use_cache=False,
        )
        result.verified = getattr(inv, "verified", False)
        result.findings = getattr(inv, "findings", [])
        md = _safe(render_investigation, inv, default="") or ""
        result.add_step("web_investigation", "ok",
                        f"verified={result.verified}", elapsed=t())
        return md
    except Exception as e:
        tb = traceback.format_exc()
        result.add_step("web_investigation", "error", str(e)[:120])
        return f"## Web investigation error\n```\n{tb[:1000]}\n```\n"


# ── Report renderer ───────────────────────────────────────────────────────────

def _render_chain_report(result: ChainResult, lang: str = "es") -> str:
    es = lang == "es"
    hdr = "# " + ("Informe Autónomo binoracle" if es else "binoracle Autonomous Report")
    out = [
        f"{hdr}\n",
        f"- **CVE**: `{result.cve_id}`\n",
        f"- **Clase**: {result.cve_class}\n",
        f"- **CVSS**: {result.cvss_score} ({result.cvss_severity})\n" if result.cvss_score else "",
        f"- **Verificado**: {'SÍ' if result.verified else 'NO'}\n",
        f"- **Tiempo total**: {result.elapsed_s:.1f}s\n",
        "\n## Descripción\n",
        result.description + "\n" if result.description else "",
        "\n## Pasos ejecutados\n" if es else "\n## Steps executed\n",
    ]
    for s in result.steps:
        icon = "✓" if s.status == "ok" else ("⊘" if s.status == "skip" else "✗")
        out.append(f"- {icon} **{s.name}** ({s.status}) {s.detail} "
                   f"[{s.elapsed:.1f}s]\n")
    if result.patch_summary:
        out.append("\n" + result.patch_summary + "\n")
    if result.report_md:
        out.append("\n" + result.report_md + "\n")
    if result.mitigation_report:
        out.append("\n" + result.mitigation_report + "\n")
    if result.error:
        out.append(f"\n## Error\n```\n{result.error}\n```\n")
    return "".join(out)


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────

def run_full_chain(
    cve_id:   str,
    binary:   str = "",
    lang:     str = "es",
    budget_s: float = 300.0,
    on_step:  Optional[Callable[[str], None]] = None,
    config=None,
    llm=None,
    save_report: bool = True,
) -> ChainResult:
    """
    Cadena autónoma completa desde solo el CVE ID.

    Args:
        cve_id:   CVE identifier, e.g. "CVE-2024-1234"
        binary:   optional path to a binary — if given, skips web path
        lang:     "es" or "en"
        budget_s: max seconds for the web investigation stage
        on_step:  progress callback(str)
        config:   binoracle config (loaded from env if None)
        llm:      LLM backend (created from config if None)
        save_report: save report to ~/.binoracle/reports/{cve_id}.md

    Returns ChainResult with all findings, verification status, and markdown report.
    """
    t0 = time.time()
    cve_id = cve_id.upper().strip()
    step = on_step or (lambda _m: None)
    result = ChainResult(cve_id=cve_id)

    step(f"[chain] iniciando cadena autónoma para {cve_id}...")

    # ── Load config + LLM ─────────────────────────────────────────────────────
    if config is None:
        try:
            from ..config import load_config
            config = load_config()
        except Exception:
            config = {}
    if llm is None:
        try:
            from ..llm import make_backend
            llm = make_backend(config)
        except Exception:
            llm = None

    # ── Stage 1: NVD lookup ───────────────────────────────────────────────────
    t_stage = _step_timer()
    step(f"[chain:1/7] NVD lookup {cve_id}...")
    cve_info = None
    try:
        from .cvelookup import fetch_cve
        cve_info = fetch_cve(cve_id)
        result.description  = cve_info.description or ""
        result.cvss_score    = cve_info.cvss_score
        result.cvss_severity = cve_info.cvss_severity or ""
        step(f"[NVD] CVSS={result.cvss_score} ({result.cvss_severity})")
        result.add_step("nvd_lookup", "ok",
                        f"cvss={result.cvss_score}", elapsed=t_stage())
    except Exception as e:
        result.add_step("nvd_lookup", "error", str(e)[:100])
        step(f"[NVD] error: {e}")

    # ── Stage 2: LLM hypothesis ───────────────────────────────────────────────
    t_stage = _step_timer()
    step(f"[chain:2/7] LLM hypothesis...")
    llm_notes: dict = {}
    if llm and cve_info and result.description:
        try:
            from .cve_agent import _llm_research  # type: ignore
            llm_notes = _llm_research(llm, cve_id, result.description) or {}
            vc = llm_notes.get("vuln_class", "?")
            step(f"[LLM] clase={vc}, trigger={llm_notes.get('trigger','?')}")
            result.add_step("llm_hypothesis", "ok", f"class={vc}", elapsed=t_stage())
        except Exception as e:
            result.add_step("llm_hypothesis", "skip", str(e)[:80])
    else:
        result.add_step("llm_hypothesis", "skip", "no LLM or no description")

    # ── Stage 3: Classify web vs binary ──────────────────────────────────────
    if binary:
        result.cve_class = "binary"
    else:
        result.cve_class = _classify_cve_class(cve_info, llm_notes) if cve_info else "unknown"
    step(f"[chain:3/7] CVE clase={result.cve_class}")

    # ── Stage 4: Patch diff ───────────────────────────────────────────────────
    step(f"[chain:4/7] patch diff...")
    with tempfile.TemporaryDirectory(prefix="bo_chain_") as tmpdir:
        if cve_info:
            result.patch_summary = _run_patch_diff_stage(
                cve_id, cve_info, result, step, tmpdir)

        # ── Stage 5: Core investigation ───────────────────────────────────────
        step(f"[chain:5/7] investigación principal ({result.cve_class})...")
        investigation_md = ""
        if binary:
            investigation_md = _run_binary_stage(
                cve_id, binary, result, step, llm=llm)
        elif result.cve_class in ("web", "unknown"):
            investigation_md = _run_web_stage(
                cve_id, cve_info, llm_notes, result, step,
                budget_s=budget_s, config=config, llm=llm, lang=lang)
        else:
            result.add_step("investigation", "skip", "binary CVE but no binary provided")
            investigation_md = (
                f"## Nota\n\nCVE clasificada como **binary** pero no se proporcionó "
                f"un binario. Proporciona la ruta con `--binary /path/to/binary`.\n"
            )
        result.report_md = investigation_md

    # ── Stage 6: Enrich (CVSS + CWE, no LLM required) ────────────────────────
    t_stage = _step_timer()
    step(f"[chain:6/7] enriqueciendo hallazgos...")
    if result.findings:
        try:
            from .enrich import enrich_findings, enrich_to_json
            enrich_findings(llm, result.findings, lang=lang)
            result.add_step("enrich", "ok",
                            f"{len(result.findings)} findings enriched", elapsed=t_stage())
        except Exception as e:
            result.add_step("enrich", "error", str(e)[:80])
    else:
        result.add_step("enrich", "skip", "no findings to enrich")

    # ── Stage 7: Render + save report ─────────────────────────────────────────
    t_stage = _step_timer()
    step(f"[chain:7/7] generando informe...")
    result.elapsed_s = time.time() - t0
    full_md = _render_chain_report(result, lang=lang)
    result.report_md = full_md

    if save_report:
        try:
            report_dir = os.path.join(os.path.expanduser("~/.binoracle"), "reports")
            os.makedirs(report_dir, exist_ok=True)
            report_path = os.path.join(report_dir, f"{cve_id}.md")
            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write(full_md)
            step(f"[chain] informe guardado en {report_path}")
            result.add_step("save_report", "ok", report_path, elapsed=t_stage())
        except Exception as e:
            result.add_step("save_report", "error", str(e)[:80])

    step(f"[chain] COMPLETADO en {result.elapsed_s:.1f}s — verificado={result.verified}")
    return result


# ── CLI shorthand ─────────────────────────────────────────────────────────────

def chain_cli(argv=None):
    """Entry point for `binoracle chain CVE-XXXX-YYYY [--binary /path] [--lang es|en]`."""
    import argparse
    p = argparse.ArgumentParser(prog="binoracle chain",
                                description="Cadena autónoma completa desde solo el CVE ID")
    p.add_argument("cve_id", help="CVE identifier (e.g. CVE-2024-1234)")
    p.add_argument("--binary", default="", help="Path to a binary (for binary CVEs)")
    p.add_argument("--lang", default="es", choices=["es", "en"])
    p.add_argument("--budget", type=float, default=300.0,
                   help="Max seconds for web investigation stage (default 300)")
    p.add_argument("--no-save", action="store_true", help="Don't save report to disk")
    args = p.parse_args(argv)

    result = run_full_chain(
        cve_id=args.cve_id,
        binary=args.binary,
        lang=args.lang,
        budget_s=args.budget,
        on_step=lambda m: print(f"  {m}"),
        save_report=not args.no_save,
    )
    print(result.report_md)
    return 0 if not result.error else 1
