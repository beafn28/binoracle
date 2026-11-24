"""auto_chain — Cadena autónoma completa desde solo el CVE ID.

Reproduce el flujo de un investigador senior de explotación:
  1. Gather ALL intelligence (NVD, EPSS, CISA KEV, correlación, patch)
  2. Classify: web / binary / cli / native
  3. Hypothesis generation (LLM + deterministic)
  4. Patch diff (auto-download del commit de fix)
  5. Lab setup + verification (Docker completo)
  6. Para HUECOs sin fuente: razonamiento desde descripción
  7. Enrich (CVSS auto, CWE, executive summary)
  8. Professional report (report_generator.py)
  9. Save + return structured result

USO:
    from binoracle.workflows.auto_chain import run_full_chain
    result = run_full_chain("CVE-2024-1234", on_step=print)
    print(result.report_md)

CLI:
    binoracle chain CVE-2024-1234
    binoracle chain CVE-2024-1234 --binary /path/to/bin --lang en

Para AUTHORIZED targets / CTF / investigación defensiva únicamente.
LLM: Qwen2.5-Coder:7b via Ollama ONLY. Zero hardcoded URLs/paths/values.
"""
from __future__ import annotations

import os
import re
import tempfile
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    name:    str
    status:  str   # "ok" | "skip" | "warn" | "error"
    detail:  str   = ""
    elapsed: float = 0.0


@dataclass
class ChainResult:
    cve_id:         str
    cve_class:      str             = ""   # "web" | "binary" | "cli" | "native" | "unknown"
    cvss_score:     Optional[float] = None
    cvss_severity:  str             = ""
    epss_score:     Optional[float] = None
    epss_pct:       Optional[float] = None
    in_cisa_kev:    bool            = False
    risk_label:     str             = ""
    description:    str             = ""
    verified:       bool            = False
    steps:          List[ChainStep] = field(default_factory=list)
    findings:       List[Any]       = field(default_factory=list)
    patch_summary:  str             = ""
    mitigation_report: str          = ""
    report_md:      str             = ""
    report_path:    str             = ""
    inv:            Any             = None   # raw Investigation object
    error:          str             = ""
    elapsed_s:      float           = 0.0

    def add_step(self, name: str, status: str, detail: str = "", elapsed: float = 0.0):
        self.steps.append(ChainStep(name, status, detail, elapsed))

    def banner(self) -> str:
        kev = " [CISA KEV — ACTIVELY EXPLOITED]" if self.in_cisa_kev else ""
        epss_str = f" | EPSS {self.epss_score:.0%} ({self.epss_pct:.0f}th pct)" if self.epss_score else ""
        return (f"{self.cve_id} | {self.risk_label or self.cvss_severity} "
                f"CVSS {self.cvss_score or '?'}{epss_str}{kev}")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _t():
    t = time.time()
    return lambda: time.time() - t


def _safe(fn, *a, default=None, **kw):
    try:
        return fn(*a, **kw)
    except Exception:
        return default


def _banner(step, msg: str):
    step(f"{'─'*60}")
    step(f"  {msg}")
    step(f"{'─'*60}")


# ── Intelligence gathering ────────────────────────────────────────────────────

def _gather_intelligence(cve_id: str, result: ChainResult, step: Callable) -> Optional[Any]:
    """Stage 1: collect everything known about this CVE from every source."""
    t = _t()
    _banner(step, f"[1/8] INTELLIGENCE GATHERING — {cve_id}")

    cve_info = None
    try:
        from .cvelookup import fetch_cve
        step("  NVD + GitHub PoC + ExploitDB + OSV.dev...")
        cve_info = fetch_cve(cve_id)
        if not cve_info.ok:
            step(f"  NVD: {cve_info.note}")
            result.add_step("nvd_lookup", "warn", cve_info.note, elapsed=t())
        else:
            result.description = cve_info.description or ""
            result.cvss_score   = cve_info.cvss_score
            result.cvss_severity = cve_info.cvss_severity or ""
            poc_count = len(getattr(cve_info, "exploit_refs", []))
            step(f"  NVD: CVSS={result.cvss_score} ({result.cvss_severity}), "
                 f"PoC={poc_count}, gap={getattr(cve_info,'is_gap',True)}")
    except Exception as e:
        step(f"  NVD error: {e}")
        result.add_step("nvd_lookup", "error", str(e)[:100])
        return cve_info

    # EPSS
    try:
        epss = getattr(cve_info, "epss_score", None)
        epss_pct = getattr(cve_info, "epss_percentile", None)
        if epss is None:
            from .cvelookup import _fetch_epss  # type: ignore
            epss_data = _fetch_epss(cve_id)
            if epss_data:
                epss = epss_data.get("epss")
                epss_pct = epss_data.get("percentile")
        if epss is not None:
            result.epss_score = float(epss)
            result.epss_pct   = float(epss_pct or 0) * 100
            step(f"  EPSS: {result.epss_score:.1%} probabilidad explotación (percentil {result.epss_pct:.0f})")
    except Exception:
        pass

    # CISA KEV
    try:
        kev = getattr(cve_info, "in_cisa_kev", False)
        if not kev:
            from .cvelookup import _fetch_cisa_kev  # type: ignore
            kev_set = _fetch_cisa_kev()
            kev = cve_id in kev_set
        if kev:
            result.in_cisa_kev = True
            step("  CISA KEV: SÍ — vulnerabilidad ACTIVAMENTE EXPLOTADA en la naturaleza")
        else:
            step("  CISA KEV: no")
    except Exception:
        pass

    # Risk label
    try:
        from .cvelookup import risk_label  # type: ignore
        result.risk_label = risk_label(cve_info)
    except Exception:
        cvss = result.cvss_score or 0
        result.risk_label = (
            "CRITICAL-WEAPONIZED" if result.in_cisa_kev else
            "CRITICAL" if cvss >= 9.0 else
            "HIGH"     if cvss >= 7.0 else
            "MEDIUM"   if cvss >= 4.0 else "LOW"
        )
    step(f"  Risk label: {result.risk_label}")

    # CVE correlation
    try:
        from .cve_correlate import correlate_cve
        corr = correlate_cve(cve_id, max_related=5)
        if corr.ok and corr.related:
            step(f"  Correlación: {len(corr.related)} CVEs relacionados con {corr.component}")
    except Exception:
        pass

    result.add_step("intelligence", "ok",
                    f"cvss={result.cvss_score} epss={result.epss_score or 0:.0%} "
                    f"kev={result.in_cisa_kev}", elapsed=t())
    return cve_info


# ── CVE classification ────────────────────────────────────────────────────────

_WEB_SIGNALS = [
    "wordpress", "plugin", "theme", "drupal", "joomla", "ghost", "strapi",
    "django", "flask", "rails", "laravel", "php", "http", "web", "sqli", "xss",
    "ssrf", "path traversal", "file upload", "auth bypass", "csrf",
    "open redirect", "injection", "cms", "rest api", "graphql", "oauth",
]
_BIN_SIGNALS = [
    "buffer overflow", "heap overflow", "stack overflow", "heap corruption",
    "rop", "libc", "binary", "elf", "pe", "mach-o",
    "format string", "uaf", "use after free", "integer overflow",
    "memory corruption", "out-of-bounds", "oob", "null deref",
    "type confusion", "arbitrary code execution", "code execution",
]
_CLI_SIGNALS = ["cli", "command line", "npm package", "pip package", "gem ",
                "tool", "utility", "argument", "command injection via flag"]
_NATIVE_SIGNALS = ["sudo", "openssl", "curl", "bash", "zip", "gzip", "tar",
                   "kernel", "linux", "windows", "macos", "firmware"]


def _classify(cve_info, llm_notes: dict) -> str:
    text = ((getattr(cve_info, "description", "") or "") + " " + str(llm_notes)).lower()
    scores = {
        "web":    sum(1 for s in _WEB_SIGNALS    if s in text),
        "binary": sum(1 for s in _BIN_SIGNALS    if s in text),
        "cli":    sum(1 for s in _CLI_SIGNALS    if s in text),
        "native": sum(1 for s in _NATIVE_SIGNALS if s in text),
    }
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "unknown"


# ── Patch diff stage ──────────────────────────────────────────────────────────

def _find_patch_urls(cve_info) -> List[str]:
    """Find ALL patch/diff URLs from CVE references, ordered by quality."""
    refs = getattr(cve_info, "references", []) or []
    urls = []
    for ref in refs:
        url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
        if not url:
            continue
        m = re.search(r"(https://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40})", url)
        if m:
            urls.append(m.group(1) + ".diff")
        elif url.endswith(".diff") or url.endswith(".patch"):
            urls.append(url)
    # Also check patch_intel block
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        pi = ref.get("patch_intel")
        if pi:
            for fc in (pi.get("fix_commits") or []):
                fc_url = fc.get("url", "")
                if fc_url and "github.com" in fc_url:
                    urls.append(fc_url + ".diff")
    return list(dict.fromkeys(urls))  # deduplicate, preserve order


def _download(url: str, timeout: int = 20) -> Optional[str]:
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "binoracle-chain/0.4"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(512_000).decode(errors="replace")
    except Exception:
        return None


def _run_patch_stage(cve_id: str, cve_info, result: ChainResult,
                     step: Callable, tmpdir: str) -> str:
    t = _t()
    _banner(step, f"[4/8] PATCH DIFF — {cve_id}")
    urls = _find_patch_urls(cve_info)
    if not urls:
        step("  sin URL de parche en referencias NVD")
        result.add_step("patch_diff", "skip", "no patch URL")
        return ""

    for patch_url in urls[:3]:
        step(f"  descargando: {patch_url[:90]}...")
        patch_text = _download(patch_url)
        if not patch_text:
            continue
        lines = patch_text.splitlines()
        added   = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))
        step(f"  parche: +{added} líneas añadidas, -{removed} eliminadas")

        # patchdiff v2
        old_path = os.path.join(tmpdir, "patch.diff")
        with open(old_path, "w") as f:
            f.write(patch_text)
        try:
            from .patchdiff import run_patchdiff, render_patchdiff
            dr = run_patchdiff(old_path, old_path)
            dr.cve_id = cve_id
            summary = render_patchdiff(dr)
            step(f"  patchdiff: tipo={dr.patch_type.value}, "
                 f"score_seguridad={dr.security_score:.1f}")
            result.add_step("patch_diff", "ok",
                            f"type={dr.patch_type.value} +{added}/-{removed}",
                            elapsed=t())
            return summary
        except Exception:
            summary = (f"## Patch diff — {cve_id}\n\n"
                       f"- **URL**: {patch_url}\n"
                       f"- **Cambios**: +{added} líneas / -{removed} líneas\n\n"
                       f"### Funciones modificadas\n")
            # Extract function names from diff
            for l in lines:
                if l.startswith("@@") and "def " in l or "function " in l or "++" in l:
                    summary += f"- `{l[2:].strip()}`\n"
            result.add_step("patch_diff", "ok", f"+{added}/-{removed}", elapsed=t())
            return summary
    result.add_step("patch_diff", "warn", "all patch downloads failed")
    return ""


# ── Binary analysis stage ─────────────────────────────────────────────────────

def _run_binary_stage(cve_id: str, binary_path: str,
                       result: ChainResult, step: Callable, llm=None) -> str:
    t = _t()
    _banner(step, f"[5/8] BINARY ANALYSIS — {os.path.basename(binary_path)}")
    parts = []

    # Quick triage
    try:
        from .triage import triage_cve, render_triage
        from ..oracles.base import ToolRegistry
        step("  triage: ELF header + mitigaciones + imports...")
        reg = ToolRegistry()
        tr  = triage_cve(cve_id=cve_id, binary=binary_path, registry=reg, on_step=step)
        tmd = render_triage(tr)
        parts.append(tmd)
        label = tr.score.label if tr.score else "?"
        step(f"  triage confidence: {label}")
        result.add_step("triage", "ok", f"confidence={label}", elapsed=t())
    except Exception as e:
        step(f"  triage error: {e}")
        result.add_step("triage", "error", str(e)[:100])

    # Mitigation fingerprint + bypass
    try:
        from .mitigation_bypass import analyze_mitigations, render_mitigation_report
        t2 = _t()
        step("  mitigaciones: NX, PIE, Canary, RELRO, CFI, ASan, SafeStack...")
        mr  = analyze_mitigations(binary_path, llm=llm)
        mmd = render_mitigation_report(mr)
        result.mitigation_report = mmd
        parts.append(mmd)
        present = [m.name for m in mr.mitigations if m.present]
        step(f"  mitigaciones presentes: {', '.join(present) or 'ninguna'}")
        result.add_step("mitigation_bypass", "ok",
                        f"{len(present)} mitigations", elapsed=t2())
    except Exception as e:
        step(f"  mitigation_bypass error: {e}")
        result.add_step("mitigation_bypass", "error", str(e)[:100])

    # ROP chain if relevant
    try:
        t3 = _t()
        step("  buscando gadgets ROP...")
        from .rop import build_rop_chain, render_rop
        rc  = build_rop_chain(binary_path)
        if rc.chains:
            step(f"  ROP: {len(rc.chains)} cadenas generadas")
            parts.append(render_rop(rc))
            result.add_step("rop_chain", "ok", f"{len(rc.chains)} chains", elapsed=t3())
        else:
            result.add_step("rop_chain", "skip", "no chains found")
    except Exception:
        pass

    return "\n\n".join(parts)


# ── Web investigation stage ───────────────────────────────────────────────────

def _run_web_stage(cve_id: str, cve_info, llm_notes: dict,
                   result: ChainResult, step: Callable,
                   budget_s: float, config=None, llm=None, lang: str = "es") -> Any:
    """Full web CVE investigation. Returns the Investigation object."""
    t = _t()
    _banner(step, f"[5/8] WEB INVESTIGATION — {cve_id}")

    is_gap = getattr(cve_info, "is_gap", True) if cve_info else True
    step(f"  modo: {'HUECO (sin PoC público)' if is_gap else 'PoC público encontrado'}")

    try:
        from .cve_agent import investigate_cve
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
        result.inv      = inv
        status = "VERIFICADO" if result.verified else "no confirmado"
        step(f"  resultado: {status}")
        result.add_step("web_investigation", "ok",
                        f"verified={result.verified} findings={len(result.findings)}",
                        elapsed=t())
        return inv
    except Exception as e:
        _tb = traceback.format_exc()
        result.add_step("web_investigation", "error", str(e)[:120])
        step(f"  error: {e}")
        return None


# ── Enrich stage ──────────────────────────────────────────────────────────────

def _run_enrich_stage(result: ChainResult, step: Callable, llm=None, lang: str = "es"):
    t = _t()
    _banner(step, "[6/8] ENRICH — CVSS auto + CWE + resumen ejecutivo")
    if not result.findings:
        step("  sin hallazgos para enriquecer")
        result.add_step("enrich", "skip", "no findings")
        return

    try:
        from .enrich import enrich_findings, auto_cvss, map_cwe
        enrich_findings(llm, result.findings, lang=lang, on_step=step)
        for f in result.findings:
            cve_est = auto_cvss(f)
            cwes    = map_cwe(f)
            step(f"  [{f.title[:40]}] CVSS~{cve_est.score} CWE={cwes[0] if cwes else '?'}")
        result.add_step("enrich", "ok",
                        f"{len(result.findings)} findings enriched", elapsed=t())
    except Exception as e:
        result.add_step("enrich", "error", str(e)[:80])


# ── Professional report stage ─────────────────────────────────────────────────

def _run_report_stage(result: ChainResult, step: Callable,
                      lang: str = "es", save: bool = True) -> str:
    t = _t()
    _banner(step, "[7/8] PROFESSIONAL REPORT")

    md_parts = []

    # Try the full professional generator first
    if result.inv is not None:
        try:
            from .report_generator import generate_report
            rpt = generate_report(result.inv, lang=lang)
            md  = rpt.to_markdown()
            if md.strip():
                md_parts.append(md)
                step("  report_generator: OK")
        except Exception as e:
            step(f"  report_generator: {e} — fallback to render_investigation")

    # Fallback: render_investigation
    if not md_parts and result.inv is not None:
        try:
            from .cve_agent import render_investigation
            md = render_investigation(result.inv, lang=lang)
            if md.strip():
                md_parts.append(md)
        except Exception:
            pass

    # Patch diff
    if result.patch_summary:
        md_parts.append(result.patch_summary)
    # Mitigation bypass
    if result.mitigation_report:
        md_parts.append(result.mitigation_report)
    # Chain execution log
    md_parts.append(_render_chain_log(result, lang))

    full_md = "\n\n---\n\n".join(md_parts)

    if save and full_md:
        try:
            report_dir = os.path.join(os.path.expanduser("~"), ".binoracle", "reports")
            os.makedirs(report_dir, exist_ok=True)
            path = os.path.join(report_dir, f"{result.cve_id}.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(full_md)
            result.report_path = path
            step(f"  informe guardado: {path}")
        except Exception as e:
            step(f"  no se pudo guardar: {e}")

    result.add_step("report", "ok", result.report_path, elapsed=t())
    return full_md


def _render_chain_log(result: ChainResult, lang: str = "es") -> str:
    es = lang == "es"
    hdr = "## " + ("Ejecución autónoma — log" if es else "Autonomous execution log")
    out = [hdr, f"\n- **CVE**: `{result.cve_id}`"]
    if result.cvss_score:
        out.append(f"- **CVSS**: {result.cvss_score} ({result.cvss_severity})")
    if result.epss_score is not None:
        out.append(f"- **EPSS**: {result.epss_score:.1%} ({result.epss_pct:.0f}th percentil)")
    if result.in_cisa_kev:
        out.append("- **CISA KEV**: SÍ — EXPLOTADA ACTIVAMENTE")
    out.append(f"- **Risk**: {result.risk_label}")
    out.append(f"- **Verificado**: {'SÍ' if result.verified else 'NO'}")
    out.append(f"- **Tiempo total**: {result.elapsed_s:.1f}s\n")
    out.append("\n### " + ("Pasos" if es else "Steps"))
    for s in result.steps:
        icon = "✓" if s.status == "ok" else ("⊘" if s.status == "skip" else
               "⚠" if s.status == "warn" else "✗")
        out.append(f"- {icon} `{s.name}` — {s.detail} [{s.elapsed:.1f}s]")
    return "\n".join(out)


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────

def run_full_chain(
    cve_id:      str,
    binary:      str   = "",
    lang:        str   = "es",
    budget_s:    float = 300.0,
    on_step:     Optional[Callable[[str], None]] = None,
    config=None,
    llm=None,
    save_report: bool  = True,
    no_cache:    bool  = False,
) -> ChainResult:
    """
    Cadena autónoma completa. Un investigador senior desde solo el CVE ID.

    Args:
        cve_id:      CVE identifier (e.g. "CVE-2024-1234")
        binary:      optional binary path (forces binary analysis path)
        lang:        "es" or "en"
        budget_s:    max seconds for the web investigation stage
        on_step:     progress callback(str)
        config:      binoracle config (auto-loaded if None)
        llm:         LLM backend (auto-created if None)
        save_report: save to ~/.binoracle/reports/{CVE_ID}.md
        no_cache:    force fresh investigation (bypass cache)

    Returns:
        ChainResult with verified, findings, report_md, report_path, etc.
    """
    t0     = time.time()
    cve_id = cve_id.upper().strip()
    step   = on_step or (lambda _m: None)
    result = ChainResult(cve_id=cve_id)

    _banner(step, f"binoracle AUTO-CHAIN — {cve_id}")
    step(f"  lang={lang} budget={budget_s}s binary={'yes' if binary else 'no'}")

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
            step(f"  LLM: {getattr(llm, 'model', '?')}")
        except Exception:
            step("  LLM: no disponible (modo determinístico)")

    # ── Stage 1: Intelligence ─────────────────────────────────────────────────
    cve_info = _gather_intelligence(cve_id, result, step)

    # ── Stage 2: LLM Hypothesis ───────────────────────────────────────────────
    _banner(step, "[2/8] LLM HYPOTHESIS")
    llm_notes: dict = {}
    if llm and result.description:
        try:
            from .cve_agent import _llm_research  # type: ignore
            llm_notes = _llm_research(llm, cve_id, result.description) or {}
            vc = llm_notes.get("vuln_class", "?")
            endpoint = llm_notes.get("endpoint", "?")
            step(f"  clase={vc}, endpoint={endpoint}, "
                 f"auth={llm_notes.get('auth_required','?')}")
            result.add_step("llm_hypothesis", "ok",
                            f"class={vc} auth={llm_notes.get('auth_required')}")
        except Exception as e:
            step(f"  hypothesis error: {e}")
            result.add_step("llm_hypothesis", "skip", str(e)[:80])
    else:
        step("  sin LLM o sin descripción — modo determinístico")
        result.add_step("llm_hypothesis", "skip", "no LLM")

    # ── Stage 3: Classify ─────────────────────────────────────────────────────
    _banner(step, "[3/8] CLASSIFY")
    if binary:
        result.cve_class = "binary"
    else:
        result.cve_class = _classify(cve_info, llm_notes)
    step(f"  CVE class: {result.cve_class}")
    result.add_step("classify", "ok", result.cve_class)

    # ── Stage 4: Patch diff ───────────────────────────────────────────────────
    with tempfile.TemporaryDirectory(prefix="bo_chain_") as tmpdir:
        if cve_info:
            result.patch_summary = _run_patch_stage(
                cve_id, cve_info, result, step, tmpdir)

        # ── Stage 5: Core investigation ───────────────────────────────────────
        if binary:
            investigation_md = _run_binary_stage(cve_id, binary, result, step, llm=llm)
            result.report_md = investigation_md
        elif result.cve_class in ("web", "unknown", "cli"):
            _run_web_stage(
                cve_id, cve_info, llm_notes, result, step,
                budget_s=budget_s, config=config, llm=llm, lang=lang)
        elif result.cve_class in ("native", "binary"):
            # native binary CVE with no binary provided — doc the limitation
            step("  CVE de binario nativo sin binario proporcionado")
            step("  Usa --binary /path/to/binary para análisis completo")
            result.add_step("investigation", "skip",
                            "native/binary CVE — provide --binary")
            # Still run the web stage as fallback (might have Docker PoC)
            _run_web_stage(
                cve_id, cve_info, llm_notes, result, step,
                budget_s=budget_s, config=config, llm=llm, lang=lang)
        else:
            result.add_step("investigation", "skip", f"class={result.cve_class}")

    # ── Stage 6: Enrich ───────────────────────────────────────────────────────
    _run_enrich_stage(result, step, llm=llm, lang=lang)

    # ── Stage 7: Report ───────────────────────────────────────────────────────
    result.elapsed_s = time.time() - t0
    result.report_md = _run_report_stage(result, step, lang=lang, save=save_report)

    # ── Stage 8: Done ─────────────────────────────────────────────────────────
    _banner(step, f"[8/8] COMPLETADO en {result.elapsed_s:.1f}s")
    step(result.banner())
    if result.report_path:
        step(f"  informe: {result.report_path}")

    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

def chain_cli(argv=None):
    """Entry point: binoracle chain CVE-XXXX-YYYY [--binary /path] [--lang es|en]"""
    import argparse
    p = argparse.ArgumentParser(prog="binoracle chain",
                                description="Cadena autónoma completa desde solo el CVE ID")
    p.add_argument("cve_id", help="CVE identifier (e.g. CVE-2024-1234)")
    p.add_argument("--binary", default="", help="Path to binary (for binary CVEs)")
    p.add_argument("--lang", default="es", choices=["es", "en"])
    p.add_argument("--budget", type=float, default=300.0,
                   help="Max seconds for web investigation stage")
    p.add_argument("--no-save", action="store_true",
                   help="Don't save report to disk")
    p.add_argument("--no-cache", action="store_true",
                   help="Force fresh investigation (bypass cache)")
    args = p.parse_args(argv)

    result = run_full_chain(
        cve_id=args.cve_id,
        binary=args.binary,
        lang=args.lang,
        budget_s=args.budget,
        on_step=lambda m: print(f"  {m}"),
        save_report=not args.no_save,
        no_cache=args.no_cache,
    )
    print(result.report_md)
    return 0 if not result.error else 1
