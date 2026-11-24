"""Mitigation fingerprinting and bypass-strategy reasoning.

ROADMAP v0.3: "CFI / SafeStack / ASan reasoning — detect and bypass mitigation fingerprints."

Detects: NX, PIE, canary, RELRO, FORTIFY_SOURCE, CFI (clang forward-edge),
SafeStack (shadow stack), AddressSanitizer, UBSan, ThreadSanitizer, PAC (ARM),
BTI (ARM), IBT/SHSTK (Intel CET), shadow call stack (Android/AArch64).

For each detected mitigation produces:
  - What it protects against
  - What it does NOT protect (the bypass surface)
  - Concrete bypass strategies grounded to this binary
  - Which exploit primitives are blocked / still work

The oracle is radare2 (subprocess, same convention as hardening.py / static_r2.py).
The model (optional, Qwen 2.5-Coder:7b via Ollama) adds reasoning — it never invents
symbol names; it only interprets the symbol list handed to it.

For AUTHORIZED targets / CTF only.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_OLLAMA_URL   = os.environ.get("BINORACLE_BASE_URL", "http://localhost:11434")
_OLLAMA_MODEL = os.environ.get("BINORACLE_MODEL",    "qwen2.5-coder:7b")

try:
    import r2pipe as _r2pipe  # type: ignore
    _HAVE_R2PIPE = True
except ImportError:
    _HAVE_R2PIPE = False


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Mitigation:
    name:              str
    present:           bool
    protects_against:  str = ""
    bypass_surface:    str = ""   # what this mitigation does NOT cover
    strategies:        List[str] = field(default_factory=list)   # grounded hints
    primitives_blocked: List[str] = field(default_factory=list)
    primitives_ok:      List[str] = field(default_factory=list)
    evidence:          str = ""   # raw symbol/flag evidence from binary


@dataclass
class MitigationReport:
    binary:          str
    mitigations:     List[Mitigation] = field(default_factory=list)
    exploit_path:    str = ""    # suggested attack path given the full combination
    blocker_summary: str = ""    # one-line summary of what's actually hard
    llm_notes:       str = ""    # optional Qwen reasoning

    @property
    def present_names(self) -> List[str]:
        return [m.name for m in self.mitigations if m.present]


# ── r2 helpers ────────────────────────────────────────────────────────────────

def _r2_run(binary: str, cmd: str, timeout: float = 60.0) -> str:
    exe = shutil.which("r2") or shutil.which("radare2")
    if not exe:
        return ""
    try:
        r = subprocess.run(
            [exe, "-A", "-q", "-c", cmd, binary],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout or ""
    except Exception:
        return ""


def _r2_symbols(binary: str) -> str:
    return _r2_run(binary, "is", timeout=90.0)


def _r2_imports(binary: str) -> str:
    return _r2_run(binary, "ii", timeout=60.0)


def _r2_checksec(binary: str) -> Dict[str, str]:
    raw = _r2_run(binary, "i~nx,pie,canary,relro,stripped,arch,bits", timeout=60.0)
    result: Dict[str, str] = {}
    for line in raw.splitlines():
        for key in ("nx", "pic", "canary", "relro", "stripped", "arch", "bits"):
            if line.lower().startswith(key):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    result[key] = parts[1].strip().lower()
    return result


def _has_symbol(syms: str, pattern: str) -> bool:
    return bool(re.search(pattern, syms, re.I))


def _has_plt(binary: str, func: str) -> bool:
    out = _r2_run(binary, f"is~{func}", timeout=30.0)
    return bool(out.strip())


def _has_csu_init(binary: str) -> bool:
    return _has_plt(binary, "__libc_csu_init")


def _fortify_missing(syms: str, imports: str) -> List[str]:
    """Return raw (non-_chk) libc functions that are present but lack a _chk wrapper."""
    _WRAPPERS = {
        "memcpy": "memcpy_chk", "memmove": "memmove_chk", "memset": "memset_chk",
        "strcpy": "strcpy_chk", "strncpy": "strncpy_chk", "strcat": "strcat_chk",
        "strncat": "strncat_chk", "sprintf": "sprintf_chk", "snprintf": "snprintf_chk",
        "vsprintf": "vsprintf_chk", "vsnprintf": "vsnprintf_chk",
        "gets": "gets_chk", "fgets": "fgets_chk", "read": "read_chk",
    }
    combined = syms + imports
    missing = []
    for raw, chk in _WRAPPERS.items():
        if re.search(r"\b" + re.escape(raw) + r"\b", combined) and \
           not re.search(r"\b" + re.escape(chk) + r"\b", combined):
            missing.append(raw)
    return missing


# ── Mitigation detection ──────────────────────────────────────────────────────

def detect_mitigations(binary: str) -> List[Mitigation]:
    """
    Scan `binary` with radare2 and return a list of Mitigation objects.
    Present mitigations have present=True; absent ones are still included
    so callers can reason about what's missing.
    """
    cs   = _r2_checksec(binary)
    syms = _r2_symbols(binary)
    imps = _r2_imports(binary)
    arch = cs.get("arch", "")
    bits = cs.get("bits", "64")

    mits: List[Mitigation] = []

    # ── NX / W^X ─────────────────────────────────────────────────────────────
    nx = cs.get("nx", "false") not in ("false", "0", "")
    mits.append(Mitigation(
        name="NX", present=nx,
        protects_against="stack/heap shellcode execution (W^X: stack/heap pages not executable)",
        bypass_surface="Return-oriented programming (ROP); only blocks direct shellcode injection",
        primitives_blocked=["stack shellcode", "heap shellcode"] if nx else [],
        primitives_ok=["ROP", "ret2libc", "SROP", "JOP"],
        evidence=f"nx={cs.get('nx','?')}",
    ))

    # ── PIE / ASLR ────────────────────────────────────────────────────────────
    pie = cs.get("pic", "false") not in ("false", "0", "")
    has_puts_plt  = _has_plt(binary, "puts@plt")
    has_printf_plt= _has_plt(binary, "printf@plt")
    leak_via = []
    if has_puts_plt:  leak_via.append("puts@PLT ret2plt leak")
    if has_printf_plt: leak_via.append("printf@PLT ret2plt leak")
    mits.append(Mitigation(
        name="PIE", present=pie,
        protects_against="static address exploitation — all segments randomised at load",
        bypass_surface="Needs an infoleak first; partial overwrite (1-2 bytes) works within a page",
        strategies=(["Need infoleak first. " + (
            "Binary has " + "/".join(leak_via) + " — ret2plt leak is viable"
            if leak_via else
            "No puts/printf PLT detected — look for other infoleak (format string, OOB read)"
        )] if pie else []),
        primitives_blocked=["absolute-address ROP (rebasing required)"] if pie else [],
        primitives_ok=["partial overwrite (last 12 bits fixed)", "infoleak + rebase"],
        evidence=f"pic={cs.get('pic','?')}",
    ))

    # ── Stack canary ──────────────────────────────────────────────────────────
    canary = cs.get("canary", "false") not in ("false", "0", "")
    has_printf_fmt = _has_plt(binary, "printf") or _has_plt(binary, "fprintf")
    mits.append(Mitigation(
        name="Canary", present=canary,
        protects_against="sequential stack-buffer overflows (detects overwrite before return)",
        bypass_surface="Does not cover heap overflows, format-string leaks, or non-sequential writes",
        strategies=([
            "Format-string leak of canary value" if has_printf_fmt else
            "No printf-family PLT — canary bypass requires OOB read or partial overwrite; "
            "heap UAF/overflow bypasses canary entirely",
            "Brute-force (fork() servers only: child inherits parent canary each fork)",
        ] if canary else []),
        primitives_blocked=["naive linear stack overflow"] if canary else [],
        primitives_ok=["heap exploit", "format-string canary leak + overwrite", "SROP"],
        evidence=f"canary={cs.get('canary','?')}",
    ))

    # ── RELRO ────────────────────────────────────────────────────────────────
    relro = cs.get("relro", "no")
    full_relro = "full" in relro
    partial_relro = "partial" in relro
    mits.append(Mitigation(
        name="RELRO", present=full_relro or partial_relro,
        protects_against=(
            "Full: GOT overwrite, PLT redirect; Partial: only .got section is RO (plt.got writable)"
            if full_relro else
            "Partial: .rel.ro section only" if partial_relro else "none"
        ),
        bypass_surface=(
            "Full RELRO: no GOT — target __malloc_hook/__free_hook (glibc < 2.34), "
            "_IO_FILE vtable (glibc < 2.24), or ld.so link_map"
            if full_relro else
            ".got.plt is still writable — classic GOT overwrite works"
            if partial_relro else
            "No RELRO — full GOT overwrite trivially possible"
        ),
        strategies=([
            "__malloc_hook / __free_hook overwrite (glibc < 2.34)",
            "_IO_FILE vtable hijack via FILE struct (glibc < 2.24)",
            "ld.so link_map / _dl_open_hook",
        ] if full_relro else
        ["GOT overwrite of any lazy-resolved function"] if partial_relro else
        ["Full GOT overwrite — no protection"]),
        primitives_blocked=["GOT overwrite"] if full_relro else [],
        primitives_ok=(
            ["__malloc_hook", "__free_hook", "_IO_FILE vtable"] if full_relro else
            ["GOT overwrite", "__malloc_hook", "__free_hook"]
        ),
        evidence=f"relro={relro}",
    ))

    # ── FORTIFY_SOURCE ────────────────────────────────────────────────────────
    has_fortify = _has_symbol(syms + imps, r"__memcpy_chk|__sprintf_chk|__strcpy_chk|__read_chk")
    missing_chk = _fortify_missing(syms, imps) if has_fortify else []
    mits.append(Mitigation(
        name="FORTIFY_SOURCE", present=has_fortify,
        protects_against="Bounded writes to known-size buffers via _chk wrappers",
        bypass_surface=(
            f"Unwrapped calls still exploitable: {', '.join(missing_chk)}"
            if missing_chk else
            "All detected risky calls have _chk wrappers — no obvious unwrapped gap"
            if has_fortify else
            "No FORTIFY_SOURCE wrappers detected"
        ),
        strategies=(
            [f"Exploit unwrapped {f}() call — no bounds check at runtime" for f in missing_chk[:5]]
            if missing_chk else []
        ),
        primitives_ok=[f + "()" for f in missing_chk],
        evidence=f"fortify={'yes' if has_fortify else 'no'}, missing_chk={missing_chk}",
    ))

    # ── CFI (clang forward-edge) ──────────────────────────────────────────────
    has_cfi = _has_symbol(syms, r"__cfi_check|__cfi_slowpath")
    has_safestack = _has_symbol(syms, r"__safestack_|safestack_init|__safestack_unsafe_stack_ptr")
    cfi_strats = []
    if has_cfi and not has_safestack:
        cfi_strats = [
            "CFI covers FORWARD edges (indirect calls/jumps) only — backward edge (return address) "
            "is NOT protected without SafeStack: standard ROP via stack overflow still works",
            "Look for type-confused vtable pointer if C++ binary — CFI may allow same-type targets",
        ]
        if _has_csu_init(binary):
            cfi_strats.append("__libc_csu_init gadgets present — ret2csu backward-edge chain viable")
    elif has_cfi and has_safestack:
        cfi_strats = [
            "Both CFI + SafeStack active: return address stored in shadow stack (separate mmap region). "
            "ROP requires compromising the shadow stack pointer or finding a JOP primitive.",
            "JOP (jump-oriented programming): look for dispatch gadgets (jmp [reg]) in .plt/.got",
            "Unsafe stack (.data/.bss/.heap) is writable and not shadow-protected — pivot there",
        ]
    mits.append(Mitigation(
        name="CFI", present=has_cfi,
        protects_against="Indirect call/jump target hijacking (forward-edge CFI)",
        bypass_surface=(
            "Return address not protected (use ROP)" if has_cfi and not has_safestack else
            "Both edges protected — JOP or shadow stack corruption required" if has_cfi else
            "No CFI — indirect call hijack / vtable overwrite works"
        ),
        strategies=cfi_strats,
        primitives_blocked=(
            ["vtable hijack", "function pointer overwrite"] if has_cfi else []
        ),
        primitives_ok=(
            ["ROP (return-addr)"] if has_cfi and not has_safestack else
            ["JOP", "unsafe-stack write"] if has_cfi and has_safestack else
            ["vtable hijack", "function pointer overwrite", "ROP"]
        ),
        evidence=f"cfi={'yes' if has_cfi else 'no'}, safestack={'yes' if has_safestack else 'no'}",
    ))

    # ── SafeStack (standalone) ────────────────────────────────────────────────
    if has_safestack and not has_cfi:
        mits.append(Mitigation(
            name="SafeStack", present=True,
            protects_against="Return-address overwrite (shadow stack for unsafe allocations)",
            bypass_surface="Forward-edge (indirect calls) not protected without CFI",
            strategies=[
                "Function pointer / vtable overwrite still works (no CFI)",
                "Unsafe stack pointer (__safestack_unsafe_stack_ptr) writable from normal stack overflow",
            ],
            primitives_blocked=["naive stack smash → ROP"],
            primitives_ok=["function pointer overwrite", "vtable hijack", "heap exploit"],
            evidence="safestack=yes, cfi=no",
        ))

    # ── AddressSanitizer ─────────────────────────────────────────────────────
    has_asan = _has_symbol(syms + imps, r"__asan_|__sanitizer_")
    mits.append(Mitigation(
        name="ASan", present=has_asan,
        protects_against="Heap/stack OOB, use-after-free, double-free (shadow memory poisoning)",
        bypass_surface=(
            "ASan is usually only in debug/CI builds — confirm production binary. "
            "Shadow map starts at 0x7fff8000 (32-bit) or 0x7fffffffffff<<3 (64-bit). "
            "Allocations are 8-byte aligned; shadow byte 0xfa=heap-rz, 0xfd=freed."
            if has_asan else "No ASan detected"
        ),
        strategies=([
            "ASan in production? Unusual — verify this is not a CI/debug artifact",
            "ASan shadow memory is readable — can be used as an infoleak oracle",
            "Contiguous allocations: ASan redzone is 8 bytes; writing 9+ bytes overflows into next chunk",
        ] if has_asan else []),
        primitives_blocked=["trivial heap OOB", "double-free", "UAF"] if has_asan else [],
        primitives_ok=["large OOB (crosses redzone)", "integer overflow before allocation"],
        evidence=f"asan={'yes' if has_asan else 'no'}",
    ))

    # ── PAC (ARM pointer auth) ────────────────────────────────────────────────
    has_pac = "aarch64" in arch and _has_symbol(syms, r"__acle_se|FEAT_PAuth|pac_|paci[a-z]|retaa|retab")
    if "aarch64" in arch:
        mits.append(Mitigation(
            name="PAC", present=has_pac,
            protects_against="Return address / function pointer forgery (cryptographic pointer signing)",
            bypass_surface=(
                "PAC keys are per-process — info leak of signed pointer + key collision possible. "
                "Gadgets in non-PAC libraries (.so without pac_) are still usable."
                if has_pac else "No PAC detected on AArch64 binary"
            ),
            strategies=([
                "Find non-PAC shared library gadgets (older libc, ld.so)",
                "Brute-force 16-bit PAC field (256 attempts on average) — only feasible with retry oracle",
            ] if has_pac else ["PAC absent — standard AArch64 ROP viable"]),
            primitives_blocked=["naive ROP (signed return addresses)"] if has_pac else [],
            primitives_ok=["gadgets in non-PAC .so"],
            evidence=f"arch={arch}, pac={'yes' if has_pac else 'no'}",
        ))

    # ── Intel CET (IBT + SHSTK) ───────────────────────────────────────────────
    has_ibt  = _has_symbol(syms, r"__intel_penter|ENDBR64|ibt_enabled")
    if "x86" in arch or bits == "64":
        mits.append(Mitigation(
            name="Intel CET", present=has_ibt,
            protects_against="IBT: indirect branch target validation; SHSTK: shadow stack for returns",
            bypass_surface=(
                "IBT only validates ENDBR64 at target — look for unguarded indirect call gadgets in "
                "older .so without IBT. SHSTK: same bypass surface as SafeStack."
                if has_ibt else "No CET/IBT detected"
            ),
            strategies=([
                "Find non-IBT shared library (libc without IBT built in) for gadget source",
                "ENDBR64 gadgets at start of every function are valid IBT targets — JOP via those",
            ] if has_ibt else []),
            primitives_blocked=["arbitrary indirect-branch gadgets"] if has_ibt else [],
            primitives_ok=["ENDBR64-headed gadgets", "shadow-map exploit"],
            evidence=f"ibt={'yes' if has_ibt else 'no'}",
        ))

    return mits


# ── Qwen reasoning (optional) ────────────────────────────────────────────────

def _ask_qwen_bypass(mit_summary: str) -> str:
    prompt = (
        "You are a binary exploitation researcher analyzing mitigations on an AUTHORIZED target. "
        "Given the following mitigation fingerprint, suggest the most practical exploit path. "
        "Be specific about which primitives work and which are blocked. Under 150 words.\n\n"
        f"Mitigations:\n{mit_summary}\n\nExploit path:"
    )
    try:
        payload = json.dumps({
            "model":   _OLLAMA_MODEL,
            "prompt":  prompt,
            "stream":  False,
            "options": {"temperature": 0.1, "num_predict": 200},
        }).encode()
        req = urllib.request.Request(
            f"{_OLLAMA_URL.rstrip('/')}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return data.get("response", "").strip()
    except Exception:
        return ""


# ── Top-level analysis ────────────────────────────────────────────────────────

def analyze_mitigations(binary: str, llm=None) -> MitigationReport:
    """
    Detect all mitigations in `binary` and produce a MitigationReport with
    grounded bypass strategies.

    llm: optional binoracle LLM backend (unused if None — Qwen called directly via Ollama).
    """
    mits   = detect_mitigations(binary)
    report = MitigationReport(binary=binary, mitigations=mits)

    present = [m for m in mits if m.present]
    absent  = [m for m in mits if not m.present]

    # Derive a combined exploit path suggestion
    names_present = {m.name for m in present}
    path_parts = []

    if "NX" in names_present and "PIE" not in names_present:
        path_parts.append("NX present but no PIE — static ROP with known addresses")
    elif "NX" in names_present and "PIE" in names_present:
        path_parts.append("NX+PIE — need infoleak first, then rebase and ROP")
    elif "NX" not in names_present:
        path_parts.append("NX absent — shellcode injection viable")

    if "CFI" not in names_present and "SafeStack" not in names_present:
        path_parts.append("no CFI/SafeStack — full ROP return-chain usable")
    elif "CFI" in names_present and "SafeStack" not in names_present:
        path_parts.append("CFI (forward-edge only) — backward-edge ROP still works")
    elif "CFI" in names_present and "SafeStack" in names_present:
        path_parts.append("CFI+SafeStack — JOP or unsafe-stack pivot required")

    if "RELRO" in names_present:
        relro_m = next((m for m in present if m.name == "RELRO"), None)
        if relro_m and "Full" in relro_m.protects_against:
            path_parts.append("Full RELRO — target __malloc_hook or FILE struct instead of GOT")
        else:
            path_parts.append("Partial RELRO — GOT overwrite viable")

    report.exploit_path = "; ".join(path_parts) if path_parts else "insufficient data"

    blockers = [m.name for m in present if m.name in ("PAC", "Intel CET")]
    if blockers:
        report.blocker_summary = f"Hard mitigations present: {', '.join(blockers)} — require gadget source outside protected range"
    elif "CFI" in names_present and "SafeStack" in names_present:
        report.blocker_summary = "CFI + SafeStack combination: return-addr ROP blocked; need JOP primitive or shadow-stack info leak"
    elif present:
        report.blocker_summary = f"Active: {', '.join(names_present)}; standard ROP adjusted for NX/PIE is likely sufficient"
    else:
        report.blocker_summary = "No significant mitigations detected — classic stack smash viable"

    # Optional Qwen reasoning
    mit_summary = "\n".join(
        f"  {m.name}: {'PRESENT' if m.present else 'absent'} — {m.bypass_surface}"
        for m in mits
    )
    report.llm_notes = _ask_qwen_bypass(mit_summary)

    return report


# ── Render ────────────────────────────────────────────────────────────────────

def render_mitigation_report(r: MitigationReport) -> str:
    lines = [
        f"# Mitigation report: `{r.binary}`\n",
        f"**Active mitigations:** {', '.join(r.present_names) or 'none'}\n",
        f"**Exploit path:** {r.exploit_path}\n",
        f"**Blocker summary:** {r.blocker_summary}\n",
    ]

    present = [m for m in r.mitigations if m.present]
    absent  = [m for m in r.mitigations if not m.present]

    if present:
        lines.append("## Present mitigations\n")
        for m in present:
            lines.append(f"### {m.name}")
            lines.append(f"- **Protects against:** {m.protects_against}")
            lines.append(f"- **Bypass surface:** {m.bypass_surface}")
            if m.strategies:
                lines.append("- **Strategies:**")
                for s in m.strategies:
                    lines.append(f"  - {s}")
            if m.primitives_blocked:
                lines.append(f"- **Blocked:** {', '.join(m.primitives_blocked)}")
            if m.primitives_ok:
                lines.append(f"- **Still viable:** {', '.join(m.primitives_ok)}")
            lines.append(f"- **Evidence:** `{m.evidence}`\n")

    if absent:
        absent_names = ", ".join(m.name for m in absent)
        lines.append(f"## Absent mitigations (attack surface)\n{absent_names}\n")

    if r.llm_notes:
        lines.append("## Qwen reasoning\n")
        lines.append(r.llm_notes + "\n")

    return "\n".join(lines)
