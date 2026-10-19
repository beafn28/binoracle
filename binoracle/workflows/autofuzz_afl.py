"""Fuzzing integration: auto-build an AFL++-instrumented harness, drive real coverage-guided
fuzzing with `afl-fuzz`, and feed every crash it finds back into binoracle's own verify/triage
loop. ROADMAP v0.4: "Fuzzing integration. Auto-build harnesses, drive AFL++/libFuzzer, and feed
crashes back into the verify/triage loop (coverage-guided)."

This is deliberately NOT `autofuzz.py` (that module hand-picks a short list of KNOWN
vulnerability-shaped payloads -- cyclic patterns, %p/%n, extreme integers -- to find a trigger
fast; no real coverage feedback, no mutation engine) and NOT `fuzz.py` (that one only prints a
harness template / an afl-fuzz command line for the user to run themselves). This module
actually BUILDS and RUNS afl-fuzz, bounded by a real time budget, and classifies every crash it
saves by replaying it under gdb/lldb (`dynamic_dbg.DebuggerOracle`) -- a crash afl-fuzz found is
not "done" until binoracle's own grounded oracle confirms it (register state + backtrace), not
just "afl says it segfaulted".

Two modes:
  - instrumented (preferred): given the C SOURCE, compiled with `afl-clang-fast` for real
    coverage feedback. Needs `-w -std=gnu89` for this project's own intentionally-vulnerable
    sample corpus (classic unsafe calls like `gets()` are a hard `-Werror`-class error under
    clang's default C standard, not just a warning -- confirmed live building `ret2win.c`).
  - black-box/QEMU (binary only, no source): `afl-fuzz -Q` against the raw binary. Needs AFL++'s
    own `afl-qemu-trace` helper, which the stock Ubuntu `afl++` package does NOT ship built by
    default (confirmed live: no `afl-qemu-trace` anywhere on this host after `apt install
    afl++`) -- this mode degrades honestly (NOT_APPLICABLE) rather than silently falling back
    to something weaker when it is missing.

For AUTHORIZED targets / CTF / your own code only."""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FuzzCrash:
    path: str
    input_hex: str
    confirmed: bool = False       # el propio gdb/lldb reprodujo un crash real (no solo afl)
    detail: str = ""


@dataclass
class AflFuzzResult:
    ok: bool = False
    note: str = ""
    binary: str = ""
    mode: str = ""                 # "instrumented" | "qemu"
    budget_s: int = 0
    crashes: List[FuzzCrash] = field(default_factory=list)

    @property
    def confirmed_crashes(self) -> int:
        return sum(1 for c in self.crashes if c.confirmed)


def afl_available() -> bool:
    return bool(shutil.which("afl-fuzz"))


def _afl_qemu_available() -> bool:
    # El propio afl-fuzz busca este binario junto a si mismo (p.ej. /usr/lib/afl/) para -Q; si
    # no esta en PATH bajo ningun nombre conocido, el modo QEMU fallaria igualmente.
    return bool(shutil.which("afl-qemu-trace"))


def _classify_crash(binary: str, data: bytes) -> FuzzCrash:
    """Retroalimenta el crash al loop de verificacion/triage de binoracle: lo reproduce con el
    oraculo dinamico (gdb/lldb) en vez de confiar solo en el codigo de salida que afl-fuzz ya
    observo -- confirmacion independiente, con registros y backtrace reales."""
    fc = FuzzCrash(path="", input_hex=data.hex())
    try:
        from ..oracles.dynamic_dbg import DebuggerOracle
        oc = DebuggerOracle(binary)
        if not oc.available():
            fc.detail = f"no disponible: {oc.why_unavailable()}"
            return fc
        tool = {t.name: t for t in oc.tools()}["dbg_run_input"]
        r = tool.run(stdin_text=data)
        if not r.ok:
            fc.detail = r.error or "dbg_run_input fallo"
            return fc
        fc.confirmed = bool(r.meta.get("crashed"))
        fc.detail = (r.data or "")[-800:]
    except Exception as e:
        fc.detail = f"error clasificando: {e}"
    return fc


def autofuzz_afl(binary: str, source: Optional[str] = None, budget_s: int = 60,
                 max_crashes_to_classify: int = 10) -> AflFuzzResult:
    res = AflFuzzResult(binary=binary, budget_s=budget_s)
    if not afl_available():
        res.note = "afl-fuzz no esta instalado (apt install afl++)"
        return res

    workdir = tempfile.mkdtemp(prefix="binoracle_afl_")
    in_dir = os.path.join(workdir, "in")
    out_dir = os.path.join(workdir, "out")
    os.makedirs(in_dir, exist_ok=True)
    with open(os.path.join(in_dir, "seed"), "wb") as f:
        f.write(b"A" * 8)

    target = binary
    mode = "qemu"
    if source and os.path.exists(source) and shutil.which("afl-clang-fast"):
        built = os.path.join(workdir, "target_afl")
        try:
            cc = subprocess.run(["afl-clang-fast", "-w", "-std=gnu89", "-o", built, source],
                               capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            cc = None
        if cc is not None and cc.returncode == 0 and os.path.exists(built):
            target = built
            mode = "instrumented"
        else:
            res.note = ("auto-build con afl-clang-fast fallo (ver fuente); cayendo a modo QEMU "
                       "contra el binario ya compilado")
    if mode == "qemu" and not _afl_qemu_available():
        return AflFuzzResult(
            ok=False, binary=binary, budget_s=budget_s,
            note="modo QEMU no disponible (falta afl-qemu-trace -- el paquete afl++ de esta "
                 "distro no lo trae compilado; necesitas fuente para el modo instrumentado, o "
                 "compilar el soporte QEMU de AFL++ tu mismo)")

    cmd = ["afl-fuzz", "-i", in_dir, "-o", out_dir]
    if mode == "qemu":
        cmd.append("-Q")
    cmd += ["-V", str(int(budget_s)), "--", target]
    env = dict(os.environ)
    env.update({"AFL_SKIP_CPUFREQ": "1", "AFL_NO_AFFINITY": "1",
               "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"})
    try:
        subprocess.run(cmd, cwd=workdir, env=env, capture_output=True, text=True,
                       timeout=budget_s + 60)
    except subprocess.TimeoutExpired:
        pass

    res.mode = mode
    crash_files = sorted(glob.glob(os.path.join(out_dir, "default", "crashes", "id:*")))
    for cf in crash_files[:max_crashes_to_classify]:
        try:
            with open(cf, "rb") as f:
                data = f.read()
        except OSError:
            continue
        fc = _classify_crash(binary, data)
        fc.path = os.path.basename(cf)
        res.crashes.append(fc)

    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    res.ok = True
    res.note = (f"afl-fuzz ({mode}) corrio {budget_s}s: {len(crash_files)} crash(es) "
               f"encontrados, {res.confirmed_crashes}/{len(res.crashes)} confirmados por "
               f"gdb/lldb (reproduce+backtrace real, no solo el codigo de salida de afl)")
    return res


def render_autofuzz_afl(r: AflFuzzResult) -> str:
    out = [f"## Fuzzing integration (AFL++, {r.mode or '?'})\n"]
    if not r.ok:
        return "\n".join(out + ["No disponible: " + r.note])
    out.append(f"- binario: `{r.binary}`  (budget={r.budget_s}s)")
    out.append(f"- {r.note}")
    if not r.crashes:
        return "\n".join(out)
    out.append("\n### Crashes (retroalimentados al oraculo dinamico)\n")
    for c in r.crashes:
        tag = "CONFIRMADO" if c.confirmed else "no reproducido"
        out.append(f"- **{c.path}** [{tag}] -- input: `{c.input_hex[:80]}"
                   f"{'...' if len(c.input_hex) > 80 else ''}`")
        if c.detail:
            out.append("  ```\n  " + c.detail.replace("\n", "\n  ")[:600] + "\n  ```")
    return "\n".join(out)
