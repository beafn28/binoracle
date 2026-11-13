"""Static analysis oracle backed by radare2.

Prefers r2pipe (persistent session, analysis cached). Falls back to invoking the `r2`
binary via subprocess so it works even without the r2pipe python package installed."""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
from typing import List, Optional

from .base import Oracle, Tool, ToolParam, ToolResult

try:
    import r2pipe  # type: ignore
    _HAVE_R2PIPE = True
except Exception:
    _HAVE_R2PIPE = False

# Classic memory-unsafe / command-exec libc sinks. Each hit is a hypothesis seed,
# never a finding on its own: the agent still has to prove reachability from input.
DANGEROUS = [
    "system", "execve", "execl", "execlp", "popen",           # command exec
    "gets", "strcpy", "strcat", "sprintf", "vsprintf",         # classic overflow
    "scanf", "sscanf", "memcpy", "memmove", "alloca",          # size-dependent
    "read", "recv",                                            # input into buffers
    "printf", "fprintf", "snprintf",                           # format-string sinks
]


class R2Oracle(Oracle):
    name = "static_r2"

    def __init__(self, binary: str, deep: bool = None):
        import os
        self.binary = binary
        # Default to light analysis ("aa") for speed on real binaries; deep ("aaa") is
        # opt-in via BINORACLE_R2_DEEP=1 (better for stripped targets, much slower).
        if deep is None:
            deep = os.environ.get("BINORACLE_R2_DEEP", "0") == "1"
        self.analysis_cmd = "aaa" if deep else "aa"
        self._r2 = None
        self._analyzed = False
        self._analysis_timed_out = False
        # Acotado como el resto de oraculos (r2session.get()/cmd_timeout(), AngrOracle._reachable):
        # el analisis inicial ('aa'/'aaa') en un binario grande/estatico puede tardar varios
        # minutos, y si r2 se queda REALMENTE colgado (bug propio de r2 en un binario raro) no
        # hay ningun otro limite que lo pare -- bug real encontrado en vivo, mismo patron que ya
        # se arreglo para `pdg` y para AngrOracle._reachable(), aqui en el chequeo de entrada que
        # los precede a todos.
        self.analysis_timeout_s = 180.0
        self.cmd_timeout_s = 60.0
        self._xref_timed_out = False

    def available(self) -> bool:
        return _HAVE_R2PIPE or shutil.which("r2") is not None or shutil.which("radare2") is not None

    def why_unavailable(self) -> str:
        return "radare2 not found on PATH (brew install radare2 / apt install radare2)"

    # ---- command execution ----
    def _pipe(self):
        if self._r2 is None:
            self._r2 = r2pipe.open(self.binary, flags=["-e", "scr.color=0", "-e", "scr.interactive=false", "-e", "log.quiet=true", "-2"])
        return self._r2

    def _ensure_analyzed_pipe(self):
        if self._analyzed or self._analysis_timed_out:
            return
        r2 = self._pipe()
        result: dict = {}
        def _run_analysis():
            try:
                r2.cmd(self.analysis_cmd)
                result["ok"] = True
            except Exception:
                result["ok"] = False
        th = threading.Thread(target=_run_analysis, daemon=True)
        th.start()
        th.join(self.analysis_timeout_s)
        if th.is_alive() or not result.get("ok"):
            # r2 realmente colgado (o el analisis fallo): matar el proceso colgado en vez de
            # dejarlo bloquear el resto del pipeline; el hilo que sigue esperando el pipe queda
            # abandonado (es daemon). self._r2 se descarta -- cualquier intento posterior de
            # reabrir empezaria de cero, pero se marca timed_out para no reintentar el mismo
            # analisis eterno en esta misma instancia.
            try:
                r2.process.kill()
            except Exception:
                pass
            self._analysis_timed_out = True
            self._r2 = None
            return
        self._analyzed = True

    def _cmd_timed(self, r2, cmd: str) -> Optional[str]:
        result: dict = {}
        def _run_cmd():
            try:
                result["out"] = r2.cmd(cmd)
            except Exception:
                result["out"] = None
        th = threading.Thread(target=_run_cmd, daemon=True)
        th.start()
        th.join(self.cmd_timeout_s)
        if th.is_alive():
            try:
                r2.process.kill()
            except Exception:
                pass
            self._r2 = None
            self._analyzed = False
            return None
        return result.get("out")

    @staticmethod
    def _is_xref_cmd(cmd: str) -> bool:
        return cmd.startswith("axt") or cmd.startswith("/r ") or cmd == "/r"

    def _run(self, cmd: str, analyze: bool = True) -> str:
        """Run one r2 command (with analysis if needed) and return raw text."""
        if _HAVE_R2PIPE:
            if analyze and self._analysis_timed_out:
                # ya se intento y se agoto el tiempo en esta instancia -- no abrir otro proceso
                # r2 inutil solo para descartarlo, devolver el degradado directamente.
                return (f"[r2 analysis ('{self.analysis_cmd}') timed out after "
                        f"{self.analysis_timeout_s:.0f}s -- binary too large/complex or r2 "
                        f"itself stuck; degrading instead of blocking the pipeline]")
            is_xref = self._is_xref_cmd(cmd)
            if is_xref and self._xref_timed_out:
                return (f"[r2 cross-reference engine (axt//r) already timed out once in this "
                        f"session -- degrading '{cmd}' instantly instead of repeating the hang]")
            r2 = self._pipe()
            if analyze:
                self._ensure_analyzed_pipe()
                if self._analysis_timed_out:
                    return (f"[r2 analysis ('{self.analysis_cmd}') timed out after "
                            f"{self.analysis_timeout_s:.0f}s -- binary too large/complex or r2 "
                            f"itself stuck; degrading instead of blocking the pipeline]")
            out = self._cmd_timed(r2, cmd)
            if out is None:
                if is_xref:
                    self._xref_timed_out = True
                return (f"[r2 command timed out after {self.cmd_timeout_s:.0f}s on this "
                        f"session ('{cmd}') -- degrading instead of blocking the pipeline]")
            return out or ""
        # subprocess fallback
        exe = shutil.which("r2") or shutil.which("radare2")
        script = f"{self.analysis_cmd};{cmd}" if analyze else cmd
        try:
            out = subprocess.run(
                [exe, "-q", "-e", "scr.color=0", "-e", "log.quiet=true", "-2", "-c", script, self.binary],
                capture_output=True, text=True, timeout=90,
            )
            return out.stdout
        except subprocess.TimeoutExpired:
            return "[r2 timed out]"

    def tools(self) -> List[Tool]:
        return [
            Tool("r2_info", "Binary info from radare2 (arch, bits, format, libs).",
                 [], lambda: self._info(), self.name),
            Tool("r2_imports", "Imported/PLT symbols the binary calls.",
                 [], lambda: self._simple("ii", "imports"), self.name),
            Tool("r2_functions", "List of analyzed functions (name, addr, size).",
                 [], lambda: self._simple("afl", "functions"), self.name),
            Tool("r2_strings", "Strings in data sections (izz).",
                 [], lambda: self._strings(), self.name),
            Tool("r2_disasm", "Disassemble a function by name or address, e.g. sym.main or 0x1149.",
                 [ToolParam("target", "function name or address")],
                 lambda target: self._disasm(target), self.name),
            Tool("r2_xrefs", "Cross-references TO a symbol/address (who calls/uses it).",
                 [ToolParam("target", "symbol name or address")],
                 lambda target: self._xrefs(target), self.name),
            Tool("r2_sinks", "Find calls to memory-unsafe / command-exec libc sinks and who reaches them.",
                 [], lambda: self._sinks(), self.name),
            Tool("r2_checksec", "Cross-platform exploit mitigations parsed from radare2 (NX, PIE/PIC, canary). Works on ELF and Mach-O.",
                 [], lambda: self._checksec(), self.name),
            Tool("r2_hardening", "Detect MODERN hardening from symbols/imports: FORTIFY_SOURCE, AddressSanitizer, CFI, SafeStack, stack canary.",
                 [], lambda: self._hardening(), self.name),
            Tool("r2_hardening_bypass_hints", "Turn modern-hardening detection into GROUNDED bypass-strategy hints tied to what THIS binary actually exposes (e.g. which raw/unwrapped calls FORTIFY misses, whether CFI lacks SafeStack so return-address ROP is untouched) -- heuristic/candidate, NOT an auto-bypass.",
                 [], lambda: self._hardening_bypass_hints(), self.name),
            Tool("r2_rop", "Search ROP gadgets (optionally matching a regex like 'pop rdi').",
                 [ToolParam("filter", "optional substring/regex to match, e.g. 'pop rdi'", required=False)],
                 lambda filter=None: self._rop(filter), self.name),
            Tool("r2_win", "Find 'gift' functions (win/shell/backdoor/flag) and /bin/sh style strings useful for ret2win/ret2libc.",
                 [], lambda: self._win(), self.name),
            Tool("r2_stackframe", "Report a function's stack frame: locals, arg vars and frame size (offset-to-return hints).",
                 [ToolParam("target", "function name or address, e.g. sym.main")],
                 lambda target: self._stackframe(target), self.name),
            Tool("r2_vtables", "Detect C++ and virtual tables (vtables, RTTI). Useful for vptr-hijack / type-confusion analysis.",
                 [], lambda: self._vtables(), self.name),
            Tool("r2_heap", "Heap attack surface: allocation/free call sites, double-free and use-after-free candidates (static heuristic).",
                 [], lambda: self._heap(), self.name),
            Tool("r2_indirect", "Indirect control flow: find call/jmp through a register or memory (function pointers, vtable dispatch) and show how the target was stored before it is invoked.",
                 [], lambda: self._indirect(), self.name),
            Tool("r2_cmd", "Escape hatch: run a raw radare2 command (read-only analysis).",
                 [ToolParam("cmd", "raw r2 command, e.g. 'pdf @ sym.main'")],
                 lambda cmd: self._raw(cmd), self.name),
        ]

    def _info(self) -> ToolResult:
        txt = self._run("iI", analyze=False)
        return ToolResult(True, "radare2: iI", txt.strip())

    def _simple(self, cmd: str, label: str) -> ToolResult:
        txt = self._run(cmd)
        return ToolResult(True, f"radare2: {cmd}", txt.strip() or f"(no {label})")

    def _strings(self) -> ToolResult:
        txt = self._run("izz", analyze=False)
        return ToolResult(True, "radare2: izz", txt.strip() or "(no strings)")

    def _disasm(self, target: str) -> ToolResult:
        txt = self._run(f"pdf @ {target}")
        ok = bool(txt.strip()) and "Cannot find" not in txt
        return ToolResult(ok, f"radare2: pdf @ {target}", txt.strip() or f"(no disasm for {target})",
                          error=None if ok else "target not found")

    def _xrefs(self, target: str) -> ToolResult:
        txt = self._run(f"axt @ {target}")
        return ToolResult(True, f"radare2: axt @ {target}", txt.strip() or f"(no xrefs to {target})")

    def _raw(self, cmd: str) -> ToolResult:
        # keep it read-only: block write/seek-modifying commands
        lowered = cmd.strip().lower()
        if lowered and lowered[0] in ("w",) or lowered.startswith(("wx", "wa", "wo")):
            return ToolResult(False, "radare2", "", error="write commands are blocked")
        txt = self._run(cmd)
        return ToolResult(True, f"radare2: {cmd}", txt.strip())

    def _sinks(self) -> ToolResult:
        """List dangerous sinks and who reaches them (grounded reachability seed).

        Dynamic binaries: the sinks are PLT imports (`sym.imp.*`). Statically-linked binaries
        have no imports, so the sinks are compiled-in symbols (`read` -> `sym.__read`); there
        we key off symbols and keep only sinks a USER function calls (`sym.vuln`, not glibc
        internals like `sym._IO_*` / `sym.__*`), which is the real attack surface."""
        imports = self._run("ii")
        # token match (not substring): 'read' must not be found inside 'fgets'/'readdir'/'pread'.
        dyn = [d for d in DANGEROUS if re.search(rf"\b{re.escape(d)}\b", imports)]
        # a binary with no import rows at all is statically linked (or fully static-pie).
        static_binary = not any("0x" in l for l in imports.splitlines())
        vaddr = {}
        for line in imports.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("0x"):
                vaddr[parts[-1]] = parts[1]
        # a real axt caller line carries an address; absence of "0x" means "no xrefs" (robust
        # against caller names that merely start with 'no', e.g. notify_handler / node_read).
        has_callers = lambda t: bool(t) and "0x" in t
        # `_run()`'s own degrade marker for a per-command timeout (see its final branches) --
        # every one it ever returns starts with this literal prefix. Once ANY axt call times
        # out, `_run()` itself latches `self._xref_timed_out` and short-circuits every FUTURE
        # axt/`/r` call on this instance instantly (see `_run`'s docstring) -- so the two
        # escalating fallbacks below and every subsequent sink in this loop degrade immediately
        # instead of each burning another real 60s on a cross-reference engine already known to
        # be stuck for this session (confirmed live against a PE with anti-debug tricks: before
        # this fix, 2 dangerous sinks x up to 3 slow calls each could cost 6 minutes).
        timed_out = lambda t: t.startswith("[r2 ")
        lines, found = [], []
        for fn in dyn:                                   # dynamic (imported) sinks
            xr = self._run(f"axt @ sym.imp.{fn}").strip()
            if not timed_out(xr) and not has_callers(xr):
                va = vaddr.get(fn)
                if va and va != "----------":
                    xr = self._run(f"axt @ {va}").strip()
                    if not timed_out(xr) and not has_callers(xr):
                        xr = self._run(f"/r {va}").strip()
            found.append(fn)
            if timed_out(xr):
                lines.append(f"### sink: {fn}\n(r2's cross-reference engine timed out resolving "
                             "this sink's callers -- degrading instead of blocking the pipeline)")
            else:
                lines.append(f"### sink: {fn}\n{xr}" if has_callers(xr)
                             else f"### sink: {fn}\n(importado; sin llamador resuelto por r2)")
        # static sinks: only for a genuinely static binary. Resolve every DANGEROUS candidate in
        # ONE r2 invocation (a single analysis pass, not one per sink -- the subprocess fallback
        # would otherwise re-run `aa` 10+ times and hang on a glibc binary) and keep the sinks
        # reached from USER code (any caller that is NOT a libc internal `sym._*`).
        # Cheap gate (no analysis): only scan a static binary that actually has a `main` symbol.
        # `is` lists the symbol table without triggering `aa`; \bmain\b matches the real `main`
        # but not `__libc_start_main`. This keeps the scan off malformed/tiny/stripped inputs
        # (a fake or no-main ELF must not reach `pdf @ main`, which would hang r2pipe), and
        # scales: one light `is`, then a single analysis + one combined axt pass.
        if static_binary and re.search(r"\bmain\b", self._run("is", analyze=False)):
            # "user code" = main plus the functions main calls (one level). A static sink is
            # kept only when a caller is in that set, which excludes glibc-internal call sites
            # (glibc has plenty of non-`_`-prefixed functions, so filtering by name alone is
            # not enough).
            main_dis = self._run("pdf @ main")
            user_funcs = {"main"} | set(re.findall(r"call\s+sym\.(\w+)", main_dis))
            if len(user_funcs) > 1:
                cmd = ";".join(f"?e ==={fn}===;axt @ sym.{fn}" for fn in DANGEROUS)
                out = self._run(cmd)
                cur, buckets = None, {}
                for line in out.splitlines():
                    m = re.match(r"===(\w+)===", line.strip())
                    if m:
                        cur = m.group(1); buckets[cur] = []
                    elif cur and "0x" in line:           # only real caller lines
                        buckets[cur].append(line.strip())

                def _caller_name(c):
                    tok = c.split()[0] if c.split() else ""
                    return tok[4:] if tok.startswith("sym.") else tok

                for fn, callers in buckets.items():
                    user = [c for c in callers if _caller_name(c) in user_funcs]
                    if user:
                        found.append(fn)
                        more = (f"  (+{len(callers) - len(user)} llamadas internas de libc)"
                                if len(callers) > len(user) else "")
                        lines.append(f"### sink: {fn} (estatico; alcanzado desde main/user code){more}\n"
                                     + "\n".join(user[:8]))
        if not lines:
            return ToolResult(True, "radare2: ii+axt",
                              "(no classic dangerous sinks imported nor reached from user code)")
        src = "radare2: dangerous sinks (imports + static symbols, axt to user code)"
        return ToolResult(True, src, "\n\n".join(lines), meta={"sinks": found})

    # ---- exploitation-oriented tools ----
    def _checksec(self) -> ToolResult:
        info = self._run("iI", analyze=False)
        def field(name):
            m = re.search(rf"^{name}\s+(\S+)", info, re.MULTILINE)
            return m.group(1) if m else "unknown"
        canary = field("canary")
        nx = field("nx")
        pic = field("pic")
        arch = field("arch")
        bits = field("bits")
        fmt = field("bintype") if "bintype" in info else ""
        relro = "N/A (solo ELF)" if fmt in ("pe", "mach0", "mach064") else "ver elf_mitigations"
        txt = (f"arch:   {arch} {bits}-bit\n"
               f"format: {fmt or '?'}\n"
               f"NX:     {nx}\n"
               f"PIE/PIC:{pic}\n"
               f"Canary: {canary}\n"
               f"RELRO:  {relro}")
        return ToolResult(True, "radare2: iI (checksec)", txt,
                          meta={"canary": canary, "nx": nx, "pic": pic, "arch": arch, "bits": bits, "format": fmt})

    # The actual _chk wrappers FORTIFY_SOURCE can emit, grouped by the raw/unsafe function each
    # one replaces -- used both to DETECT fortify precisely (not a blunt "_chk" substring, which
    # false-positives on __stack_chk_fail/__stack_chk_guard) and to name a SPECIFIC gap (a
    # wrapper that is absent) instead of a vague "FORTIFY detected" claim.
    _FORTIFY_WRAPPERS = {
        "strcpy": "__strcpy_chk", "strcat": "__strcat_chk", "sprintf": "__sprintf_chk",
        "vsprintf": "__vsprintf_chk", "memcpy": "__memcpy_chk", "memmove": "__memmove_chk",
        "memset": "__memset_chk", "gets": "__gets_chk", "read": "__read_chk",
        "fgets": "__fgets_chk", "snprintf": "__snprintf_chk", "vsnprintf": "__vsnprintf_chk",
    }

    _HARDENING_CHECKS = {
        "AddressSanitizer": ["__asan_", "asan_report"],
        "CFI (clang)":      ["__cfi_", "__cfi_check"],
        "SafeStack":        ["__safestack", "safestack_"],
        "Stack canary":     ["__stack_chk_fail", "__stack_chk_guard"],
        "UBSan":            ["__ubsan_"],
    }

    def _detect_hardening(self):
        """Simbolos realmente presentes (imports + simbolos de funcion) -- base compartida para
        la deteccion cruda y para los hints de bypass, que citan los simbolos EXACTOS en vez de
        una afirmacion generica."""
        syms = self._run("is~FUNC") + "\n" + self._run("ii")
        detected = {name: any(mk in syms for mk in markers)
                   for name, markers in self._HARDENING_CHECKS.items()}
        # FORTIFY_SOURCE checked against the KNOWN wrapper names specifically (not a bare "_chk"
        # substring), since that also matches __stack_chk_fail/__stack_chk_guard.
        detected["FORTIFY_SOURCE"] = any(w in syms for w in self._FORTIFY_WRAPPERS.values())
        return syms, detected

    def _hardening(self) -> ToolResult:
        syms, detected = self._detect_hardening()
        lines = [f"{name:18s}: {'DETECTED' if hit else 'not detected'}"
                 for name, hit in detected.items()]
        return ToolResult(True, "radare2: is/ii (modern hardening)", "\n".join(lines),
                          meta={"detected": detected})

    def _hardening_bypass_hints(self) -> ToolResult:
        """Convierte la deteccion cruda en hints de bypass FUNDAMENTADOS (citando lo que
        realmente se observo: que symbolos/funciones de fortify faltan, si hay canary/CFI a la
        vez, etc.) -- siguen siendo heuristica/candidato (no auto-bypass), pero atados a lo que
        este binario concreto expone, no un parrafo generico pegado para cualquier target."""
        syms, detected = self._detect_hardening()
        checksec = self._checksec()
        canary_on = (checksec.meta or {}).get("canary", "").lower() == "true"
        hints = []

        if detected.get("FORTIFY_SOURCE"):
            present = {raw: wrapper for raw, wrapper in self._FORTIFY_WRAPPERS.items() if wrapper in syms}
            missing = [raw for raw, wrapper in self._FORTIFY_WRAPPERS.items()
                      if wrapper not in syms and raw in syms]
            if missing:
                hints.append(
                    "FORTIFY_SOURCE: wrapped=[" + ", ".join(sorted(present)) + "] but the binary "
                    "ALSO calls the raw, UNWRAPPED function(s) [" + ", ".join(sorted(missing)) +
                    "] directly -- those calls get no `_chk` bounds check at all (the compiler "
                    "could not prove a destination size, or the call predates the FORTIFY "
                    "annotation). Target the raw call, not the wrapped ones.")
            else:
                hints.append(
                    "FORTIFY_SOURCE: every risky call seen also has a `_chk` wrapper present -- "
                    "the bounds check only aborts when the DESTINATION size is known at compile "
                    "time AND exceeded; it does nothing for a logically-sized but "
                    "attacker-controlled index/offset bug (e.g. write-what-where via an array "
                    "index) or a heap/UAF primitive. Look there instead of a flat buffer overrun.")

        if detected.get("CFI (clang)"):
            if not detected.get("SafeStack"):
                hints.append(
                    "CFI (clang forward-edge): __cfi_check is present but SafeStack/shadow-stack "
                    "markers are NOT -- clang's CFI instruments indirect call/jump TARGETS, it "
                    "does not protect the return address on the normal stack. A classic ROP "
                    "overwrite of a saved return address is a plausible bypass path entirely "
                    "orthogonal to CFI; only an indirect call/vtable-dispatch hijack needs to "
                    "satisfy CFI's type check (land on a function with a COMPATIBLE "
                    "signature already in its type set -- a type-confusion angle, not a "
                    "flat redirect to an arbitrary gadget).")
            else:
                hints.append(
                    "CFI + SafeStack together: both indirect-call targets and the return address "
                    "are checked/isolated. A bypass needs either a type-confused indirect-call "
                    "target that still satisfies CFI's check, or a way to corrupt data ON THE "
                    "UNSAFE STACK that SafeStack itself relocates pointers from (see the "
                    "SafeStack hint below) -- a flat stack-overwrite is unlikely to reach "
                    "anything that matters here.")

        if detected.get("SafeStack"):
            hints.append(
                "SafeStack: only values whose address is taken / that can't be proven not to "
                "escape (arrays, big locals, anything &'d) live on the UNSAFE stack an overflow "
                "can still reach; return addresses, spilled registers and non-escaping locals "
                "move to a separate, normally-not-overflowable safe stack. The bypass angle is a "
                "local on the UNSAFE side that is itself a pointer (a local function-pointer "
                "array, a local struct with a vtable-like field) -- overflow INTO that, not "
                "toward the return address, which this overflow can no longer reach directly.")

        if detected.get("AddressSanitizer"):
            hints.append(
                "AddressSanitizer: rarely a PRODUCTION mitigation (it is a bug-finding build, "
                "usually absent from release binaries) -- if you are seeing this, double check "
                "this is really the deployed target. Its real effect on exploitation is "
                "layout, not blocking: redzones around every allocation mean heap-overflow "
                "offsets measured against a non-ASan build will be WRONG here; re-derive them "
                "dynamically against this exact binary (heap_dump_state) rather than reusing "
                "assumed tcache/fastbin offsets.")

        if detected.get("UBSan"):
            hints.append(
                "UBSan: traps on behavior the C STANDARD calls undefined (signed overflow, "
                "misaligned access, etc.) -- it does not catch a bug that is undefined-behavior-"
                "free by the standard but still attacker-exploitable, e.g. an out-of-bounds "
                "ARRAY INDEX the program never range-checks itself (plain pointer arithmetic "
                "into memory the C standard doesn't forbid addressing) needs the separate "
                "`-fsanitize=bounds`/`array-bounds` check, which this generic marker does not "
                "distinguish from the default set. A write-what-where via an unchecked index is "
                "a realistic path UBSan's default build leaves untouched.")

        if canary_on and not any("canary" in h.lower() or "leak" in h.lower() for h in hints):
            hints.append(
                "Stack canary: blocks a LINEAR overflow through the canary, but does nothing "
                "once the canary's own value is known -- a format-string/OOB-read leak feeding "
                "the same overflow (see autocanary.py / heap_confirm_* style leak-then-overwrite "
                "chaining) remains a direct, grounded bypass path, not a hint.")

        if not hints:
            return ToolResult(True, "r2_hardening_bypass_hints", "(no modern hardening detected -- nothing to reason about)",
                              meta={"detected": detected, "hints": []})
        body = "\n\n".join(f"- {h}" for h in hints)
        return ToolResult(True, "radare2 symbols + checksec -> grounded bypass hints (heuristic, NOT auto-bypass)",
                          body, meta={"detected": detected, "hints": hints})

    def _rop(self, filt=None) -> ToolResult:
        # /Rl lists rop gadgets one per line; radare needs analysis off is fine.
        out = self._run("/Rl", analyze=False)
        lines = [l for l in out.splitlines() if l.strip()]
        if filt:
            try:
                rx = re.compile(filt, re.IGNORECASE)
                lines = [l for l in lines if rx.search(l)]
            except re.error:
                lines = [l for l in lines if filt.lower() in l.lower()]
        body = "\n".join(lines[:200]) if lines else "(no gadgets matched)"
        return ToolResult(True, f"radare2: /Rl{(' ~'+filt) if filt else ''}", body,
                          meta={"count": len(lines)})

    def _win(self) -> ToolResult:
        funcs = self._run("afl")
        interesting = []
        # delimited token, not a bare substring, so "win" does not match "_Unwind_Resume"/"winner"
        # nor "flag" match unrelated glibc internals in a static binary.
        gift = re.compile(r"(?:^|[^a-z])(win|shell|backdoor|flag|secret|admin|give|vuln)(?:[^a-z]|$)")
        for line in funcs.splitlines():
            if gift.search(line.lower()):
                interesting.append(line.strip())
        strings = self._run("izz", analyze=False)
        sh_lines = [l for l in strings.splitlines()
                    if "/bin/sh" in l or "/bin/bash" in l or "flag" in l.lower() or "cat " in l]
        body = ""
        if interesting:
            body += "## candidate gift functions\n" + "\n".join(dict.fromkeys(interesting)) + "\n\n"
        if sh_lines:
            body += "## interesting strings\n" + "\n".join(sh_lines[:40])
        if not body:
            body = "(no obvious win functions or shell strings)"
        return ToolResult(True, "radare2: afl + izz (gift finder)", body,
                          meta={"win_funcs": len(interesting)})

    def _stackframe(self, target: str) -> ToolResult:
        # afvd/afv dumps frame variables after seeking to the function
        out = self._run(f"s {target}; af; afvd")
        if not out.strip():
            out = self._run(f"pdf @ {target}")
        return ToolResult(bool(out.strip()), f"radare2: afvd @ {target}",
                          out.strip() or f"(no frame info for {target})")

    def _vtables(self) -> ToolResult:
        av = self._run("av")
        syms = self._run("is~_ZT")           # _ZTV vtable, _ZTI typeinfo, _ZTS typestring
        is_cpp = bool(syms.strip()) or "vtable" in av.lower()
        parts = []
        parts.append("C++ detected: " + ("yes" if is_cpp else "no (or no RTTI symbols)"))
        if av.strip():
            parts.append("## radare2 vtable analysis (av)\n" + av.strip())
        if syms.strip():
            parts.append("## RTTI / vtable symbols (_ZT*)\n" + syms.strip()[:1500])
        if not av.strip() and not syms.strip():
            parts.append("(no vtables or RTTI symbols found)")
        return ToolResult(True, "radare2: av + is~_ZT (vtables/C++)", "\n\n".join(parts),
                          meta={"cpp": is_cpp})

    def _heap(self) -> ToolResult:
        # Bug real encontrado probando contra un binario CVE real (no un sample pequeno de CTF):
        # `sudo` 1.8.31 (CVE-2021-3156) importa `reallocarray` pero NO una `realloc` suelta --
        # la comprobacion anterior ("realloc" in imports_text) daba un falso positivo porque
        # "realloc" es substring literal de "reallocarray", asi que pedia axt sobre un simbolo
        # (`sym.imp.realloc`) que no existe. Ahora compara nombres EXACTOS, uno por linea de `ii`.
        allocs = ("malloc", "calloc", "realloc", "reallocarray")
        frees = ("free", "cfree")
        imports = self._run("ii")
        import_names = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*$", imports, re.M))
        present = [a for a in allocs + frees if a in import_names]
        if not present:
            return ToolResult(True, "radare2: heap surface", "(no heap allocator calls imported)",
                              meta={"heap": False})
        # group call sites by caller function
        by_func = {}
        timed_out_allocs = []
        for fn in present:
            xr = self._run(f"axt @ sym.imp.{fn}")
            if xr.startswith("[r2"):
                # Degrade marker from `_run()` (axt timed out, here or earlier this session --
                # see `self._xref_timed_out`), not a real axt listing. Found live: parsing this
                # English sentence as caller lines below produced garbage buckets (its words
                # looked enough like "caller addr" pairs to slip past the blank/"no..." guard).
                timed_out_allocs.append(fn)
                continue
            for line in xr.splitlines():
                line = line.strip()
                if not line or line[:2].lower() == "no":
                    continue
                caller = line.split()[0] if line.split() else "?"
                by_func.setdefault(caller, {"alloc": 0, "free": 0, "lines": []})
                if fn in frees:
                    by_func[caller]["free"] += 1
                else:
                    by_func[caller]["alloc"] += 1
                by_func[caller]["lines"].append(f"{fn}: {line}")
        out = []
        candidates = []
        for func, d in by_func.items():
            flags = []
            if d["free"] >= 2:
                flags.append("DOUBLE-FREE candidate")
            if d["free"] >= 1 and d["alloc"] >= 1:
                flags.append("alloc+free in same func (UAF surface)")
            tag = ("  <-- " + ", ".join(flags)) if flags else ""
            if flags:
                candidates.append(func)
            out.append(f"### {func} (alloc={d['alloc']}, free={d['free']}){tag}\n" +
                       "\n".join("  " + l for l in d["lines"]))
        if timed_out_allocs:
            out.append("### (unresolved)\nr2's cross-reference engine timed out resolving "
                       f"callers for: {', '.join(timed_out_allocs)} -- degrading instead of "
                       "blocking the pipeline.")
        body = "\n\n".join(out) or "(no caller resolved)"
        note = ("\n\nNOTE: these are STATIC heuristics (surface/candidates), not proven UAF/"
                "double-free. Confirm with dbg_run_input or dynamic analysis.")
        return ToolResult(True, "radare2: heap surface (ii + axt)", body + note,
                          meta={"heap": True, "candidates": candidates,
                                "xref_timed_out": bool(timed_out_allocs)})

    def _indirect(self) -> ToolResult:
        """Locate indirect calls/jumps and show the few instructions that set the target,
        so you can see how a pointer is stored (heap/stack/struct/vtable) and then invoked."""
        funcs = self._run("afl")
        names = []
        for line in funcs.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].startswith("0x"):
                names.append(parts[-1])
        import re as _re
        # register/memory indirect targets (not a resolved sym)
        indir = _re.compile(r"\b(call|jmp)\s+(r[a-z0-9]+|\[[^\]]+\])", _re.IGNORECASE)
        blocks = []
        heap_regs = ("malloc", "calloc", "realloc")
        for fn in names[:60]:
            pdf = self._run(f"pdf @ {fn}")
            lines = pdf.splitlines()
            for i, l in enumerate(lines):
                m = indir.search(l)
                if not m:
                    continue
                op = m.group(2)
                # skip PLT-resolved indirect (call qword [sym.imp.x]) which is a normal import call
                if "sym.imp." in l or "reloc." in l:
                    continue
                ctx = lines[max(0, i - 5):i + 1]
                tag = ""
                joined = "\n".join(ctx)
                if any(h in joined for h in heap_regs):
                    tag = "  <-- objetivo proviene de una reserva de heap (posible hijack de puntero/vtable)"
                elif "vtable" in joined.lower() or "0x" in op:
                    tag = "  <-- posible dispatch por vtable / puntero en memoria"
                blocks.append(f"### {fn}: {m.group(1)} {op}{tag}\n" + "\n".join(ctx))
        if not blocks:
            return ToolResult(True, "radare2: indirect control flow",
                              "(no se hallaron call/jmp indirectos; el flujo es directo)")
        body = "\n\n".join(blocks[:40])
        note = ("\n\nCada bloque muestra las instrucciones que CARGAN el objetivo (de donde sale "
                "el puntero: heap/stack/struct) justo antes de la llamada/salto INDIRECTA. Un "
                "puntero de heap invocado indirectamente es el patron de UAF -> control de flujo.")
        return ToolResult(True, "radare2: indirect control flow (pdf scan)", body + note,
                          meta={"indirect": len(blocks)})
