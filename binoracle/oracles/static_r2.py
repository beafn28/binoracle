"""Static analysis oracle backed by radare2.

Prefers r2pipe (persistent session, analysis cached). Falls back to invoking the `r2`
binary via subprocess so it works even without the r2pipe python package installed."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
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
        if not self._analyzed:
            self._pipe().cmd(self.analysis_cmd)
            self._analyzed = True

    def _run(self, cmd: str, analyze: bool = True) -> str:
        """Run one r2 command (with analysis if needed) and return raw text."""
        if _HAVE_R2PIPE:
            r2 = self._pipe()
            if analyze:
                self._ensure_analyzed_pipe()
            return r2.cmd(cmd) or ""
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
        """For each dangerous import present, list the callers (grounded reachability seed)."""
        imports = self._run("ii")
        found = [d for d in DANGEROUS if d in imports]
        if not found:
            return ToolResult(True, "radare2: ii+axt", "(no classic dangerous sinks imported)")
        lines = []
        for fn in found:
            xr = self._run(f"axt @ sym.imp.{fn}")
            xr = xr.strip()
            if xr and "no" not in xr[:3].lower():
                lines.append(f"### sink: {fn}\n{xr}")
            else:
                lines.append(f"### sink: {fn}\n(imported; no direct xref resolved by r2)")
        body = "\n\n".join(lines)
        return ToolResult(True, "radare2: dangerous sinks (ii + axt @ sym.imp.*)", body,
                          meta={"sinks": found})

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

    def _hardening(self) -> ToolResult:
        syms = self._run("is~FUNC") + "\n" + self._run("ii")
        checks = {
            "FORTIFY_SOURCE": ["_chk"],                         # __memcpy_chk, __printf_chk...
            "AddressSanitizer": ["__asan_", "asan_report"],
            "CFI (clang)":      ["__cfi_", "__cfi_check"],
            "SafeStack":        ["__safestack", "safestack_"],
            "Stack canary":     ["__stack_chk_fail", "__stack_chk_guard"],
            "UBSan":            ["__ubsan_"],
            "RELRO/bind_now":   ["__libc_start_main"],          # informative only
        }
        lines = []
        for name, markers in checks.items():
            hit = any(mk in syms for mk in markers)
            if name == "RELRO/bind_now":
                continue
            lines.append(f"{name:18s}: {'DETECTED' if hit else 'not detected'}")
        return ToolResult(True, "radare2: is/ii (modern hardening)", "\n".join(lines),
                          meta={})

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
        for kw in ("win", "shell", "backdoor", "flag", "secret", "admin", "give", "vuln"):
            for line in funcs.splitlines():
                if kw in line.lower():
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
        allocs = ("malloc", "calloc", "realloc", "reallocarray")
        frees = ("free", "cfree")
        imports = self._run("ii")
        present = [a for a in allocs + frees if a in imports]
        if not present:
            return ToolResult(True, "radare2: heap surface", "(no heap allocator calls imported)",
                              meta={"heap": False})
        # group call sites by caller function
        by_func = {}
        for fn in present:
            xr = self._run(f"axt @ sym.imp.{fn}")
            for line in xr.splitlines():
                line = line.strip()
                if not line or "no" == line[:2].lower():
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
        body = "\n\n".join(out)
        note = ("\n\nNOTE: these are STATIC heuristics (surface/candidates), not proven UAF/"
                "double-free. Confirm with dbg_run_input or dynamic analysis.")
        return ToolResult(True, "radare2: heap surface (ii + axt)", body + note,
                          meta={"heap": True, "candidates": candidates})

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
