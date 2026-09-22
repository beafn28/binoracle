"""Dynamic analysis oracle: run the target under a debugger, feed it input, and observe
real crashes. This turns "I think this overflows" into "it faulted at PC=0x... with these
registers" - an observable, not a claim.

Uses lldb on macOS or gdb on Linux via a batch script. Minimal by design; extend as needed.
Only runs the target you point it at, with the input you provide."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import List

from .base import Oracle, Tool, ToolParam, ToolResult


class DebuggerOracle(Oracle):
    name = "dynamic_dbg"

    def __init__(self, binary: str):
        self.binary = binary
        self.lldb = shutil.which("lldb")
        self.gdb = shutil.which("gdb")

    def available(self) -> bool:
        return bool(self.lldb or self.gdb) and os.path.exists(self.binary)

    def why_unavailable(self) -> str:
        return "no lldb/gdb on PATH (macOS ships lldb; on Linux: apt install gdb)"

    def tools(self) -> List[Tool]:
        return [
            Tool(
                "dbg_run_input",
                "Run the target under a debugger with the given stdin input; report exit/crash and, on crash, the faulting PC and registers.",
                [ToolParam("stdin_text", "text piped to the process stdin (use 'A'*N style yourself)")],
                lambda stdin_text: self._run_input(stdin_text),
                self.name,
            ),
        ]

    def _run_input(self, stdin_text: str) -> ToolResult:
        data = stdin_text.encode("utf-8", "backslashreplace") if isinstance(stdin_text, str) else bytes(stdin_text)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            infile = tf.name
        try:
            if self.gdb:
                return self._run_gdb(infile)
            return self._run_lldb(infile)
        finally:
            try:
                os.unlink(infile)
            except OSError:
                pass

    def _run_gdb(self, infile: str) -> ToolResult:
        script = (
            "set pagination off\n"
            f"run < {infile}\n"
            "info registers\n"
            "bt\n"
            "quit\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as sf:
            sf.write(script)
            spath = sf.name
        try:
            out = subprocess.run(
                [self.gdb, "-q", "-batch", "-x", spath, self.binary],
                capture_output=True, text=True, timeout=30,
            )
            txt = out.stdout + ("\n[stderr]\n" + out.stderr if out.stderr else "")
        except subprocess.TimeoutExpired:
            txt = "[target timed out under gdb]"
        finally:
            os.unlink(spath)
        crashed = any(s in txt for s in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL"))
        return ToolResult(True, "gdb: run < input; info registers; bt", txt.strip(),
                          meta={"crashed": crashed})

    def _run_lldb(self, infile: str) -> ToolResult:
        script = (
            "settings set target.input-path " + infile + "\n"
            "run\n"
            "register read\n"
            "bt\n"
            "quit\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".lldb", delete=False) as sf:
            sf.write(script)
            spath = sf.name
        try:
            out = subprocess.run(
                [self.lldb, "-b", "-s", spath, self.binary],
                capture_output=True, text=True, timeout=30,
            )
            txt = out.stdout + ("\n[stderr]\n" + out.stderr if out.stderr else "")
        except subprocess.TimeoutExpired:
            txt = "[target timed out under lldb]"
        finally:
            os.unlink(spath)
        crashed = any(s in txt for s in ("EXC_BAD_ACCESS", "stop reason", "signal SIG"))
        return ToolResult(True, "lldb: run; register read; bt", txt.strip(),
                          meta={"crashed": crashed})
