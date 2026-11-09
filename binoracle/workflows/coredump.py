"""Static ELF core-dump reader: signal, per-thread registers and memory mappings.

A Linux core dump is an ET_CORE ELF whose PT_NOTE segment carries the crash state: NT_PRSTATUS
(one per thread: the killing signal and the full integer register set), NT_PRPSINFO (the program
name/args), NT_SIGINFO (signal + fault address) and NT_FILE (the file-backed memory mappings).
This reads all of it statically with pyelftools -- no debugger, nothing executed -- which is the
grounded starting point for turning a crash into an exploit (what faulted, with which registers,
where the overflow landed). Design adapted from REA's recorded-crash reader (morluto/rea, MIT);
re-implemented in Python. For AUTHORIZED / CTF / research crashes."""
from __future__ import annotations

import struct

# x86-64 elf_gregset_t order (user_regs_struct); pr_reg starts at offset 112 in elf_prstatus.
_AMD64_REGS = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
    "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
    "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
]
_PRSTATUS_REG_OFF = 112
_PRSTATUS_CURSIG_OFF = 12          # short pr_cursig
_PRSTATUS_PID_OFF = 32             # pid_t pr_pid

NT_PRSTATUS = 1
NT_PRPSINFO = 3
NT_SIGINFO = 0x53494749
NT_FILE = 0x46494C45

_SIGNALS = {4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 11: "SIGSEGV", 5: "SIGTRAP"}


def _looks_controlled(value: int) -> bool:
    """True if a 64-bit register holds >=4 printable-ASCII bytes (classic overflow tell: 0x4141...)."""
    if not value:
        return False
    b = value.to_bytes(8, "little")
    printable = sum(1 for c in b if 0x20 <= c <= 0x7E)
    return printable >= 4 and any(0x41 <= c <= 0x7A for c in b)


def _iter_raw_notes(data: bytes):
    """Yield (n_type:int, desc:bytes) from raw PT_NOTE segment bytes (ELF note layout, 4-aligned)."""
    pos = 0
    n = len(data)
    while pos + 12 <= n:
        try:
            namesz, descsz, ntype = struct.unpack_from("<III", data, pos)
        except Exception:
            return
        pos += 12
        pos += (namesz + 3) & ~3                      # skip name, 4-aligned
        if pos + descsz > n:
            return
        desc = data[pos:pos + descsz]
        pos += (descsz + 3) & ~3                      # skip desc, 4-aligned
        yield ntype, desc


def _parse_prstatus(desc: bytes) -> dict:
    cursig = struct.unpack_from("<H", desc, _PRSTATUS_CURSIG_OFF)[0] if len(desc) >= 14 else 0
    pid = struct.unpack_from("<i", desc, _PRSTATUS_PID_OFF)[0] if len(desc) >= 36 else 0
    regs = {}
    for idx, name in enumerate(_AMD64_REGS):
        off = _PRSTATUS_REG_OFF + idx * 8
        if off + 8 > len(desc):
            break
        regs[name] = struct.unpack_from("<Q", desc, off)[0]
    return {"pid": pid, "cursig": cursig, "regs": regs}


def _parse_nt_file(desc: bytes) -> list:
    """NT_FILE: count, page_size, count*(start,end,file_ofs), then count NUL-terminated names."""
    out = []
    try:
        count, page = struct.unpack_from("<QQ", desc, 0)
        pos = 16
        rows = []
        for _ in range(count):
            start, end, fileofs = struct.unpack_from("<QQQ", desc, pos)
            pos += 24
            rows.append((start, end, fileofs))
        names = desc[pos:].split(b"\x00")
        for i, (start, end, _ofs) in enumerate(rows):
            name = names[i].decode("utf-8", "replace") if i < len(names) else ""
            out.append({"start": start, "end": end, "path": name})
    except Exception:
        pass
    return out


def _parse_siginfo(desc: bytes) -> dict:
    # struct siginfo: si_signo, si_errno, si_code (3 ints), then union; si_addr for SIGSEGV/SIGBUS
    # is at offset 16 on amd64 (after the 3 ints + 4 pad, inside _sigfault).
    si = {}
    try:
        signo, errno, code = struct.unpack_from("<iii", desc, 0)
        si = {"si_signo": signo, "si_errno": errno, "si_code": code}
        if len(desc) >= 24:
            si["si_addr"] = struct.unpack_from("<Q", desc, 16)[0]
    except Exception:
        pass
    return si


def inspect_core(path: str) -> dict:
    """Parse an ELF core dump. Returns {ok, is_core, signal, threads, mappings, psinfo, fault_addr}."""
    try:
        from elftools.elf.elffile import ELFFile
    except Exception as e:
        return {"ok": False, "is_core": False, "note": f"falta pyelftools: {e}"}
    try:
        f = open(path, "rb")
    except Exception as e:
        return {"ok": False, "is_core": False, "note": f"no se pudo abrir: {e}"}
    with f:
        try:
            elf = ELFFile(f)
        except Exception as e:
            return {"ok": True, "is_core": False, "note": f"no es un ELF: {e}"}
        if elf["e_type"] != "ET_CORE":
            return {"ok": True, "is_core": False,
                    "note": f"no es un core dump (e_type={elf['e_type']})"}
        threads, mappings, psinfo, siginfo = [], [], None, None
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_NOTE":
                continue
            # Parse the raw PT_NOTE bytes ourselves: pyelftools returns n_type as a STRING for
            # known core notes and pre-parses some descriptors into Containers, losing the raw
            # bytes our struct parsers need. The on-disk layout is uniform: namesz|descsz|type|
            # name(4-aligned)|desc(4-aligned).
            try:
                data = seg.data()
            except Exception:
                continue
            for ntype, desc in _iter_raw_notes(data):
                if ntype == NT_PRSTATUS:
                    threads.append(_parse_prstatus(desc))
                elif ntype == NT_FILE and not mappings:
                    mappings = _parse_nt_file(desc)
                elif ntype == NT_PRPSINFO and psinfo is None:
                    # pr_fname is 16 bytes at offset 40, psargs 80 bytes after
                    try:
                        fname = desc[40:56].split(b"\x00")[0].decode("utf-8", "replace")
                        args = desc[56:136].split(b"\x00")[0].decode("utf-8", "replace")
                        psinfo = {"fname": fname, "args": args}
                    except Exception:
                        psinfo = None
                elif ntype == NT_SIGINFO and siginfo is None:
                    siginfo = _parse_siginfo(desc)
        sig = threads[0]["cursig"] if threads else (siginfo or {}).get("si_signo", 0)
        fault = (siginfo or {}).get("si_addr")
        return {"ok": True, "is_core": True, "arch": "x86-64",
                "signal": sig, "signal_name": _SIGNALS.get(sig, f"signal {sig}"),
                "fault_addr": fault, "threads": threads, "mappings": mappings, "psinfo": psinfo}


def render_core(r: dict) -> str:
    out = ["## Inspeccion de core dump (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_core"):
        return "\n".join(out + ["- No es un core dump: " + r.get("note", "")])
    ps = r.get("psinfo") or {}
    if ps:
        out.append(f"- programa: **{ps.get('fname','?')}**  (`{ps.get('args','')}`)")
    out.append(f"- senal: **{r.get('signal_name')}** ({r.get('signal')})")
    if r.get("fault_addr") is not None:
        out.append(f"- direccion de fallo (si_addr): **{hex(r['fault_addr'])}**")
    threads = r.get("threads") or []
    out.append(f"- hilos: {len(threads)}")
    for i, t in enumerate(threads):
        regs = t.get("regs") or {}
        out.append(f"\n### hilo {i} (pid {t.get('pid')}), senal {t.get('cursig')}")
        for row in ("rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi"):
            if row in regs:
                tag = "  <= **parece controlado por la entrada**" if _looks_controlled(regs[row]) else ""
                out.append(f"- {row} = {hex(regs[row])}{tag}")
        ctl = [r for r in ("rip", "rbp", "rsp") if _looks_controlled(regs.get(r, 0))]
        if ctl:
            out.append(f"  - **{', '.join(ctl).upper()} contiene bytes imprimibles de la entrada "
                       "-> desbordamiento controlando esos registros**")
    maps = r.get("mappings") or []
    if maps:
        out.append(f"\n### mapeos de memoria ({len(maps)})")
        for m in maps[:40]:
            out.append(f"- {hex(m['start'])}-{hex(m['end'])}  {m['path']}")
        if len(maps) > 40:
            out.append(f"- ... (+{len(maps) - 40} mas)")
    out.append("\n_Hecho observado por lectura estatica del core; nada se ejecuta._")
    return "\n".join(out)
