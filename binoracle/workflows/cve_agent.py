"""Agente de investigacion de exploits guiado por LLM (de la CVE al exploit, iterando).

Este es el "LLM investigando y probando" del problema abierto: dado un id CVE, el agente:
  1. Consulta la CVE (NVD + PoCs de GitHub/Exploit-DB) y decide si es un hueco.
  2. RAZONA con el LLM: clase de vuln, primitiva, que binario haria falta, como se dispara, y una
     estrategia de explotacion. Es HIPOTESIS (grounded como razonamiento, no como hecho probado).
  3. Deriva el esquema y DESARROLLA la plantilla de exploit para la clase.
  4. Si hay un binario, PRUEBA de verdad: corre la auto-explotacion autonoma (offset+cadena+sandbox)
     y el LLM revisa el resultado. Lo VERIFICADO sale del sandbox, no del modelo.
  5. Informe honesto: que se sabe, que hipotetizo el LLM, que se VERIFICO y que queda bloqueado
     (p.ej. hace falta el binario vulnerable concreto o el disparador de red).

Sin LLM disponible, degrada a la via determinista (lookup + desarrollo + auto-explotacion). El agente
nunca afirma un exploit funcional que el sandbox no haya confirmado. Solo objetivos autorizados.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class Investigation:
    cve_id: str
    description: str = ""
    lookup_ok: bool = False
    is_gap: bool = False
    vuln_class: str = ""
    llm_notes: dict = field(default_factory=dict)     # hipotesis del modelo (target, trigger, plan)
    developed_script: str = ""
    poc_kind: str = "pwntools"                        # "pwntools" (memoria) | "http" | "html" (web)
    verified: bool = False
    verified_detail: str = ""
    trigger: str = ""                                 # disparador descubierto por auto-fuzzing
    blockers: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    source_fetch: dict = field(default_factory=dict)  # {ok, kind, resolved_version, local_path}
    source_grounding: dict = field(default_factory=dict)  # {found: {fn: [loc,...]}, not_found: [...]}
    dynamic_verify: dict = field(default_factory=dict)    # {attempted, available, verified, detail}


_RESEARCH_SYS = (
    "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). Analizas "
    "una vulnerabilidad y propones un plan tecnico. Responde SOLO con JSON valido con las claves: "
    "vuln_class (memoria: stack-overflow, heap-overflow, uaf, double-free, format-string, oob-write, "
    "oob-read, integer-overflow, type-confusion; WEB/APP: missing-authorization, idor, auth-bypass, "
    "sqli, xss, ssrf, command-injection, rce, path-traversal, file-upload, deserialization, xxe, "
    "ssti, csrf, open-redirect; u otra), primitive (que concede), target_binary (binario/componente "
    "a obtener, o el plugin/paquete), source_url (si lo sabes: repo git o zip del codigo vulnerable; "
    "para plugins WordPress deja el slug), affected_version (version afectada, p.ej. '5.1.8'), "
    "vulnerable_functions (lista de funciones/metodos citados, p.ej. update_user), trigger (como se "
    "alcanza: stdin/argumento/fichero/peticion HTTP...), http_method (GET/POST si es web), endpoint "
    "(ruta/accion si es web, p.ej. /wp-admin/admin-ajax.php?action=...), parameters (lista de "
    "parametros relevantes), auth_required (true/false/rol minimo), strategy (una frase), steps "
    "(lista de pasos concretos). Se tecnico y breve; deja vacio lo que no sepas."
)


def _llm_research(llm, cve_id: str, description: str) -> Optional[dict]:
    """Pide al LLM un analisis estructurado de la CVE. Devuelve el dict o None si no hay modelo."""
    if llm is None or not getattr(llm, "available", lambda: False)():
        return None
    from ..llm.base import Message
    prompt = (f"CVE: {cve_id}\nDescripcion: {description}\n\n"
              "Analiza la vulnerabilidad y da el plan en JSON con las claves indicadas.")
    try:
        raw = llm.chat([Message("system", _RESEARCH_SYS), Message("user", prompt)], json_mode=True)
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except Exception:
        return None
    return None


def _run_web_investigation(inv: "Investigation", lang: str, step) -> None:
    """Rama WEB/APP de investigate_cve: descarga el codigo real si se puede, fundamenta la hipotesis
    del LLM contra el (grep de las funciones citadas) y desarrolla el PoC HTTP/HTML. Muta `inv` in
    place.

    `inv.verified` solo se pone a True en UN caso concreto, y por una prueba real: la clase es
    missing-authorization/idor, el codigo se descargo como plugin de WordPress, y hay Docker con
    daemon disponible -> wpverify.py levanta un WordPress+MySQL efimero, instala el plugin de
    verdad, inicia sesion como un usuario de bajo privilegio, envia la peticion, y confirma con un
    SEGUNDO login (con la password que la peticion fijo) que la cuenta objetivo quedo tomada. Fuera
    de ese caso (otra clase, sin Docker, sin plugin de WordPress...) nunca se marca verificado aqui:
    hace falta correr el PoC contra el objetivo autorizado real."""
    es = lang == "es"
    from .websource import fetch_source, grep_vulnerable_functions
    from .webexploit import build_http_poc

    notes = inv.llm_notes or {}
    source = (notes.get("source_url") or "").strip()
    version = (notes.get("affected_version") or "").strip()
    fn_names = notes.get("vulnerable_functions") or []
    if isinstance(fn_names, str):
        fn_names = [fn_names]

    if source:
        step(f"intentando obtener el codigo real ({source})..." if es else
             f"attempting to fetch the real source ({source})...")
        fr = fetch_source(source, version=version, on_step=step)
        inv.source_fetch = {"ok": fr.ok, "kind": fr.kind, "source": fr.source,
                            "resolved_version": fr.resolved_version,
                            "local_path": fr.local_path, "note": fr.note}
        if fr.ok:
            step(f"codigo obtenido ({fr.kind}, version {fr.resolved_version or '?'})" if es else
                 f"source fetched ({fr.kind}, version {fr.resolved_version or '?'})")
            if fn_names:
                step("confirmando en el codigo real las funciones citadas por el LLM..." if es else
                     "confirming the LLM-cited functions in the real source...")
                g = grep_vulnerable_functions(fr.local_path, fn_names)
                inv.source_grounding = {
                    "found": {k: [f"{m.file}:{m.line}" for m in v] for k, v in g["found"].items()},
                    "not_found": g["not_found"],
                }
                for name, locs in inv.source_grounding["found"].items():
                    step((f"GROUNDED: '{name}' existe en el codigo real -> {locs[0]}" if es else
                          f"GROUNDED: '{name}' exists in the real source -> {locs[0]}"))
                if inv.source_grounding["not_found"]:
                    nf = ", ".join(inv.source_grounding["not_found"])
                    step((f"no localizadas en el codigo descargado: {nf} (puede ser otra version/"
                          f"nombre, o hipotesis del LLM)" if es else
                          f"not found in the fetched source: {nf} (could be a different version/"
                          f"name, or an LLM hypothesis)"))
            # verificacion DINAMICA: solo para el caso concreto que wpverify.py sabe confirmar de
            # verdad (account-takeover por missing-authorization/idor en un plugin de WordPress).
            if (fr.kind == "wordpress-plugin" and inv.vuln_class in ("missing-authorization", "idor")
                    and notes.get("endpoint")):
                step("intentando verificacion DINAMICA (WordPress+MySQL efimero en Docker)..." if es
                     else "attempting DYNAMIC verification (ephemeral WordPress+MySQL in Docker)...")
                from .wpverify import verify_wordpress_account_takeover
                wr = verify_wordpress_account_takeover(
                    fr.local_path, fr.source, notes.get("endpoint"),
                    notes.get("http_method") or "POST", notes.get("parameters") or [],
                    on_step=step)
                inv.dynamic_verify = {"attempted": True, "available": wr.available,
                                      "ok": wr.ok, "verified": wr.verified, "detail": wr.detail}
                if wr.verified:
                    inv.verified = True
                    inv.verified_detail = wr.detail
                elif not wr.available:
                    inv.blockers.append(("verificacion dinamica no intentada: " + wr.limitations[0]
                                         if wr.limitations else
                                         "verificacion dinamica no disponible (sin Docker)"))
                else:
                    inv.blockers.append((f"verificacion dinamica intentada pero no confirmada: "
                                         f"{wr.detail}" if es else
                                         f"dynamic verification attempted but not confirmed: "
                                         f"{wr.detail}"))
        else:
            step(f"no se pudo obtener el codigo: {fr.note}" if es else
                 f"could not fetch the source: {fr.note}")
            inv.blockers.append((f"no se pudo descargar el codigo ({fr.note})" if es else
                                 f"could not download the source ({fr.note})"))
    else:
        inv.blockers.append(("el LLM no indico un source_url/slug del plugin: sin codigo real que "
                             "confirmar (la clase/hipotesis siguen siendo validas)" if es else
                             "the LLM did not provide a source_url/plugin slug: no real source to "
                             "confirm against (the class/hypothesis are still valid)"))

    step("desarrollando el PoC HTTP a partir de la hipotesis..." if es else
         "developing the HTTP PoC from the hypothesis...")
    poc = build_http_poc(inv.vuln_class, inv.cve_id, notes, lang=lang)
    if poc:
        inv.developed_script = poc
        inv.poc_kind = "html" if inv.vuln_class == "csrf" else "http"
    else:
        inv.blockers.append(("sin plantilla de PoC para esta clase todavia" if es else
                             "no PoC template for this class yet"))

    if not notes.get("endpoint"):
        inv.blockers.append(("falta el endpoint/ruta exacto (ajusta ENDPOINT en el PoC)" if es else
                             "missing the exact endpoint/route (set ENDPOINT in the PoC)"))
    if not inv.verified:
        inv.blockers.append(("para pasar a VERIFICADO: ejecuta el PoC contra TU objetivo autorizado "
                             "(laboratorio propio o engagement con alcance) y confirma el efecto "
                             "observado; binoracle no lanza peticiones contra objetivos por su "
                             "cuenta (salvo el laboratorio efimero de wpverify.py, cuando aplica)"
                             if es else
                             "to reach VERIFIED: run the PoC against YOUR authorized target (your "
                             "own lab or a scoped engagement) and confirm the observed effect; "
                             "binoracle does not fire requests at targets on its own (except "
                             "wpverify.py's ephemeral lab, when applicable)"))


def investigate_cve(cve_id: str, binary: str = "", config=None, llm=None,
                    on_step: Optional[Callable[[str], None]] = None, lang: str = "es",
                    budget_s: float = 300.0, hints: Optional[dict] = None) -> Investigation:
    """Investiga una CVE con el LLM y prueba lo que se pueda. No lanza.

    `hints` deja al analista aportar lo que YA SABE de la CVE (igual que un exploit developer real:
    la hipotesis del LLM es un punto de partida, no la unica fuente) y pisa lo que proponga el LLM en
    esas claves exactas: source_url (slug de WordPress.org o URL git), affected_version, endpoint,
    http_method, parameters (lista), vulnerable_functions (lista). Util cuando ya tienes el aviso
    oficial delante y no quieres depender de que el modelo adivine el slug/endpoint correctos."""
    import os
    from ..config import load_config
    from ..llm import make_backend
    from .cvelookup import fetch_cve
    from .cveplan import classify_cve, classify_binary, plan, plan_for_binary, is_web_class

    step = on_step or (lambda _m: None)
    es = lang == "es"
    config = config or load_config()
    if llm is None:
        try:
            llm = make_backend(config)
        except Exception:
            llm = None
    inv = Investigation(cve_id=cve_id.upper().strip())

    # 1) consulta la CVE
    step(f"consultando {inv.cve_id} (NVD + GitHub + Exploit-DB)..." if es else
         f"looking up {inv.cve_id} (NVD + GitHub + Exploit-DB)...")
    info = fetch_cve(inv.cve_id)
    inv.description = info.description
    inv.lookup_ok = info.ok
    inv.is_gap = info.is_gap
    if info.ok:
        step((f"{inv.cve_id}: {'HUECO (sin exploit publico)' if info.is_gap else 'ya tiene exploit publico'}"
              if es else
              f"{inv.cve_id}: {'GAP (no public exploit)' if info.is_gap else 'has public exploit'}"))
    else:
        step(f"{inv.cve_id}: {info.note}")

    # 2) el LLM investiga (hipotesis)
    llm_on = bool(llm and getattr(llm, "available", lambda: False)())
    if llm_on and inv.description:
        step("el LLM analiza la vulnerabilidad y propone un plan..." if es else
             "the LLM analyzes the vulnerability and proposes a plan...")
        notes = _llm_research(llm, inv.cve_id, inv.description)
        if notes:
            inv.llm_notes = notes
            step((f"hipotesis del LLM: clase={notes.get('vuln_class','?')}, "
                  f"disparador={notes.get('trigger','?')}" if es else
                  f"LLM hypothesis: class={notes.get('vuln_class','?')}, "
                  f"trigger={notes.get('trigger','?')}"))
    elif not llm_on:
        step("sin modelo LLM disponible: via determinista (arranca ollama para el modo agente)" if es else
             "no LLM available: deterministic path (start ollama for agent mode)")

    # 2b) hechos conocidos del analista: PISAN la hipotesis del LLM en esas claves (el analista
    # que tiene el aviso oficial delante sabe el slug/endpoint reales mejor que una adivinanza).
    if hints:
        given = {k: v for k, v in hints.items() if v}
        if given:
            inv.llm_notes = {**inv.llm_notes, **given}
            step(("hechos del analista aplicados: " if es else "analyst-supplied facts applied: ")
                 + ", ".join(f"{k}={v}" for k, v in given.items()))

    # 3) clasifica + desarrolla la plantilla (grounded, deterministico)
    inv.vuln_class = (classify_cve(inv.description) or
                      classify_cve(inv.llm_notes.get("vuln_class", "")) or "")
    has_bin = bool(binary and os.path.exists(binary))

    if is_web_class(inv.vuln_class):
        # Clase WEB/APP (missing-authorization, IDOR, SQLi, RCE...): no hay binario que explotar con
        # pwntools, el "exploit" es una peticion HTTP. En vez de forzar el camino de memoria, esto:
        #   1) intenta DESCARGAR el codigo real (plugin de WordPress.org o repo git) y confirmar por
        #      grep que las funciones citadas por el LLM existen de verdad (evidencia GROUNDED),
        #   2) desarrolla el PoC HTTP (o la pagina para CSRF) a partir de la hipotesis del LLM.
        # Nunca se marca 'verificado' aqui: eso exige lanzar el PoC contra un objetivo autorizado real.
        _run_web_investigation(inv, lang=lang, step=step)
        inv.steps = []
        return inv

    if has_bin:
        # 4a) AUTO-FUZZING: descubre dinamicamente el disparador (stdin/argv/format-string)
        try:
            from .autofuzz import autofuzz, directed_fuzz
            step("auto-fuzzing: buscando el input que dispara el fallo..." if es else
                 "auto-fuzzing: searching for the crashing input...")
            fz = autofuzz(binary, on_step=lambda m: step(m), lang=lang)
            if fz.ok and fz.triggers:
                t = fz.triggers[0]
                inv.trigger = (f"{t.vector} -> {t.vuln_class}"
                               + (f" (~{t.min_size} bytes)" if t.min_size else ""))
            # si el fuzzing generico no crashea y el LLM tiene una hipotesis del disparador, prueba
            # invocaciones DIRIGIDAS por el LLM (flags/patrones especificos del trigger).
            elif llm_on and inv.llm_notes.get("trigger"):
                step("fuzzing DIRIGIDO por el LLM (segun la hipotesis del disparador)..." if es else
                     "LLM-DIRECTED fuzzing (from the trigger hypothesis)...")
                dz = directed_fuzz(binary, inv.llm_notes.get("trigger", ""), llm,
                                   on_step=lambda m: step(m), lang=lang)
                if dz.ok and dz.triggers:
                    t = dz.triggers[0]
                    inv.trigger = f"{t.vector} (dirigido por LLM) -> {t.vuln_class}"
                elif dz.note:
                    inv.blockers.append(("fuzzing dirigido: " + dz.note) if es else
                                        ("directed fuzzing: " + dz.note))
        except Exception:
            pass
        # 4b) PRUEBA de verdad: concreta offset/gadgets y VERIFICA en sandbox
        step(f"binario dado: intentando explotar y verificar en sandbox (presupuesto {budget_s:.0f}s)..."
             if es else
             f"binary provided: attempting exploit + sandbox verification (budget {budget_s:.0f}s)...")
        from .exploit_trainer import plan_with_budget
        hint = classify_binary(binary) or inv.vuln_class or ""
        pl, err = plan_with_budget(binary, hint, lang, True, budget_s)
        if pl is None:
            inv.blockers.append(("verificacion agoto el presupuesto" if err == "timeout" else f"error: {err}")
                                if es else ("verification exceeded budget" if err == "timeout" else f"error: {err}"))
        else:
            inv.vuln_class = pl.vuln_class or inv.vuln_class
            inv.developed_script = pl.script
            inv.verified = bool(pl.verified)
            if pl.verified:
                pr = pl.proof or {}
                inv.verified_detail = "  ".join(f"{k}={v}" for k, v in pr.items() if k != "output" and v)
                step("EXPLOIT VERIFICADO en sandbox: objetivo alcanzado." if es else
                     "EXPLOIT VERIFIED in sandbox: goal reached.")
            else:
                step("no se pudo verificar una cadena ejecutable; queda la plantilla desarrollada." if es else
                     "could not verify an executable chain; developed template remains.")
    else:
        # sin binario: desarrolla la plantilla y deja claros los bloqueos reales
        pl = plan(inv.description or inv.cve_id, {}, cve=inv.cve_id, lang=lang)
        inv.developed_script = pl.script
        tgt = inv.llm_notes.get("target_binary") or ("el binario vulnerable concreto" if es else
                                                     "the specific vulnerable binary")
        trg = inv.llm_notes.get("trigger") or ("el disparador de la vulnerabilidad" if es else
                                               "the vulnerability trigger")
        inv.blockers.append((f"falta {tgt} (obtenlo de un paquete/imagen Docker de esa version)" if es else
                             f"missing {tgt} (obtain it from a package/Docker image of that version)"))
        inv.blockers.append((f"falta reproducir {trg} (harness/fuzzing o la peticion concreta)" if es else
                             f"missing a way to reproduce {trg} (harness/fuzzing or the exact request)"))
        step("sin binario: esquema + plantilla desarrollados; bloqueos reales anotados." if es else
             "no binary: schema + template developed; real blockers noted.")

    inv.steps = []   # el streaming ya emitio los pasos; el informe los reconstruye del render
    return inv


def render_investigation(inv: Investigation, lang: str = "es") -> str:
    es = lang == "es"
    out = ["## " + ("Investigacion de explotacion" if es else "Exploitation investigation")
           + f": {inv.cve_id}"]
    if inv.description:
        out.append("\n" + inv.description.strip())
    if inv.lookup_ok:
        pub = ("HUECO (no consta)" if es else "GAP (none)") if inv.is_gap else ("existe" if es else "exists")
    else:
        pub = "no consultado (no es un id CVE)" if es else "not checked (not a CVE id)"
    out.append("\n- " + ("Estado exploit publico: " if es else "Public exploit: ") + pub)
    out.append("- " + ("Clase: " if es else "Class: ") + (inv.vuln_class or "?"))
    if inv.llm_notes:
        out.append("\n### " + ("Investigacion del LLM (hipotesis)" if es else "LLM research (hypothesis)"))
        for k in ("primitive", "target_binary", "trigger", "strategy", "source_url",
                  "affected_version", "vulnerable_functions", "http_method", "endpoint",
                  "parameters", "auth_required"):
            v = inv.llm_notes.get(k)
            if v:
                v = ", ".join(v) if isinstance(v, list) else v
                out.append(f"- **{k}**: {v}")
        steps = inv.llm_notes.get("steps")
        if isinstance(steps, list) and steps:
            out.append("- " + ("pasos" if es else "steps") + ":")
            for i, s in enumerate(steps, 1):
                if isinstance(s, dict):        # algunos modelos devuelven {"step": "..."}
                    s = s.get("step") or s.get("action") or next(iter(s.values()), str(s))
                out.append(f"  {i}. {s}")
    if inv.trigger:
        out.append("- " + ("Disparador descubierto (auto-fuzzing): " if es else
                           "Trigger discovered (auto-fuzzing): ") + f"`{inv.trigger}`")
    if inv.source_fetch:
        sf = inv.source_fetch
        out.append("\n### " + ("Codigo fuente" if es else "Source code"))
        if sf.get("ok"):
            out.append("- " + (f"obtenido ({sf.get('kind')}, version {sf.get('resolved_version') or '?'}): "
                               f"`{sf.get('local_path')}`" if es else
                               f"fetched ({sf.get('kind')}, version {sf.get('resolved_version') or '?'}): "
                               f"`{sf.get('local_path')}`"))
            g = inv.source_grounding or {}
            for name, locs in (g.get("found") or {}).items():
                out.append(f"  - **GROUNDED** `{name}` -> " + ", ".join(locs[:5])
                           + (f"  (+{len(locs)-5})" if len(locs) > 5 else ""))
            if g.get("not_found"):
                out.append("  - " + ("no localizadas: " if es else "not found: ")
                           + ", ".join(g["not_found"]))
        else:
            out.append("- " + (f"no obtenido: {sf.get('note')}" if es else
                               f"not fetched: {sf.get('note')}"))
    if inv.verified:
        out.append("\n> **" + ("EXPLOIT VERIFICADO" if es else "VERIFIED EXPLOIT")
                   + "** (sandbox): " + inv.verified_detail)
    if inv.blockers:
        out.append("\n### " + ("Bloqueos para el exploit real" if es else "Blockers for a real exploit"))
        out += [f"- {b}" for b in inv.blockers]
    if inv.developed_script:
        if inv.poc_kind == "http":
            title = "PoC desarrollado (HTTP / requests)" if es else "Developed PoC (HTTP / requests)"
            fence = "python"
        elif inv.poc_kind == "html":
            title = "PoC desarrollado (CSRF, pagina HTML)" if es else "Developed PoC (CSRF, HTML page)"
            fence = "html"
        else:
            title = "Exploit desarrollado (pwntools)" if es else "Developed exploit (pwntools)"
            fence = "python"
        out.append(f"\n### {title}\n```{fence}\n" + inv.developed_script + "\n```")
    out.append("\n_" + ("El LLM propone e investiga; el sandbox decide lo VERIFICADO. Solo objetivos "
                        "autorizados / CTF / research." if es else
                        "The LLM proposes and investigates; the sandbox decides what is VERIFIED. "
                        "Authorized / CTF / research only.") + "_")
    return "\n".join(out)
