"""Vulnerability hunt workflow.

If a local LLM is up, run the grounded agent loop in 'hunt' mode. If not, fall back to a
deterministic heuristic pass that still produces grounded candidates from the sink oracle,
so the tool is useful even with no model loaded."""
from __future__ import annotations

from typing import List

from ..agent.loop import AgentLoop, AgentResult
from ..oracles.base import ToolRegistry
from ..store.session import Finding


HUNT_TASK = (
    "Audit this binary for memory-safety and command-injection vulnerabilities. "
    "Start from mitigations (elf_mitigations) and sinks (r2_sinks). For each candidate "
    "sink, disassemble the caller (r2_disasm), check who reaches it (r2_xrefs), and, if "
    "angr is available, test reachability. Report only evidence-backed findings."
)


def run_hunt(registry: ToolRegistry, binary: str, llm=None, config=None,
             store=None, on_step=None, lang: str = "es", kb_hint: str = "") -> AgentResult:
    if llm is not None and llm.available():
        loop = AgentLoop(llm, registry, config, store=store, on_step=on_step, kb_hint=kb_hint or None)
        return loop.run(HUNT_TASK, mode="hunt")
    return _heuristic_hunt(registry, store, lang=lang)


def _heuristic_hunt(registry: ToolRegistry, store=None, lang: str = "es") -> AgentResult:
    T = _STR.get(lang, _STR["es"])
    from ..agent.grounding import GroundingLedger
    ledger = GroundingLedger()
    findings: List[Finding] = []

    sinks_tool = registry.get("r2_sinks")
    mit_tool = registry.get("elf_mitigations")
    mitig_txt = ""
    if mit_tool:
        mres = mit_tool.run()
        if mres.ok:
            mitig_txt = mres.data
            ledger.record(0, "elf_mitigations", mres.source, mres.data)

    # Si existe una funcion gift (win/backdoor) que ya da shell, los sinks de ejecucion
    # (system/execve) son el gadget/objetivo del exploit, no una vulnerabilidad a reportar.
    has_gift = False
    win_tool = registry.get("r2_win")
    if win_tool:
        wres = win_tool.run()
        if wres.ok and (wres.meta.get("win_funcs", 0) > 0 or "/bin/sh" in (wres.data or "")):
            has_gift = True
            ledger.record(2, "r2_win", wres.source, wres.data)

    if sinks_tool:
        sres = sinks_tool.run()
        if sres.ok:
            ledger.record(1, "r2_sinks", sres.source, sres.data)
            for sink in sres.meta.get("sinks", []):
                sl = _slice_for(sres.data, sink)
                sev, kind = _classify_sink(sink, mitig_txt, sl, has_gift)
                if kind is None:
                    continue           # no aporta como hallazgo (ruido), se omite
                tk = T[kind]
                # version bilingue: el texto del hallazgo tambien en el otro idioma (para el toggle).
                other = "en" if lang == "es" else "es"
                To = _STR[other]; tko = To[kind]
                f = Finding(
                    title=tk["title"].format(sink=sink),
                    severity=sev,
                    verdict="grounded",  # static evidence, reachability not proven
                    evidence=f"[{sres.source}]\n{sl}",
                    location=T["loc"].format(sink=sink),
                    rationale=tk["rationale"].format(sink=sink, mit=mitig_txt or T["unknown"],
                                                     desc=_SINK_DESC.get(lang, {}).get(sink, "")),
                    recommendation=tk["reco"],
                    rationale_en=tko["rationale"].format(sink=sink, mit=mitig_txt or To["unknown"],
                                                         desc=_SINK_DESC.get(other, {}).get(sink, "")),
                    recommendation_en=tko["reco"],
                )
                if store:
                    store.add_finding(f)
                findings.append(f)

    answer = T["answer"]
    return AgentResult(ledger.annotate(answer), findings, ledger, 1, "heuristic")


# Sinks que SON superficie de corrupcion de memoria (el bug de verdad esta aqui).
_OVERFLOW_SINKS = {"gets", "scanf", "sscanf", "fscanf", "strcpy", "strncpy", "strcat", "strncat",
                   "sprintf", "vsprintf", "read", "fread", "recv", "memcpy", "memmove"}
# Sinks de EJECUCION: en un reto suelen ser el OBJETIVO/gadget (system("/bin/sh")), no el bug.
_EXEC_SINKS = {"system", "execve", "execl", "execlp", "execvp", "popen"}
# Sinks de FORMATO: solo son bug si el formato lo controla el usuario.
_FMT_SINKS = {"printf", "fprintf", "snprintf", "vprintf", "vfprintf", "syslog"}


def _classify_sink(sink: str, mitig: str, sl: str, has_gift: bool = False):
    """Devuelve (severidad, kind) o (None, None) si no merece ser un hallazgo (ruido).

    Evita el falso positivo clasico de 'usa X -> FINDING': un sink de ejecucion con argumento
    constante (p.ej. system("/bin/sh")) o cuando existe una funcion gift es un gadget/objetivo,
    NO una vulnerabilidad; se degrada a informativo. La superficie real de bug son los overflow."""
    no_canary = "canary: false" in mitig.lower() or "canary:false" in mitig.lower()
    if sink in _OVERFLOW_SINKS:
        if sink == "gets":
            return "high", "overflow"            # desbordamiento inevitable
        return ("high" if no_canary else "medium"), "overflow"
    if sink in _EXEC_SINKS:
        const_arg = has_gift or any(x in sl.lower() for x in
                                    ("/bin/sh", "bin_sh", "/bin/", "str.", "sh\";", "cat flag",
                                     "\"sh\"", "'sh'"))
        # arg constante o hay gift -> gadget/objetivo, no bug: informativo. Si no, posible RCE.
        return ("info", "exec_const") if const_arg else ("medium", "exec_var")
    if sink in _FMT_SINKS:
        return "low", "fmt"                       # solo bug si el formato es controlable
    return "low", "other"


def _slice_for(text: str, sink: str) -> str:
    marker = f"### sink: {sink}"
    idx = text.find(marker)
    if idx == -1:
        return text[:800]
    end = text.find("### sink:", idx + 1)
    return text[idx:end if end != -1 else idx + 800]


_RECO_ES = ("Rastrea la entrada controlada por el atacante hasta esta llamada; verifica la "
            "reachability con angr_reachable o un PoC con dbg_run_input antes de tratarlo como "
            "explotable.")
_RECO_EN = ("Trace attacker-controlled input into this call; verify reachability with "
            "angr_reachable or a dbg_run_input PoC before treating it as exploitable.")

_STR = {
    "es": {
        "loc": "llamadas a sym.imp.{sink}",
        "unknown": "(desconocidas)",
        "answer": ("Analisis heuristico (sin modelo): los candidatos de abajo estan respaldados "
                   "estaticamente (grounded) pero su reachability NO esta probada. Levanta un "
                   "modelo local o ejecuta angr/debugger para promoverlos a verified. [src: r2_sinks]"),
        "overflow": {
            "title": "Posible desbordamiento via '{sink}'",
            "rationale": ("'{sink}' escribe en un buffer sin garantizar el tamano: superficie de "
                          "desbordamiento de memoria. {desc}\n\nMitigaciones observadas:\n{mit}"),
            "reco": _RECO_ES},
        "exec_const": {
            "title": "Sink de ejecucion '{sink}' con argumento constante",
            "rationale": ("'{sink}' se llama con un argumento CONSTANTE (p.ej. \"/bin/sh\"): es un "
                          "gadget/objetivo de explotacion (ret2*), NO una vulnerabilidad por si "
                          "mismo. {desc}\n\nMitigaciones observadas:\n{mit}"),
            "reco": "Util como destino de un exploit (ret2win/ret2system); no es un bug a reportar."},
        "exec_var": {
            "title": "Posible command injection via '{sink}'",
            "rationale": ("'{sink}' ejecuta con un argumento que NO parece constante: si incluye "
                          "entrada del usuario, es command injection / RCE. {desc}\n\n"
                          "Mitigaciones observadas:\n{mit}"),
            "reco": _RECO_ES},
        "fmt": {
            "title": "Posible format string en '{sink}'",
            "rationale": ("'{sink}' es un format string SOLO si el formato lo controla el usuario "
                          "(fuga con %p, escritura con %n). {desc}\n\nMitigaciones observadas:\n{mit}"),
            "reco": _RECO_ES},
        "other": {
            "title": "Sink presente '{sink}'",
            "rationale": ("'{sink}' presente en el binario. {desc}\n\nMitigaciones observadas:\n{mit}"),
            "reco": _RECO_ES},
    },
    "en": {
        "loc": "callers of sym.imp.{sink}",
        "unknown": "(unknown)",
        "answer": ("Heuristic (no-LLM) hunt: candidates below are statically grounded but NOT "
                   "proven reachable. Bring up a local model or run angr/debugger to promote "
                   "them to verified. [src: r2_sinks]"),
        "overflow": {
            "title": "Possible overflow via '{sink}'",
            "rationale": ("'{sink}' writes to a buffer without a guaranteed size: memory-overflow "
                          "surface. {desc}\n\nMitigations observed:\n{mit}"),
            "reco": _RECO_EN},
        "exec_const": {
            "title": "Execution sink '{sink}' with a constant argument",
            "rationale": ("'{sink}' is called with a CONSTANT argument (e.g. \"/bin/sh\"): it is an "
                          "exploitation gadget/target (ret2*), NOT a vulnerability by itself. "
                          "{desc}\n\nMitigations observed:\n{mit}"),
            "reco": "Useful as an exploit target (ret2win/ret2system); not a bug to report."},
        "exec_var": {
            "title": "Possible command injection via '{sink}'",
            "rationale": ("'{sink}' executes with a non-constant argument: if it includes user "
                          "input it is command injection / RCE. {desc}\n\nMitigations observed:\n{mit}"),
            "reco": _RECO_EN},
        "fmt": {
            "title": "Possible format string in '{sink}'",
            "rationale": ("'{sink}' is a format string ONLY if the format is user-controlled "
                          "(leak with %p, write with %n). {desc}\n\nMitigations observed:\n{mit}"),
            "reco": _RECO_EN},
        "other": {
            "title": "Sink present '{sink}'",
            "rationale": "'{sink}' present in the binary. {desc}\n\nMitigations observed:\n{mit}",
            "reco": _RECO_EN},
    },
}

_SINK_DESC = {
    "es": {
        "system": "Ejecuta comandos del sistema; si el argumento incluye entrada del usuario, es command injection / RCE.",
        "gets": "Lee de stdin sin limite de tamano: desbordamiento de buffer clasico e inevitable.",
        "strcpy": "Copia hasta el NUL sin comprobar el tamano del destino: desbordamiento si la fuente es mayor.",
        "strcat": "Concatena sin comprobar el espacio restante: desbordamiento.",
        "sprintf": "Formatea sin limite en el destino: desbordamiento.",
        "printf": "Si el formato es controlado por el usuario, es un format string (fuga con %p, escritura con %n).",
        "memcpy": "Copia un tamano posiblemente controlado por el atacante: desbordamiento si no se valida.",
        "read": "Lee en un buffer; si el tamano supera al buffer, desbordamiento.",
        "scanf": "Sin especificador de ancho puede desbordar el buffer destino.",
        "popen": "Abre un proceso via shell: command injection si el comando incluye entrada del usuario.",
        "execve": "Ejecuta un programa; peligroso si ruta/argumentos son controlables.",
    },
    "en": {},
}
