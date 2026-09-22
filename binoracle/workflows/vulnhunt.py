"""Vulnerability hunt workflow.

If a local LLM is up, run the grounded agent loop in 'hunt' mode. If not, fall back to a
deterministic heuristic pass that still produces grounded candidates from the sink oracle,
so the tool is useful even with no model loaded."""
from __future__ import annotations

from typing import List, Optional

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
             store=None, on_step=None, lang: str = "es") -> AgentResult:
    if llm is not None and llm.available():
        loop = AgentLoop(llm, registry, config, store=store, on_step=on_step)
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

    if sinks_tool:
        sres = sinks_tool.run()
        if sres.ok:
            ledger.record(1, "r2_sinks", sres.source, sres.data)
            for sink in sres.meta.get("sinks", []):
                sev = _severity_for(sink, mitig_txt)
                f = Finding(
                    title=T["title"].format(sink=sink),
                    severity=sev,
                    verdict="grounded",  # static evidence, reachability not proven
                    evidence=f"[{sres.source}]\n{_slice_for(sres.data, sink)}",
                    location=T["loc"].format(sink=sink),
                    rationale=T["rationale"].format(sink=sink, mit=mitig_txt or T["unknown"],
                                                    desc=_SINK_DESC.get(lang, {}).get(sink, "")),
                    recommendation=T["reco"],
                )
                if store:
                    store.add_finding(f)
                findings.append(f)

    answer = T["answer"]
    return AgentResult(ledger.annotate(answer), findings, ledger, 1, "heuristic")


def _severity_for(sink: str, mitig: str) -> str:
    high = {"system", "execve", "gets", "strcpy", "sprintf", "popen"}
    if sink in high:
        # no canary makes classic overflows worse
        if "canary: false" in mitig.lower() or "canary:false" in mitig.lower():
            return "high"
        return "medium"
    return "low"


def _slice_for(text: str, sink: str) -> str:
    marker = f"### sink: {sink}"
    idx = text.find(marker)
    if idx == -1:
        return text[:800]
    end = text.find("### sink:", idx + 1)
    return text[idx:end if end != -1 else idx + 800]


_STR = {
    "es": {
        "title": "Uso de funcion peligrosa '{sink}'",
        "loc": "llamadas a sym.imp.{sink}",
        "rationale": ("'{sink}' es un sink peligroso presente en el binario. {desc}\n\n"
                      "Mitigaciones observadas:\n{mit}"),
        "reco": ("Rastrea la entrada controlada por el atacante hasta esta llamada; verifica "
                 "la reachability con angr_reachable o un PoC con dbg_run_input antes de "
                 "tratarlo como explotable."),
        "answer": ("Analisis heuristico (sin modelo): los candidatos de abajo estan respaldados "
                   "estaticamente (grounded) pero su reachability NO esta probada. Levanta un "
                   "modelo local o ejecuta angr/debugger para promoverlos a verified. [src: r2_sinks]"),
        "unknown": "(desconocidas)",
    },
    "en": {
        "title": "Use of dangerous function '{sink}'",
        "loc": "callers of sym.imp.{sink}",
        "rationale": ("'{sink}' is a memory-unsafe/command-exec sink in the binary. {desc}\n\n"
                      "Mitigations observed:\n{mit}"),
        "reco": ("Trace attacker-controlled input into this call; verify reachability with "
                 "angr_reachable or a dbg_run_input PoC before treating it as exploitable."),
        "answer": ("Heuristic (no-LLM) hunt: candidates below are statically grounded but NOT "
                   "proven reachable. Bring up a local model or run angr/debugger to promote "
                   "them to verified. [src: r2_sinks]"),
        "unknown": "(unknown)",
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
