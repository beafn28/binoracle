"""The grounded hypothesis/verification loop.

  user task
     |
     v
  LLM proposes ONE action (JSON)
     |
   tool? --yes--> execute oracle --> observation --> feed back to LLM  (repeat)
     |
   final --> annotate with grounding ledger --> persist findings
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

from ..llm.base import LLMBackend, Message
from ..oracles.base import ToolRegistry
from ..store.session import SessionStore, Finding
from .grounding import GroundingLedger, gate_findings
from .prompts import ASK_SYSTEM, HUNT_SYSTEM, AUDIT_SYSTEM
from .tools import extract_action, execute_action


@dataclass
class AgentResult:
    answer: str
    findings: List[Finding]
    ledger: GroundingLedger
    steps: int
    stopped_reason: str


class AgentLoop:
    def __init__(self, llm: LLMBackend, registry: ToolRegistry, config,
                 store: Optional[SessionStore] = None,
                 on_step: Optional[Callable[[int, dict], None]] = None,
                 kb_hint: Optional[str] = None):
        self.llm = llm
        self.registry = registry
        self.config = config
        self.store = store
        self.on_step = on_step or (lambda i, a: None)
        self.kb_hint = kb_hint            # RAG cheat-sheet context (reference, not proof)

    def _system(self, mode: str) -> str:
        catalog = self.registry.catalog()
        tmpl = AUDIT_SYSTEM if mode == "audit" else (HUNT_SYSTEM if mode == "hunt" else ASK_SYSTEM)
        # templates contain literal JSON braces, so do a token replace, not str.format
        out = tmpl.replace("{catalog}", catalog)
        if self.kb_hint:
            out += ("\n\n# Reference cheat sheets (local knowledge base)\n"
                    "Technique notes retrieved for this binary. Use them to choose and refine "
                    "the exploitation plan. They are REFERENCE, not evidence: never cite them as "
                    "an observation and never let them override a tool result.\n\n" + self.kb_hint)
        return out

    def run(self, task: str, mode: str = "ask") -> AgentResult:
        ledger = GroundingLedger()
        messages: List[Message] = [
            Message("system", self._system(mode)),
            Message("user", task),
        ]
        seen: dict = {}          # signature -> cached observation
        tool_counts: dict = {}   # tool name -> veces llamada (aunque cambien los args)
        dup_total = 0            # total duplicate/wasteful tool calls
        malformed = 0            # replies en fila sin una accion parseable
        forced = False
        budget = self.config.max_steps
        per_tool_cap = 4         # misma tool >N veces = spam (p.ej. cyclic_offset value=0,1,2,...)
        # Herramientas de exploracion que SI aportan info nueva en cada llamada (una funcion
        # distinta, un simbolo distinto): no se limitan, para no truncar un analisis legitimo.
        uncapped = {"r2_disasm", "r2_xrefs", "r2_stackframe", "elf_symbols", "elf_relocations",
                    "ghidra_decompile", "decai_decompile", "r2_cmd"}

        for step in range(1, budget + 1):
            # If we are on the last step, or the model keeps repeating or emitting junk, force
            # a final answer (no quemar el presupuesto haciendo nudge sin fin).
            if not forced and (step == budget or dup_total >= 3 or malformed >= 3):
                messages.append(Message(
                    "user",
                    "STOP investigating. You have enough tool results. Emit action=final NOW "
                    "with your answer and findings, citing the tool sources you already saw. "
                    "Do not call any more tools.",
                ))
                forced = True

            # Ask for JSON-constrained output: the whole protocol is a single JSON object,
            # so this stops small models from wrapping the action in prose (the main cause
            # of 'not valid protocol' nudges). Falls back gracefully if the backend ignores it.
            reply = self.llm.chat(messages, json_mode=True)
            action = extract_action(reply)

            if action is None:
                malformed += 1
                messages.append(Message("assistant", reply))
                messages.append(Message(
                    "user",
                    "That was not a single valid JSON action. Reply with ONE JSON object only, "
                    'like {"action":"tool","tool":"r2_checksec","args":{}}. No text outside it.',
                ))
                self.on_step(step, {"action": "malformed"})
                continue

            malformed = 0            # una accion valida rompe la racha de malformados
            self.on_step(step, action)

            if action.get("action") == "final":
                answer = action.get("answer", "")
                findings = self._parse_findings(action.get("findings", []))
                findings, gate_notes = gate_findings(findings, ledger)
                if gate_notes:
                    answer += "\n\n> [!note] Anti-false-positive gate:\n" + \
                              "\n".join(f"> - {n}" for n in gate_notes)
                if self.store:
                    for f in findings:
                        self.store.add_finding(f)
                return AgentResult(ledger.annotate(answer), findings, ledger, step, "final")

            if action.get("action") == "tool":
                sig = action.get("tool", "?") + "|" + _sig_args(action.get("args", {}))
                if sig in seen:
                    # anti-repetition: do NOT re-run; nudge hard toward progress/finalize.
                    dup_total += 1
                    messages.append(Message("assistant", _compact(action)))
                    messages.append(Message(
                        "user",
                        "You ALREADY ran that exact call; the result is unchanged (see below). "
                        "Do NOT repeat it. Either call a DIFFERENT tool that makes progress, or "
                        f"emit action=final now.\n\nCACHED RESULT:\n{seen[sig]}",
                    ))
                    continue

                # anti-loop por herramienta: la misma tool llamada muchas veces (aunque con args
                # distintos, p.ej. cyclic_offset value=0,1,2,...) no aporta y quema el presupuesto.
                tname = action.get("tool", "?")
                tool_counts[tname] = tool_counts.get(tname, 0) + 1
                if tname not in uncapped and tool_counts[tname] > per_tool_cap:
                    dup_total += 1
                    messages.append(Message("assistant", _compact(action)))
                    messages.append(Message(
                        "user",
                        f"You have called '{tname}' {tool_counts[tname]} times; it will not reveal "
                        "anything new. STOP using it. Call a DIFFERENT tool that advances the audit "
                        "(e.g. try_ret2win / try_rop to build+run an exploit), or emit action=final now.",
                    ))
                    continue

                obs, result = execute_action(self.registry, action, self.config.max_tool_output_chars)
                seen[sig] = obs
                if result is not None and result.ok:
                    ledger.record(step, action.get("tool", "?"), result.source, result.data)
                    if self.store:
                        self.store.add_fact(action.get("tool", "?"), result.source, result.data)
                messages.append(Message("assistant", _compact(action)))
                messages.append(Message("user", f"TOOL RESULT:\n{obs}"))
                continue

            messages.append(Message("assistant", reply))
            messages.append(Message("user", "Unknown action. Use action=tool or action=final."))

        # Budget exhausted without a final: do ONE synthesis pass from the evidence gathered.
        synth = self._synthesize(task, ledger)
        return AgentResult(ledger.annotate(synth), [], ledger, budget, "synthesized")

    def _synthesize(self, task: str, ledger: GroundingLedger) -> str:
        evidence = ledger.evidence_trail()
        prompt = [
            Message("system",
                    "You are summarizing a completed investigation. Using ONLY the evidence "
                    "trail provided, answer the task in markdown. Cite sources as [src: <source>]. "
                    "Do not invent anything not in the evidence."),
            Message("user", f"TASK:\n{task}\n\n{evidence}\n\nWrite the final answer now."),
        ]
        try:
            return self.llm.chat(prompt)
        except Exception:
            return "(investigation ran out of steps; see the evidence trail below)"

    @staticmethod
    def _parse_findings(raw) -> List[Finding]:
        out = []
        for item in raw or []:
            if not isinstance(item, dict):
                continue
            out.append(Finding(
                title=item.get("title", "untitled"),
                severity=item.get("severity", "info"),
                verdict=item.get("verdict", "unverified"),
                evidence=item.get("evidence", ""),
                location=item.get("location", ""),
                rationale=item.get("rationale", ""),
                recommendation=item.get("recommendation", ""),
            ))
        return out


def _sig_args(args: dict) -> str:
    import json
    try:
        return json.dumps(args, sort_keys=True)
    except Exception:
        return str(args)


def _compact(action: dict) -> str:
    import json
    return json.dumps({k: action[k] for k in ("action", "tool", "args") if k in action})
