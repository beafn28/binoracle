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

    def _native_tool_schema(self) -> Optional[List[dict]]:
        """OpenAI-style function-calling schema for every available tool, PLUS a synthetic
        `finish` tool the model calls instead of emitting the portable protocol's bare
        `{"action":"final",...}` object -- native tool-calling has no other way to signal
        "I'm done, here's the answer" distinct from "call this tool". `run()` recognizes a
        call to `finish` by name and maps it back to the exact same final-answer path as the
        portable protocol (see the `tool == "finish"` check there), so every downstream
        consumer (grounding gate, finding persistence) is untouched. None (not an empty list)
        when native tool-calling isn't both backend-capable and config-enabled, so the caller
        never pays for building this and the backend never receives an unwanted `tools` kwarg."""
        if not getattr(self.llm, "_supports_native_tools", False):
            return None
        if not getattr(self.config, "native_tools", False):
            return None
        schema = []
        for t in self.registry.available_tools():
            props = {p.name: {"type": "string", "description": p.description} for p in t.params}
            required = [p.name for p in t.params if p.required]
            schema.append({"type": "function", "function": {
                "name": t.name, "description": t.description,
                "parameters": {"type": "object", "properties": props, "required": required},
            }})
        schema.append({"type": "function", "function": {
            "name": "finish",
            "description": "Call this INSTEAD of any other tool once you have enough grounded "
                           "evidence to answer. Ends the investigation.",
            "parameters": {"type": "object", "properties": {
                "answer": {"type": "string", "description": "the final answer, citing tool sources"},
                "findings": {"type": "array", "description": "list of {title,severity,verdict,"
                            "evidence,location,rationale,recommendation} objects, [] if none"},
            }, "required": ["answer"]},
        }})
        return schema

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

    # Inserted once the live conversation is trimmed, so the model knows older evidence
    # wasn't lost -- it's still in the grounding ledger, just no longer repeated to it verbatim.
    _CONTEXT_TRIMMED_NOTE = (
        "[earlier tool results were trimmed from this conversation to stay within the "
        "local model's context window. Every real fact already seen is still recorded in "
        "the grounding ledger and will back the final report -- do not re-request it, "
        "just keep going from here or finalize.]"
    )

    def _enforce_context_budget(self, messages: List[Message]) -> None:
        """A binary with many functions/strings (or a model that keeps circling) can grow
        `messages` past whatever context window the local server was started with -- the
        failure mode observed live is not a clean error: the backend either 400s or drops
        the connection mid-request, killing the whole investigation with zero findings.
        Every tool result that ever lands here was ALREADY written to the GroundingLedger
        in `run()` before this function is called, so it is safe to evict the oldest
        request/response pairs from what we actually SEND the model next: the final
        answer's grounding comes from the ledger, never from what remains in `messages`.
        Keeps `messages[0]` (system) and `messages[1]` (task) always; everything after
        comes in pairs (one assistant action + one user observation/nudge), so eviction
        removes exactly two at a time to never split a pair."""
        budget_chars = getattr(self.config, "max_context_chars", 16000)
        has_note = len(messages) > 2 and messages[2].content == self._CONTEXT_TRIMMED_NOTE
        start = 3 if has_note else 2
        if sum(len(m.content) for m in messages[start:]) <= budget_chars:
            return
        if not has_note:
            messages.insert(2, Message("user", self._CONTEXT_TRIMMED_NOTE))
            start = 3
        # Always leave the most recent 2 exchanges (4 messages) visible so the model still
        # has something concrete to act on immediately after trimming.
        while len(messages) - start > 4 and sum(len(m.content) for m in messages[start:]) > budget_chars:
            del messages[start:start + 2]

    _CONTEXT_OVERFLOW_MARKERS = (
        "context_length_exceeded", "maximum context length", "context window",
        "reduce the length",
    )

    @classmethod
    def _is_context_overflow(cls, exc: Exception) -> bool:
        """True when `exc` (from self.llm.chat) is the backend's own context-window-exceeded
        rejection, not some other failure (dead server, OOM, malformed request). Detected from
        the error text llama.cpp/vLLM/LM Studio actually send back in their 400 body -- real
        examples confirmed live: "This model's maximum context length is 8192 tokens. However,
        you requested 9297 tokens..." """
        return any(m in str(exc).lower() for m in cls._CONTEXT_OVERFLOW_MARKERS)

    def _force_trim_to_minimum(self, messages: List[Message]) -> None:
        """Bug real encontrado en vivo, dos veces, resolviendo el mismo CTF real contra un
        servidor local real de 8192 tokens de contexto: `_enforce_context_budget` arriba solo
        mira `max_context_chars` (en CARACTERES), que para contenido denso en hex/desensamblado
        tokeniza mucho peor que texto normal -- 16000 caracteres de ese contenido superaron los
        8192 tokens reales del servidor DOS veces, en el mismo paso (~18), con exactamente el
        mismo error 400 cada vez. La investigacion entera se abortaba ahi (ver el comentario de
        `except Exception` en run()) en vez de recuperarse y seguir. Este metodo es el recorte
        de emergencia que se usa SOLO tras un rechazo de contexto confirmado: tira todo el
        historial de herramientas salvo el ultimo intercambio (igual que arriba, nunca parte un
        par accion+observacion), para dar a la siguiente llamada el maximo margen posible antes
        de reintentar una vez."""
        has_note = len(messages) > 2 and messages[2].content == self._CONTEXT_TRIMMED_NOTE
        start = 3 if has_note else 2
        if not has_note:
            messages.insert(2, Message("user", self._CONTEXT_TRIMMED_NOTE))
            start = 3
        while len(messages) - start > 2:
            del messages[start:start + 2]

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
        tool_schema = self._native_tool_schema()   # None unless backend+config both opt in

        for step in range(1, budget + 1):
            self._enforce_context_budget(messages)
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
            # `tools=` is only passed when actually in play (native_tools opted in AND the
            # backend supports it) -- never unconditionally, so a backend/test-double whose
            # chat() predates this parameter (no `tools` kwarg at all) keeps working unchanged.
            try:
                reply = self.llm.chat(messages, json_mode=True, **({"tools": tool_schema} if tool_schema else {}))
            except Exception as e:
                # Bug real encontrado en vivo, dos veces, con el MISMO CTF real contra un
                # servidor local de 8192 tokens: `_enforce_context_budget` ya corrio este mismo
                # paso y no vio motivo para recortar (su presupuesto es en caracteres, y
                # contenido denso en hex/desensamblado tokeniza mucho peor de lo que esa cuenta
                # de caracteres asume) -- la investigacion entera se abortaba aqui en el mismo
                # paso (~18) con el mismo 400 "maximum context length... you requested 9297
                # tokens" cada vez, perdiendo la oportunidad de simplemente recortar MAS y
                # seguir. Antes de rendirse, si el error es especificamente un rechazo de
                # contexto (no un servidor caido, OOM, o un 400 por otra causa), se recorta al
                # minimo con _force_trim_to_minimum y se reintenta UNA vez -- igual de barato
                # que la sintesis parcial de abajo, pero intenta seguir investigando primero.
                if self._is_context_overflow(e):
                    self._force_trim_to_minimum(messages)
                    try:
                        reply = self.llm.chat(messages, json_mode=True,
                                              **({"tools": tool_schema} if tool_schema else {}))
                    except Exception as e2:
                        e = e2
                    else:
                        # el reintento funciono: `reply` ya tiene la respuesta buena y el flujo
                        # normal del paso (action = extract_action(reply), justo debajo de este
                        # bloque) sigue como si nunca hubiera fallado.
                        e = None
                if e is not None:
                    # Every OTHER oracle in this codebase degrades on failure instead of
                    # crashing the whole investigation (r2's cmd timeout, angr's hard-killed
                    # subprocess) -- the LLM backend itself was the one exception to that rule,
                    # confirmed live against a real local CPU server: an HTTP 400 (context
                    # window exceeded) and a dropped connection (OOM-killed server process) both
                    # propagated straight past this loop, past cmd_ask/cmd_hunt's own
                    # try/except, out to the CLI's generic handler -- the whole run printed
                    # "error inesperado: ..." and lost every real fact already gathered (steps
                    # 1-6 of real r2/angr evidence, thrown away for a step-7 backend hiccup).
                    # Synthesizing from the ledger we DO have, same as the budget-exhausted path
                    # below, means a backend failure degrades the answer instead of destroying it.
                    synth = self._synthesize(
                        task, ledger,
                        note=f"(the LLM backend failed mid-investigation: {e}; this is a partial "
                             "answer from the evidence gathered before that point, not a complete one)",
                    )
                    return AgentResult(ledger.annotate(synth), [], ledger, step, "backend_failure")
            action = extract_action(reply)

            # Native tool-calling has no bare "I'm done" signal distinct from "call this tool"
            # -- the model calls the synthetic `finish` tool instead (see
            # `_native_tool_schema`). Map it back to the exact same final-answer shape the
            # portable protocol already produces, so every line below this is unchanged.
            if action is not None and action.get("action") == "tool" and action.get("tool") == "finish":
                fargs = action.get("args") or {}
                action = {"action": "final", "answer": fargs.get("answer", ""),
                         "findings": fargs.get("findings", [])}

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
                if forced:
                    # Already told the model to stop and answer (last step, or too many
                    # dup/malformed replies); it tried another tool call instead of
                    # complying. Cut losses NOW -- a model that ignores this once won't
                    # reliably comply later either, and letting it keep going is exactly
                    # how a stuck session burns the rest of its step budget (and context)
                    # for no new evidence, live-observed as HTTP 400s / dropped connections
                    # once the local server's context window fills.
                    synth = self._synthesize(task, ledger)
                    return AgentResult(ledger.annotate(synth), [], ledger, step, "forced_synthesis")
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

    def _synthesize(self, task: str, ledger: GroundingLedger, note: str = "") -> str:
        evidence = ledger.evidence_trail()
        prompt = [
            Message("system",
                    "You are summarizing a completed investigation. Using ONLY the evidence "
                    "trail provided, answer the task in markdown. Cite sources as [src: <source>]. "
                    "Do not invent anything not in the evidence."),
            Message("user", f"TASK:\n{task}\n\n{evidence}\n\nWrite the final answer now."),
        ]
        try:
            out = self.llm.chat(prompt)
            return f"{note}\n\n{out}" if note else out
        except Exception:
            # The backend that just failed is also what this synthesis pass needs -- if it's
            # truly down (not just that one request), there is no model left to summarize
            # with. Fall back to the raw evidence trail itself rather than nothing: every real
            # fact gathered is still in `ledger` and gets appended below by `ledger.annotate`.
            fallback = "(no model response available; see the raw evidence trail below)"
            return f"{note}\n\n{fallback}" if note else fallback

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
