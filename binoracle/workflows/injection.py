"""OWASP DA1 - Inyeccion (mas alla del command injection de backdoors).

Cubre:
- Inyeccion SQL: el binario usa una API SQL (sqlite3_exec/mysql_query/PQexec/...) o embebe consultas
  SQL, Y construye cadenas dinamicamente (sprintf/strcat/snprintf) -> consultas armadas por
  concatenacion en vez de parametrizadas -> SQLi si parte viene de la entrada.
- Entrada NO confiable que llega a un sink de ejecucion: fuentes controlables (getenv/argv via
  __libc_start_main, read/recv/fgets/scanf) + system/popen/exec -> superficie de inyeccion de
  comando. Complementa backdoors (concatenacion) y fileperms (getenv->exec).

Grounded en imports (r2 ii) + strings (r2 izz). No duplica backdoors; aqui va SQL y la vision de
'entrada -> sink' consolidada.
"""
from __future__ import annotations

import re
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding
from ._binfacts import imported_names, shared_caller_fns, dataflow_confirmed

_SQL_API = ("sqlite3_exec", "sqlite3_prepare", "mysql_query", "mysql_real_query", "mysql_stmt_prepare",
            "pqexec", "pqexecparams", "mysql_real_escape_string", "sqlite3_mprintf")
_SQL_TEXT = re.compile(r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b.{0,80}\b(FROM|INTO|SET|WHERE|VALUES)\b",
                       re.I | re.S)
_SQL_FMT = re.compile(r"(SELECT|INSERT|UPDATE|DELETE)\b[^\"']*(?:'%s'|%s|%d|\"\s*\+|\|\|)", re.I)
_BUILDERS = ("sprintf", "snprintf", "vsprintf", "strcat", "strncat", "asprintf")
_EXEC = ("system", "popen", "execl", "execlp", "execvp", "execv", "execve")
_INPUT = ("read", "recv", "recvfrom", "fgets", "gets", "scanf", "__isoc99_scanf", "getenv",
          "fread", "getline")


def _imp(reg):
    t = reg.get("r2_imports"); r = t.run() if t else None
    return (r.data or "").lower() if r and r.ok else ""


def _str(reg):
    t = reg.get("r2_strings"); r = t.run() if t else None
    return (r.data or "") if r and r.ok else ""


def _f(t_es, t_en, sev, ev, r_es, r_en, rec_es, rec_en, lang, loc):
    return Finding(title=t_es if lang == "es" else t_en, severity=sev, verdict="grounded",
                   evidence=ev, location=loc, rationale=r_es if lang == "es" else r_en,
                   recommendation=rec_es if lang == "es" else rec_en,
                   rationale_en=r_en, recommendation_en=rec_en)


def _present(names, keys):
    """Palabras clave presentes como IMPORT real (subcadena dentro de un nombre parseado, para captar
    variantes _chk). No matchea cabeceras ni strings sueltas: solo nombres de simbolos importados."""
    return [k for k in keys if any(k in n for n in names)]


def scan_injection(reg: ToolRegistry, binary: str, lang: str = "es") -> List[Finding]:
    findings: List[Finding] = []
    names = imported_names(reg)          # nombres de import REALES (parseados), no texto crudo
    strings = _str(reg)
    es = lang == "es"

    # (a) SQL injection: EXIGE una API de ejecucion SQL real importada. Sin ella, cadenas SQL sueltas
    # (frecuentes en glibc estatica / recursos embebidos) NO son evidencia de SQLi -> no se reporta.
    sql_api = _present(names, _SQL_API)
    has_param = bool(_present(names, ("sqlite3_prepare", "mysql_stmt_prepare", "pqexecparams",
                                      "sqlite3_bind", "mysql_stmt_bind")))
    sql_text = bool(_SQL_TEXT.search(strings)) or bool(_SQL_FMT.search(strings))
    builders = _present(names, _BUILDERS)
    if sql_api and (builders or _SQL_FMT.search(strings)) and not (has_param and not builders):
        findings.append(_f(
            "Posible inyeccion SQL (consulta por concatenacion)",
            "Possible SQL injection (query by concatenation)", "high",
            "[radare2: ii + izz]\n" + ("api: " + ", ".join(sql_api) + "\n" if sql_api else "")
            + ("construccion: " + ", ".join(builders) + "\n" if builders else "")
            + ("consulta SQL con formato/concatenacion en strings" if sql_text else ""),
            "El binario arma consultas SQL con concatenacion/formato (sprintf/%s) en vez de sentencias "
            "parametrizadas. Si parte de la consulta viene de la entrada del usuario, es SQL injection "
            "(leer/alterar la BBDD, bypass de auth)." if es else
            "The binary builds SQL queries via concatenation/format (sprintf/%s) instead of prepared "
            "statements. If any part comes from user input, it is SQL injection (read/alter the DB, auth "
            "bypass).",
            "The binary builds SQL by concatenation instead of prepared statements; SQLi risk.",
            "Usa SIEMPRE sentencias preparadas con parametros ligados (sqlite3_prepare_v2/bind, "
            "mysql_stmt_bind, PQexecParams); nunca concatenes entrada en el SQL." if es else
            "Always use prepared statements with bound parameters (sqlite3_prepare_v2/bind, "
            "mysql_stmt_bind, PQexecParams); never concatenate input into SQL.",
            "Use prepared statements with bound parameters; never concatenate input into SQL.",
            lang, "inyeccion / sql"))

    # (b) entrada no confiable -> sink de ejecucion (vision consolidada). Requiere imports REALES de
    # una fuente de entrada Y de un sink de ejecucion, Y que ambos esten llamados desde la MISMA
    # funcion (shared_caller_fns): sin esto, cualquier binario que lea entrada en algun sitio Y
    # ejecute un exec en otro (p.ej. un 'gift'/'win' de CTF con system("/bin/sh") fijo, sin relacion
    # con la entrada) disparaba un falso positivo -- se confirmo en ~60% del corpus de ejemplo
    # (ret2win, canary, oobwrite...: el system() esta en win(), no alimentado por gets()).
    #
    # Dataflow INTRAPROCEDURAL (pedido explicito del usuario -- "no basta con la misma funcion, hay
    # que ir mas alla"): dataflow_confirmed() intenta un nivel mas de evidencia, buscando si el
    # MISMO operando (variable de pila o registro) que recibe la entrada se reutiliza como argumento
    # del sink -- mas fuerte que "misma funcion" a secas, aunque sigue siendo heuristico sintactico,
    # no symbolic execution real (se dice honestamente en el hallazgo, nunca se presenta como prueba
    # absoluta). Si no se confirma a ese nivel, se mantiene el hallazgo con la senal mas debil
    # (misma funcion) que ya habia antes, citando la funcion real.
    inputs = _present(names, _INPUT)
    execs = _present(names, _EXEC)
    shared_fns = shared_caller_fns(reg, inputs, execs, binary) if (inputs and execs) else set()
    if shared_fns:
        flow = dataflow_confirmed(reg, inputs, execs, binary)
        fn_txt = ", ".join(sorted(shared_fns))
        base_es = "El binario lee entrada (" + ", ".join(inputs[:4]) + ") y ejecuta comandos (" + ", ".join(execs[:3]) + ")."
        base_en = "The binary reads input (" + ", ".join(inputs[:4]) + ") and executes commands (" + ", ".join(execs[:3]) + ")."
        if flow:
            t_es = "Superficie de inyeccion: dataflow confirmado hasta ejecucion de comandos"
            t_en = "Injection surface: dataflow confirmed into command execution"
            r_es = base_es + (
                f" DATAFLOW: en {flow['fn']}, la llamada a {flow['source']} y la llamada a "
                f"{flow['sink']} comparten el operando '{flow['shared_operand']}' -- senal de que el "
                f"MISMO valor leido se reutiliza como argumento del sink, no solo que ambas llamadas "
                f"viven en la misma funcion. Sigue siendo una heuristica sintactica (no symbolic "
                f"execution), pero es una senal bastante mas fuerte que la simple co-ocurrencia.")
            r_en = base_en + (
                f" DATAFLOW: in {flow['fn']}, the call to {flow['source']} and the call to "
                f"{flow['sink']} share the operand '{flow['shared_operand']}' -- a signal that the "
                f"SAME value read is reused as the sink's argument, not just that both calls live in "
                f"the same function. Still a syntactic heuristic (not symbolic execution), but a much "
                f"stronger signal than mere co-occurrence.")
            sev = "high"
            loc = flow["fn"]
        else:
            t_es = "Superficie de inyeccion: entrada no confiable alcanza ejecucion de comandos"
            t_en = "Injection surface: untrusted input reaches command execution"
            r_es = base_es + (
                f" Confirmado que ambas llamadas viven en {fn_txt} (xref), pero NO se pudo confirmar "
                f"que el mismo operando fluya de la entrada al sink (heuristica de dataflow sin "
                f"match) -- puede que sean valores distintos en la misma funcion; revisa el flujo de "
                f"datos a mano.")
            r_en = base_en + (
                f" Confirmed that both calls live in {fn_txt} (xref), but the same-operand dataflow "
                f"heuristic found no match -- they may be unrelated values within the same function; "
                f"review the data flow by hand.")
            sev = "medium"
            loc = fn_txt
        findings.append(_f(
            t_es, t_en, sev,
            "[radare2: ii + axt]\nfuentes de entrada: " + ", ".join(inputs[:5])
            + "\nsinks de ejecucion: " + ", ".join(execs[:4]) + f"\nfuncion(es): {fn_txt}",
            r_es, r_en,
            "No pases entrada a system/popen; usa execve con argv fijo (sin shell), valida/escapa y "
            "aplica listas de permitidos.",
            "Do not pass input to system/popen; use execve with a fixed argv (no shell), validate/escape "
            "and use allow-lists.",
            lang, loc))
    return findings
