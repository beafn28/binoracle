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
from ._binfacts import imported_names

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
    # una fuente de entrada Y de un sink de ejecucion (no basta el simbolo en glibc estatica).
    inputs = _present(names, _INPUT)
    execs = _present(names, _EXEC)
    if inputs and execs:
        findings.append(_f(
            "Superficie de inyeccion: entrada no confiable alcanza ejecucion de comandos",
            "Injection surface: untrusted input reaches command execution", "medium",
            "[radare2: ii]\nfuentes de entrada: " + ", ".join(inputs[:5])
            + "\nsinks de ejecucion: " + ", ".join(execs[:4]),
            "El binario lee entrada (" + ", ".join(inputs[:4]) + ") y ejecuta comandos (" +
            ", ".join(execs[:3]) + "). Si esa entrada llega al comando sin sanear, es inyeccion de "
            "comando. Revisa el flujo de datos entre la lectura y el exec." if es else
            "The binary reads input (" + ", ".join(inputs[:4]) + ") and executes commands (" +
            ", ".join(execs[:3]) + "). If that input reaches the command unsanitized, it is command "
            "injection. Review the data flow between the read and the exec.",
            "The binary reads input and executes commands; review the data flow for injection.",
            "No pases entrada a system/popen; usa execve con argv fijo (sin shell), valida/escapa y "
            "aplica listas de permitidos." if es else
            "Do not pass input to system/popen; use execve with a fixed argv (no shell), validate/escape "
            "and use allow-lists.",
            "Use execve with a fixed argv (no shell); validate/escape input with allow-lists.",
            lang, "inyeccion / comando"))
    return findings
