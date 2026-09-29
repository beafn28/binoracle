"""Puertas traseras de red y comandos inyectables.

Detecta (a) patrones de bind shell / reverse shell (socket + bind/connect + dup2 + execve),
(b) puertos hardcodeados tipicos de backdoor extraidos del disasm (htons inmediato), y
(c) inyeccion de comando por concatenacion (system/popen alimentado por sprintf/strcat).

Grounded: se apoya en los imports (r2 ii), las strings (izz) y, para el puerto, en el
inmediato real que se pasa a htons antes de bind/connect (r2 pdf sobre la funcion que llama).
Nunca lanza: si r2 no esta, cae a la deteccion por imports.
"""
from __future__ import annotations

from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding
from ._binfacts import imported_names, shared_caller_fns

_SPAWN = ("execve", "execl", "execlp", "execvp", "execv", "system", "popen", "dup2")
# puertos tipicos de backdoor/bind-shell (decimal) -> se buscan como inmediato htons en el disasm
_BD_PORTS = (4444, 4445, 1337, 31337, 12345, 1234, 6666, 6667, 9999, 5555, 2323, 8888)
# constructores de cadena: si su salida llega a system/popen, es inyeccion de comando
_BUILDERS = ("sprintf", "snprintf", "vsprintf", "strcat", "strncat", "strcpy", "asprintf")


def _run(reg: ToolRegistry, name: str) -> str:
    t = reg.get(name)
    if t:
        r = t.run()
        if r.ok:
            return r.data or ""
    return ""


def _f(title_es, title_en, sev, ev, rat_es, rat_en, rec_es, rec_en, lang, loc="binario / red"):
    return Finding(
        title=title_es if lang == "es" else title_en,
        severity=sev, verdict="grounded", evidence=ev, location=loc,
        rationale=rat_es if lang == "es" else rat_en,
        recommendation=rec_es if lang == "es" else rec_en,
        rationale_en=rat_en, recommendation_en=rec_en,
    )


def _hardcoded_ports(binary: str, sinks) -> list:
    """Busca en el disasm de las funciones que llaman a bind/connect un inmediato que, interpretado
    como htons(puerto), coincida con un puerto tipico de backdoor. Devuelve [(puerto, addr)].
    Best-effort: si r2 no esta o no hay match, devuelve []."""
    found = []
    try:
        import json as _j
        import r2pipe
        r = r2pipe.open(binary, flags=["-2"]); r.cmd("aaa")
        # inmediatos candidatos: htons hace byte-swap, asi que buscamos ambos (host y network order)
        want = {}
        for p in _BD_PORTS:
            want[p] = p
            want[((p & 0xff) << 8) | (p >> 8)] = p   # byte-swapped (htons en x86 little-endian)
        for sink in sinks:
            xr = r.cmd(f"axtj @ sym.imp.{sink}") or ""
            try:
                xs = _j.loads(xr) if xr.strip() else []
            except Exception:
                xs = []
            for x in xs:
                fn = x.get("fcn_name")
                if not fn:
                    continue
                dis = r.cmd(f"pdfj @ {fn}") or ""
                try:
                    ops = _j.loads(dis).get("ops", []) if dis.strip() else []
                except Exception:
                    ops = []
                for op in ops:
                    for v in op.get("refs", []) + ([{"addr": op.get("val")}] if op.get("val") is not None else []):
                        val = v.get("addr") if isinstance(v, dict) else v
                        if isinstance(val, int) and val in want:
                            found.append((want[val], hex(op.get("offset", 0))))
        r.quit()
    except Exception:
        return []
    # dedup por puerto
    seen = {}
    for port, addr in found:
        seen.setdefault(port, addr)
    return sorted(seen.items())


def scan_backdoors(reg: ToolRegistry, binary: str, lang: str = "es") -> List[Finding]:
    findings: List[Finding] = []
    # nombres de import REALES (parseados), no substring sobre el texto crudo de `ii`: la cabecera de
    # la tabla lleva una columna literal 'bind', que con matching ingenuo se leia como uso de red.
    names = imported_names(reg)
    strings = _run(reg, "r2_strings")

    has_socket = "socket" in names
    has_bind = "bind" in names and "listen" in names
    has_connect = "connect" in names
    spawn = [s for s in _SPAWN if s in names]
    has_shell_str = "/bin/sh" in strings or "/bin/bash" in strings

    # (a) bind shell: socket + bind + listen + (dup2 | execve/system), Y el spawn debe compartir
    # funcion llamadora con socket/bind (misma ruta de codigo, no solo presencia en el binario).
    # shared_caller_fns (no solo shares_caller booleano) da la funcion REAL, para citarla en vez de
    # dejar "binario / red" generico -- pedido explicito del usuario, mismo principio aplicado a
    # credenciales: no basta con decir que hay coincidencia, hay que decir EN QUE funcion.
    bind_fns = shared_caller_fns(reg, ("socket", "bind", "listen"), spawn, binary) if (has_socket and has_bind and spawn) else set()
    if bind_fns:
        fn_txt = ", ".join(sorted(bind_fns))
        ports = _hardcoded_ports(binary, ("bind",))
        port_ev = ("\ninmediato(s) compatible(s) con puerto (heuristico): "
                   + ", ".join(f"{p} @ {a}" for p, a in ports)) if ports else ""
        # critical solo con la cadena de shell presente (senal fuerte); el puerto es heuristico y
        # puede dar falsos positivos, asi que por si solo no escala por encima de high.
        sev = "critical" if has_shell_str else "high"
        findings.append(_f(
            "Posible bind shell / backdoor de red",
            "Possible bind shell / network backdoor", sev,
            f"[radare2: ii + axt]\nsocket + bind + listen + {', '.join(spawn)}\nfuncion: {fn_txt}"
            + (f"\ncadena de shell presente: /bin/sh" if has_shell_str else "") + port_ev,
            f"El binario abre un socket, escucha en un puerto y puede lanzar un shell "
            f"({', '.join(spawn)}), todo desde la misma funcion ({fn_txt}, confirmado por xref). Es "
            "el patron de una bind shell: cualquiera que conecte al puerto obtiene ejecucion de "
            "comandos. Si el puerto esta hardcodeado, es casi seguro una puerta trasera.",
            f"The binary opens a socket, listens on a port and can spawn a shell "
            f"({', '.join(spawn)}), all from the same function ({fn_txt}, xref-confirmed). This is "
            "the bind-shell pattern: anyone connecting to the port gets command execution. A "
            "hardcoded port makes it almost certainly a backdoor.",
            "Elimina el codigo de bind/listen no legitimo; si es un servicio real, no lances shells, "
            "escucha solo en localhost, autentica y filtra por firewall.",
            "Remove any illegitimate bind/listen code; if it is a real service, never spawn shells, "
            "listen only on localhost, authenticate and firewall it.", lang, loc=fn_txt))

    # (b) reverse shell: socket + connect + (dup2 | execve/system), misma funcion llamadora.
    conn_fns = shared_caller_fns(reg, ("socket", "connect"), spawn, binary) if (has_socket and has_connect and spawn) else set()
    if conn_fns:
        fn_txt = ", ".join(sorted(conn_fns))
        ports = _hardcoded_ports(binary, ("connect",))
        port_ev = ("\ninmediato(s) compatible(s) con puerto (heuristico): "
                   + ", ".join(f"{p} @ {a}" for p, a in ports)) if ports else ""
        sev = "critical" if has_shell_str else "high"
        findings.append(_f(
            "Posible reverse shell / callback a atacante",
            "Possible reverse shell / attacker callback", sev,
            f"[radare2: ii + axt]\nsocket + connect + {', '.join(spawn)}\nfuncion: {fn_txt}"
            + (f"\ncadena de shell presente: /bin/sh" if has_shell_str else "") + port_ev,
            f"El binario abre un socket, se CONECTA a un host y puede lanzar un shell "
            f"({', '.join(spawn)}), todo desde la misma funcion ({fn_txt}, confirmado por xref). Es "
            "el patron de una reverse shell: el binario llama de vuelta a un atacante y le entrega "
            "ejecucion de comandos. Un destino/puerto hardcodeado confirma la puerta trasera.",
            f"The binary opens a socket, CONNECTS out to a host and can spawn a shell "
            f"({', '.join(spawn)}), all from the same function ({fn_txt}, xref-confirmed). This is "
            "the reverse-shell pattern: the binary calls back to an attacker and hands over command "
            "execution. A hardcoded host/port confirms the backdoor.",
            "Elimina el codigo de callback; un binario legitimo no debe conectar a hosts fijos ni "
            "redirigir un shell por socket. Revisa el destino y bloquea la salida.",
            "Remove the callback code; a legitimate binary must not connect to fixed hosts or pipe a "
            "shell over a socket. Review the destination and block egress.", lang, loc=fn_txt))

    # (c) inyeccion de comando por concatenacion: system/popen alimentado por un constructor de cadena
    # EN LA MISMA FUNCION. Sin este requisito, un binario con un builder en una funcion (p.ej. un
    # strcpy(buf, entrada) normal) y un exec de cadena FIJA en otra (p.ej. un system("cmd.exe") de un
    # 'win()' de CTF, sin relacion) disparaba un falso positivo -- confirmado en win_chall.exe.
    execs = [s for s in ("system", "popen", "execl", "execlp", "execvp") if s in names]
    builders = [b for b in _BUILDERS if b in names]
    inj_fns = shared_caller_fns(reg, builders, execs, binary) if (execs and builders) else set()
    if inj_fns:
        fn_txt = ", ".join(sorted(inj_fns))
        findings.append(_f(
            "Posible inyeccion de comando por concatenacion",
            "Possible command injection via string concatenation", "high",
            f"[radare2: ii + axt]\nejecucion: {', '.join(execs)}\nconstruccion de cadena: "
            f"{', '.join(builders)}\nfuncion: {fn_txt}",
            f"El binario construye una cadena de comando dinamicamente "
            f"({', '.join(builders)}) y la ejecuta con {', '.join(execs)}, todo en la funcion "
            f"{fn_txt} (confirmado por xref). Si parte de esa cadena viene de entrada del usuario "
            "(argumentos, ficheros, red), un atacante inyecta comandos con metacaracteres del shell "
            "(;, |, &&, $(), comillas) o rutas con espacios.",
            f"The binary builds a command string dynamically "
            f"({', '.join(builders)}) and runs it with {', '.join(execs)}, all in function {fn_txt} "
            "(xref-confirmed). If any part of that string comes from user input (arguments, files, "
            "network), an attacker injects commands via shell metacharacters (;, |, &&, $(), quotes) "
            "or paths containing spaces.",
            "No construyas comandos por concatenacion. Usa execve con argv fijo (sin shell), o valida "
            "estrictamente y escapa cada argumento; entrecomilla rutas y rechaza metacaracteres.",
            "Never build commands by concatenation. Use execve with a fixed argv (no shell), or strictly "
            "validate and escape every argument; quote paths and reject shell metacharacters.",
            lang, loc=fn_txt))
    return findings
