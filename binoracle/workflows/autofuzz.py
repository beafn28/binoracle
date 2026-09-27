"""Auto-fuzzing: descubre dinamicamente QUE input dispara el fallo (bloqueo nº2 de la explotacion).

Cierra el hueco de "hace falta el disparador": dado un binario, prueba distintos VECTORES de entrada
(stdin, argv, fichero) con payloads que provocan fallos (patrones ciclicos largos -> overflow;
`%p/%n` -> format-string; numeros extremos -> integer) y detecta el CRASH por el codigo de salida en
el sandbox (139 = SIGSEGV, 134 = SIGABRT). Devuelve el vector y la clase de vulnerabilidad
confirmados por ejecucion, mas el tamano minimo que crashea (cota del offset). El offset exacto y el
exploit los resuelve y VERIFICA el resto del pipeline; aqui solo se descubre el disparador.

Solo binarios AUTORIZADOS / CTF / research. Corre en el sandbox docker (--network none, --rm).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple


@dataclass
class Trigger:
    vector: str          # stdin | argv | file
    vuln_class: str      # stack-overflow | format-string | integer-overflow | crash
    min_size: Optional[int] = None
    exit_code: Optional[int] = None
    evidence: str = ""


@dataclass
class FuzzResult:
    ok: bool = False
    binary: str = ""
    triggers: List[Trigger] = field(default_factory=list)
    note: str = ""

    @property
    def crashed(self) -> bool:
        return any(t.exit_code in (139, 134, 136) for t in self.triggers)


def _cyclic(n: int) -> bytes:
    try:
        from pwn import cyclic
        return cyclic(n)
    except Exception:
        # fallback deterministico si pwntools no esta: patron aaaabaaac...
        import string
        alpha = (string.ascii_lowercase).encode()
        out = bytearray()
        i = 0
        while len(out) < n:
            block = bytes([alpha[(i // 26) % 26], alpha[i % 26]]) * 2
            out += block
            i += 1
        return bytes(out[:n])


def _probe(binary: str, *, stdin: bytes = b"", argv: Optional[str] = None,
           argv_list: Optional[List[str]] = None, as_file: Optional[bytes] = None,
           timeout: float = 30.0) -> Tuple[Optional[int], str]:
    """Ejecuta el binario en el sandbox capturando el CODIGO DE SALIDA (para detectar el crash) y la
    salida. `argv` pasa un argumento; `argv_list` pasa VARIOS (para invocaciones dirigidas tipo
    `-s <payload>`); `as_file` escribe un fichero y lo pasa como argv[1]."""
    docker = shutil.which("docker")
    if not docker:
        return (None, "docker no disponible")
    d = os.path.dirname(os.path.abspath(binary))
    name = os.path.basename(binary)
    inp = os.path.join(d, ".fuzz_in")
    with open(inp, "wb") as f:
        f.write(stdin)
    fpath_rel = ""
    if as_file is not None:
        fp = os.path.join(d, ".fuzz_file")
        with open(fp, "wb") as f:
            f.write(as_file)
        fpath_rel = ".fuzz_file"
    if argv_list:
        args = " ".join(_shq(a) for a in argv_list)
        run = f"chmod +x ./{name}; ./{name} {args} < .fuzz_in > .fuzz_out 2>&1; echo EXIT=$?"
    elif argv is not None:
        run = f"chmod +x ./{name}; ./{name} {_shq(argv)} < .fuzz_in > .fuzz_out 2>&1; echo EXIT=$?"
    elif fpath_rel:
        run = f"chmod +x ./{name}; ./{name} {fpath_rel} < /dev/null > .fuzz_out 2>&1; echo EXIT=$?"
    else:
        run = f"chmod +x ./{name}; ./{name} < .fuzz_in > .fuzz_out 2>&1; echo EXIT=$?"
    run += "; head -c 800 .fuzz_out"
    try:
        out = subprocess.run(
            [docker, "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--memory", "256m", "--pids-limit", "128", "-v", d + ":/w", "-w", "/w",
             "gcc:13", "bash", "-c", run],
            capture_output=True, text=True, errors="replace", timeout=timeout)
        text = (out.stdout or "") + (out.stderr or "")
    except subprocess.TimeoutExpired:
        text = "EXIT=124\n[timed out]"
    finally:
        for fn in (".fuzz_in", ".fuzz_out", ".fuzz_file"):
            try:
                os.unlink(os.path.join(d, fn))
            except OSError:
                pass
    code = None
    for ln in text.splitlines():
        if ln.startswith("EXIT="):
            try:
                code = int(ln.split("=", 1)[1].strip())
            except ValueError:
                code = None
            break
    body = "\n".join(l for l in text.splitlines() if not l.startswith("EXIT="))
    return (code, body.strip())


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def autofuzz(binary: str, on_step: Optional[Callable[[str], None]] = None,
             lang: str = "es", timeout: float = 30.0) -> FuzzResult:
    """Descubre el/los disparador(es) del binario probando vectores y payloads en el sandbox. No lanza."""
    step = on_step or (lambda _m: None)
    es = lang == "es"
    res = FuzzResult(binary=binary)
    if not os.path.exists(binary):
        res.note = "binario no encontrado"
        return res

    # pista estatica de vectores por los imports
    imports = ""
    try:
        from ..oracles import build_registry
        reg = build_registry(binary)
        if reg.get("r2_imports"):
            imports = (reg.get("r2_imports").run().data or "").lower()
    except Exception:
        pass

    # 1) STDIN overflow: patron ciclico creciente, busca el minimo que crashea (SIGSEGV)
    step("fuzzing stdin con patrones ciclicos crecientes..." if es else
         "fuzzing stdin with growing cyclic patterns...")
    min_crash = None
    last_code = None
    for size in (64, 128, 256, 512, 1024, 2048):
        code, _out = _probe(binary, stdin=_cyclic(size), timeout=timeout)
        last_code = code
        if code in (139, 134, 136):
            min_crash = size
            break
    if min_crash is not None:
        res.triggers.append(Trigger("stdin", "stack-overflow", min_size=min_crash, exit_code=last_code,
                                    evidence=(f"crash (exit {last_code}) con {min_crash} bytes ciclicos por stdin")))
        step((f"crash por stdin con ~{min_crash} bytes (exit {last_code}) -> overflow" if es else
              f"stdin crash at ~{min_crash} bytes (exit {last_code}) -> overflow"))

    # 2) FORMAT-STRING: %p en cadena -> fuga de la pila (hex en la salida) o crash con %n
    if any(f in imports for f in ("printf", "fprintf", "vprintf", "snprintf", "syslog")):
        step("probando format-string (%p/%n) por stdin..." if es else
             "probing format-string (%p/%n) via stdin...")
        code, out = _probe(binary, stdin=b"%p." * 20 + b"\n", timeout=timeout)
        hexcount = out.count("0x")
        if hexcount >= 4:
            res.triggers.append(Trigger("stdin", "format-string", exit_code=code,
                                        evidence=f"la salida filtro {hexcount} valores de la pila con %p"))
            step((f"format-string CONFIRMADA: %p filtro {hexcount} valores de la pila" if es else
                  f"format-string CONFIRMED: %p leaked {hexcount} stack values"))
        else:
            code2, _ = _probe(binary, stdin=b"%n%n%n%n\n", timeout=timeout)
            if code2 in (139, 134):
                res.triggers.append(Trigger("stdin", "format-string", exit_code=code2,
                                            evidence=f"crash con %n (exit {code2}): escritura por format-string"))

    # 3) ARGV overflow: argumento largo
    step("fuzzing argv (argumento largo)..." if es else "fuzzing argv (long argument)...")
    code, _ = _probe(binary, argv=_cyclic(1024).decode("latin1"), timeout=timeout)
    if code in (139, 134, 136):
        res.triggers.append(Trigger("argv", "stack-overflow", min_size=1024, exit_code=code,
                                    evidence=f"crash (exit {code}) con argv[1] de 1024 bytes"))
        step("crash por argv -> overflow en argumento" if es else "argv crash -> argument overflow")

    res.ok = bool(res.triggers)
    if not res.ok:
        res.note = ("sin crash con los vectores probados (stdin/argv/format-string); el disparador "
                    "puede ser un formato de fichero o una peticion de red (harness dedicado)"
                    if es else
                    "no crash with the probed vectors; the trigger may be a file format or a network "
                    "request (dedicated harness needed)")
    return res


_DIRECTED_SYS = (
    "Eres un fuzzer dirigido para retos AUTORIZADOS. Dada la hipotesis del disparador de una "
    "vulnerabilidad y un binario, propones INVOCACIONES CONCRETAS para intentar provocar el fallo. "
    "Responde SOLO JSON: {\"cases\": [{\"vector\": \"stdin\"|\"argv\"|\"file\", \"argv\": [\"-s\", "
    "\"{PAD:200}\\\\\"], \"stdin\": \"...\", \"file\": \"...\", \"note\": \"...\"}]}. Usa los tokens "
    "{PAD:n} (n bytes 'A') y {CYCLIC:n} (patron ciclico de n bytes) donde quieras un relleno largo. "
    "Incluye flags y patrones especificos de la hipotesis (p.ej. un argumento acabado en '\\\\'). "
    "Da 4-8 casos, del mas probable al menos."
)


def _expand(s: str) -> bytes:
    """Expande los tokens {PAD:n} y {CYCLIC:n} de una cadena propuesta por el LLM a bytes."""
    if s is None:
        return b""
    if isinstance(s, bytes):
        return s
    out = str(s)
    for m in list(re.finditer(r"\{PAD:(\d+)\}", out)):
        out = out.replace(m.group(0), "A" * int(m.group(1)), 1)
    def _cyc(m):
        return _cyclic(int(m.group(1))).decode("latin1")
    out = re.sub(r"\{CYCLIC:(\d+)\}", _cyc, out)
    return out.encode("latin1", "replace")


def directed_fuzz(binary: str, trigger_hint: str, llm, on_step=None, lang: str = "es",
                  timeout: float = 30.0, max_cases: int = 8) -> FuzzResult:
    """Fuzzing DIRIGIDO por el LLM: a partir de la hipotesis del disparador, el modelo propone
    invocaciones concretas (flags, patrones como argumentos acabados en '\\') y las probamos en el
    sandbox buscando el crash. Cierra el hueco de los disparadores no triviales (no solo stdin). No
    lanza; sin LLM devuelve vacio."""
    step = on_step or (lambda _m: None)
    es = lang == "es"
    res = FuzzResult(binary=binary)
    if not os.path.exists(binary):
        res.note = "binario no encontrado"
        return res
    if llm is None or not getattr(llm, "available", lambda: False)():
        res.note = "sin LLM: no hay fuzzing dirigido"
        return res
    try:
        from ..llm.base import Message
        raw = llm.chat([Message("system", _DIRECTED_SYS),
                        Message("user", f"binario: {os.path.basename(binary)}\n"
                                        f"hipotesis del disparador: {trigger_hint}\n"
                                        "Propon los casos en JSON.")], json_mode=True)
        import json as _json
        data = _json.loads(raw)
        cases = data.get("cases") if isinstance(data, dict) else None
    except Exception as e:
        res.note = f"no se pudo obtener casos del LLM: {e}"
        return res
    if not isinstance(cases, list) or not cases:
        res.note = "el LLM no propuso casos"
        return res
    step((f"probando {min(len(cases), max_cases)} invocaciones dirigidas por el LLM..." if es else
          f"trying {min(len(cases), max_cases)} LLM-directed invocations..."))
    for i, c in enumerate(cases[:max_cases], 1):
        if not isinstance(c, dict):
            continue
        vector = (c.get("vector") or "stdin").lower()
        note = c.get("note", "")
        try:
            if vector == "argv" and c.get("argv"):
                argv_list = [_expand(a).decode("latin1") for a in c["argv"]]
                code, out = _probe(binary, argv_list=argv_list, timeout=timeout)
                shown = " ".join(a[:24] for a in argv_list)
            elif vector == "file" and c.get("file") is not None:
                code, out = _probe(binary, as_file=_expand(c["file"]), timeout=timeout)
                shown = "fichero"
            else:
                code, out = _probe(binary, stdin=_expand(c.get("stdin", "")), timeout=timeout)
                shown = "stdin"
        except Exception:
            continue
        crashed = code in (139, 134, 136)
        step((f"  caso {i} [{vector}] {shown[:40]} -> {'CRASH exit '+str(code) if crashed else 'ok'}"
              if es else
              f"  case {i} [{vector}] {shown[:40]} -> {'CRASH exit '+str(code) if crashed else 'ok'}"))
        if crashed:
            res.triggers.append(Trigger(vector, "stack-overflow", exit_code=code,
                                        evidence=(f"crash dirigido por el LLM (exit {code}): "
                                                  f"{note or shown}")))
            break
    res.ok = bool(res.triggers)
    if not res.ok:
        res.note = ("ninguna invocacion dirigida por el LLM provoco el fallo (puede requerir el "
                    "binario/entorno exactos o heap grooming)" if es else
                    "no LLM-directed invocation triggered the fault (may need the exact binary/"
                    "environment or heap grooming)")
    return res


def render_fuzz(res: FuzzResult, lang: str = "es") -> str:
    es = lang == "es"
    out = ["## " + ("Auto-fuzzing: descubrimiento del disparador" if es else
                    "Auto-fuzzing: trigger discovery")]
    if not res.ok:
        return "\n".join(out) + "\n\n" + (res.note or ("sin disparador hallado" if es else "no trigger found"))
    for t in res.triggers:
        line = (f"- **{t.vector}** -> `{t.vuln_class}`"
                + (f" (min {t.min_size} bytes)" if t.min_size else "")
                + (f", exit {t.exit_code}" if t.exit_code is not None else ""))
        out.append(line)
        if t.evidence:
            out.append(f"  - {t.evidence}")
    out.append("\n" + ("El offset exacto y el exploit los resuelve y VERIFICA el pipeline "
                       "(CVE->Exploit / autopwn) sobre este binario." if es else
                       "The exact offset and the exploit are resolved and VERIFIED by the pipeline "
                       "(CVE->Exploit / autopwn) on this binary."))
    return "\n".join(out)
