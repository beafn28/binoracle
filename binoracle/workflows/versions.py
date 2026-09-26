"""OWASP DA9 - Componentes con vulnerabilidades conocidas: detecta las versiones de los componentes
embebidos/enlazados (glibc, compilador GCC/Clang, OpenSSL, zlib, ...) a partir de las strings del
binario y senala las claramente ANTIGUAS.

Grounded y honesto: se reporta la version REAL extraida del binario. NO se afirma un CVE concreto
(no hay base de CVEs local); se marca 'version antigua' cuando el numero esta por debajo de un
umbral conservador, para que el analista lo contraste con el aviso de seguridad correspondiente.
"""
from __future__ import annotations

import re
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding

# patron -> (componente, regex de version, umbral 'antiguo' como tupla, nota)
_COMPONENTS = [
    ("glibc", re.compile(r"GNU C Library[^0-9]*(?:release |version |stable release version )([0-9]+)\.([0-9]+)"),
     (2, 27)),
    ("glibc", re.compile(r"glibc[ _-]?([0-9]+)\.([0-9]+)", re.I), (2, 27)),
    ("GCC", re.compile(r"GCC: \([^)]*\) ([0-9]+)\.([0-9]+)(?:\.[0-9]+)?"), (7, 0)),
    ("Clang", re.compile(r"clang version ([0-9]+)\.([0-9]+)", re.I), (10, 0)),
    ("OpenSSL", re.compile(r"OpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+)", re.I), (1, 1)),
    ("zlib", re.compile(r"(?:deflate |inflate )?([0-9]+)\.([0-9]+)\.([0-9]+) Copyright[^\n]*Adler", re.I),
     (1, 2)),
    ("libpng", re.compile(r"libpng version ([0-9]+)\.([0-9]+)\.([0-9]+)", re.I), (1, 6)),
    ("Python", re.compile(r"Python ([0-9]+)\.([0-9]+)\.([0-9]+)"), (3, 8)),
]


def _strings(reg: ToolRegistry) -> str:
    t = reg.get("r2_strings")
    if t:
        r = t.run()
        if r.ok:
            return r.data or ""
    return ""


def _old(ver, thr) -> bool:
    return tuple(ver[:len(thr)]) < tuple(thr)


def scan_versions(reg: ToolRegistry, binary: str, lang: str = "es") -> List[Finding]:
    findings: List[Finding] = []
    strings = _strings(reg)
    if not strings:
        return findings
    es = lang == "es"
    seen = set()
    for comp, rx, thr in _COMPONENTS:
        m = rx.search(strings)
        if not m:
            continue
        ver = tuple(int(x) for x in m.groups())
        key = (comp, ver)
        if key in seen:
            continue
        seen.add(key)
        vstr = ".".join(str(x) for x in ver)
        old = _old(ver, thr)
        if old:
            findings.append(Finding(
                title=(f"Componente antiguo: {comp} {vstr}" if es else f"Outdated component: {comp} {vstr}"),
                severity="medium", verdict="grounded", location="strings / componentes",
                evidence=f"[radare2: izz]\n{comp} {vstr} (umbral moderno: {'.'.join(str(x) for x in thr)}+)",
                rationale=(f"El binario embebe/enlaza {comp} {vstr}, por debajo de una version moderna. "
                           "Las versiones antiguas suelen acumular vulnerabilidades publicas conocidas; "
                           "contrasta esta version con el aviso de seguridad del componente." if es else
                           f"The binary embeds/links {comp} {vstr}, below a modern version. Old versions "
                           "tend to carry known public vulnerabilities; check this version against the "
                           "component's security advisory."),
                rationale_en=(f"The binary embeds/links {comp} {vstr}, below a modern version; check it "
                              "against the component's security advisory."),
                recommendation=(f"Actualiza {comp} a una version soportada y recompila/reenlaza; evita "
                                "distribuir componentes fuera de soporte." if es else
                                f"Update {comp} to a supported version and rebuild/relink; do not ship "
                                "out-of-support components."),
                recommendation_en=f"Update {comp} to a supported version and rebuild/relink."))
        else:
            findings.append(Finding(
                title=(f"Componente detectado: {comp} {vstr}" if es else f"Detected component: {comp} {vstr}"),
                severity="info", verdict="grounded", location="strings / componentes",
                evidence=f"[radare2: izz]\n{comp} {vstr}",
                rationale=(f"Componente enlazado/embebido: {comp} {vstr} (version moderna). Registrado "
                           "para el inventario de componentes; comprueba periodicamente sus avisos." if es else
                           f"Linked/embedded component: {comp} {vstr} (modern). Recorded for the component "
                           "inventory; check its advisories periodically."),
                rationale_en=f"Linked/embedded component: {comp} {vstr} (modern).",
                recommendation=("Manten el inventario de componentes y vigila sus avisos de seguridad."
                                if es else "Keep a component inventory and watch its security advisories."),
                recommendation_en="Keep a component inventory and watch its security advisories."))
    return findings
