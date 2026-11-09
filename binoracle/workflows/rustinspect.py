"""Static Rust binary heuristics: toolchain commit, dependency crates, panic strings.

ROADMAP v0.4 "[S] More formats & backends" -- "Rust binary heuristics", the counterpart to
`goinspect.py`'s Go build-info reader. Rust has no equivalent embedded build-info blob, but the
rustc compiler bakes the FULL SOURCE PATH of every library/crate it compiles into panic
location strings and debug info references -- and that path is deterministic:
`/rustc/<40-hex-commit-hash>/library/<crate>/src/...` for the standard library, and
`/rust/deps/<crate>-<version>/src/...` for third-party crates pulled in via Cargo. These are
plain ASCII strings embedded in .rodata; unlike Go's magic-prefixed blob there is no dedicated
parser needed, and -- confirmed live against a real `rustc -O`-compiled, then `strip`-ed binary
-- they SURVIVE strip entirely (they are data, not symbol-table entries, so `strip` never touches
them). Mangled Rust symbol names (`_ZN...` legacy or `_R...` v0 mangling) are a secondary signal,
checked only if present (modern release-profile Cargo builds often strip almost all of them from
the symbol table even before an explicit `strip`, which is why this module does not depend on
them). Absence of every signal is NOT proof the binary isn't Rust (it could be built with
`panic = "abort"` and heavily stripped by hand) -- this reports what it observes and its limits,
same honesty convention as `goinspect.py`."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

_MAX_READ = 64 * 1024 * 1024   # 64MB cap, same order of magnitude as other static string scans

_RUSTC_PATH_RE = re.compile(rb"/rustc/([0-9a-f]{40})/")
_DEP_CRATE_RE = re.compile(rb"/rust/deps/([A-Za-z0-9_.+]+)-(\d+\.\d+\.\d+[A-Za-z0-9.+-]*)/")
_PANIC_RE = re.compile(rb"panicked at ")
_MANGLE_LEGACY_RE = re.compile(rb"_ZN[0-9A-Za-z_]{4,}")
_MANGLE_V0_RE = re.compile(rb"_R[A-Za-z0-9_]{4,}")
_CARGO_PKG_RE = re.compile(rb"CARGO_PKG_NAME=([A-Za-z0-9_-]+)")


@dataclass
class RustSignals:
    ok: bool = False
    note: str = ""
    is_likely_rust: bool = False
    rustc_commit: str = ""
    dep_crates: List[str] = field(default_factory=list)
    cargo_pkg_names: List[str] = field(default_factory=list)
    has_panic_strings: bool = False
    n_mangled_legacy: int = 0
    n_mangled_v0: int = 0


def inspect_rust(path: str) -> RustSignals:
    """Escanea `path` (sin parsear ELF/PE -- un grep estructurado sobre los bytes crudos, igual
    de valido este stripped o no) buscando las firmas que el propio compilador de Rust deja
    detras. Nunca afirma 'es Rust' con certeza absoluta -- is_likely_rust solo se activa si hay
    al menos UNA senal de alta confianza (hash de commit de rustc, o una ruta de dependencia de
    Cargo); los simbolos mangled o las cadenas de panic solas son demasiado ambiguas."""
    res = RustSignals()
    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_READ)
    except OSError as e:
        res.note = f"no se pudo leer el binario: {e}"
        return res

    m = _RUSTC_PATH_RE.search(data)
    if m:
        res.rustc_commit = m.group(1).decode("ascii")

    seen = set()
    for m in _DEP_CRATE_RE.finditer(data):
        name, ver = m.group(1).decode("ascii"), m.group(2).decode("ascii")
        key = f"{name}-{ver}"
        if key not in seen:
            seen.add(key)
            res.dep_crates.append(key)
    res.dep_crates.sort()

    seen_pkg = set()
    for m in _CARGO_PKG_RE.finditer(data):
        name = m.group(1).decode("ascii")
        if name not in seen_pkg:
            seen_pkg.add(name)
            res.cargo_pkg_names.append(name)

    res.has_panic_strings = _PANIC_RE.search(data) is not None
    res.n_mangled_legacy = len(_MANGLE_LEGACY_RE.findall(data))
    res.n_mangled_v0 = len(_MANGLE_V0_RE.findall(data))

    res.ok = True
    res.is_likely_rust = bool(res.rustc_commit or res.dep_crates or res.cargo_pkg_names)
    signals = []
    if res.rustc_commit:
        signals.append(f"commit de rustc {res.rustc_commit[:12]}")
    if res.dep_crates:
        signals.append(f"{len(res.dep_crates)} crate(s) de dependencia")
    if res.cargo_pkg_names:
        signals.append(f"{len(res.cargo_pkg_names)} CARGO_PKG_NAME")
    if res.has_panic_strings:
        signals.append("cadenas 'panicked at'")
    if res.n_mangled_legacy or res.n_mangled_v0:
        signals.append(f"{res.n_mangled_legacy + res.n_mangled_v0} simbolo(s) mangled")
    res.note = ("senales encontradas: " + ", ".join(signals)) if signals else \
        "ninguna senal de Rust encontrada (no prueba que NO sea Rust -- puede estar muy stripped o usar panic=abort)"
    return res


def render_rust(r: RustSignals) -> str:
    out = ["## Rust binary heuristics\n"]
    if not r.ok:
        return "\n".join(out + ["No disponible: " + r.note])
    out.append(f"- es probablemente Rust: {'SI' if r.is_likely_rust else 'sin senal suficiente'}")
    out.append(f"- {r.note}\n")
    if r.rustc_commit:
        out.append(f"- commit del compilador rustc: `{r.rustc_commit}`")
    if r.cargo_pkg_names:
        out.append(f"- CARGO_PKG_NAME embebidos: {', '.join(r.cargo_pkg_names)}")
    if r.dep_crates:
        out.append("\n### Crates de dependencia (via Cargo)\n")
        for c in r.dep_crates:
            out.append(f"- `{c}`")
    if r.n_mangled_legacy or r.n_mangled_v0:
        out.append(f"\n- simbolos con mangling legacy (`_ZN...`): {r.n_mangled_legacy}")
        out.append(f"- simbolos con mangling v0 (`_R...`): {r.n_mangled_v0}")
    return "\n".join(out)
