"""Flutter / Dart AOT static reader (no execution).

Flutter apps ship a Dart Ahead-Of-Time (AOT) runtime: the engine `libflutter.so` plus the compiled
app `libapp.so`, whose four AOT snapshot symbols (`_kDartVmSnapshotData/Instructions`,
`_kDartIsolateSnapshotData/Instructions`) carry the program. Every fact here is an observation of
bytes at read time -- nothing is executed and nothing is looked up externally:

* the Dart snapshot magic `f5 f5 dc dc`, with the 32-hex snapshot hash 20 bytes after it (the hash
  pins the exact Dart SDK/engine revision the app was built with);
* the GNU build-id ELF note;
* labelled ASCII version strings (`Dart VM version: ...`);
* the four `_kDart*Snapshot*` dynamic symbols that identify an AOT `libapp.so`.

Works on a raw ELF (`libapp.so`/`libflutter.so`) or straight on an APK (ZIP): it finds the Flutter
payload libraries under `lib/<abi>/` and reads them in place. Design parity with REA's Flutter tools
(morluto/rea, MIT): `identify_flutter_build` -> `inspect_flutter`, `inspect_dart_aot` ->
`inspect_dart_aot`. Input is untrusted data; the reader only reads bytes."""
from __future__ import annotations

import re
import struct
import zipfile

DART_SNAPSHOT_MAGIC = b"\xf5\xf5\xdc\xdc"
_SNAP_HASH_OFFSET = 20
_SNAP_HASH_LEN = 32
_HASH_RE = re.compile(rb"^[0-9a-f]{32}$")
_AOT_SYMS = (
    "_kDartVmSnapshotData", "_kDartVmSnapshotInstructions",
    "_kDartIsolateSnapshotData", "_kDartIsolateSnapshotInstructions",
)
_VER_RE = re.compile(rb"Dart VM version: ([0-9][0-9A-Za-z.\-+_]{0,63})")
_FLUTTER_ENGINE_RE = re.compile(rb"Flutter[ _-]?[Ee]ngine[^\x00]{0,80}")
_MAX_HASHES = 64


def _scan_snapshot_hashes(data: bytes) -> tuple[list[str], int]:
    """Distinct 32-hex hashes that follow each Dart snapshot magic, in first-seen order."""
    hashes: list[str] = []
    seen: set[str] = set()
    sources = 0
    idx = data.find(DART_SNAPSHOT_MAGIC)
    while idx != -1:
        sources += 1
        start = idx + _SNAP_HASH_OFFSET
        cand = data[start:start + _SNAP_HASH_LEN]
        if len(cand) == _SNAP_HASH_LEN and _HASH_RE.match(cand):
            h = cand.decode("latin1")
            if h not in seen and len(hashes) < _MAX_HASHES:
                seen.add(h)
                hashes.append(h)
        idx = data.find(DART_SNAPSHOT_MAGIC, idx + 4)
    return hashes, sources


def _gnu_build_id(data: bytes) -> str | None:
    """Pull the GNU build-id out of a .note.gnu.build-id note by scanning for the note shape:
    namesz=4, descsz=N, type=3 (NT_GNU_BUILD_ID), name='GNU\\0'."""
    needle = b"GNU\x00"
    pos = data.find(needle)
    while pos != -1:
        hdr = pos - 12
        if hdr >= 0:
            namesz, descsz, ntype = struct.unpack_from("<III", data, hdr)
            if namesz == 4 and ntype == 3 and 0 < descsz <= 64:
                desc = data[pos + 4:pos + 4 + descsz]
                if len(desc) == descsz:
                    return desc.hex()
        pos = data.find(needle, pos + 1)
    return None


def _elf_dynsym_names(data: bytes) -> set[str]:
    """Best-effort: collect dynamic-symbol names present in an ELF by reading .dynstr via the
    section headers. Pure byte parsing; returns an empty set on any shape it cannot read."""
    try:
        if data[:4] != b"\x7fELF":
            return set()
        is64 = data[4] == 2
        le = "<" if data[5] == 1 else ">"
        if is64:
            e_shoff = struct.unpack_from(le + "Q", data, 0x28)[0]
            e_shentsize, e_shnum = struct.unpack_from(le + "HH", data, 0x3a)
        else:
            e_shoff = struct.unpack_from(le + "I", data, 0x20)[0]
            e_shentsize, e_shnum = struct.unpack_from(le + "HH", data, 0x2e)
        if not e_shoff or not e_shnum:
            return set()
        names: set[str] = set()
        # find .dynsym (type 11) + its linked .dynstr
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if is64:
                sh_type = struct.unpack_from(le + "I", data, off + 4)[0]
                sh_link = struct.unpack_from(le + "I", data, off + 0x28)[0]
                sh_offset = struct.unpack_from(le + "Q", data, off + 0x18)[0]
                sh_size = struct.unpack_from(le + "Q", data, off + 0x20)[0]
                sh_entsize = struct.unpack_from(le + "Q", data, off + 0x38)[0]
            else:
                sh_type = struct.unpack_from(le + "I", data, off + 4)[0]
                sh_link = struct.unpack_from(le + "I", data, off + 0x18)[0]
                sh_offset = struct.unpack_from(le + "I", data, off + 0x10)[0]
                sh_size = struct.unpack_from(le + "I", data, off + 0x14)[0]
                sh_entsize = struct.unpack_from(le + "I", data, off + 0x24)[0]
            if sh_type != 11 or not sh_entsize:
                continue
            # linked string table
            stroff = e_shoff + sh_link * e_shentsize
            if is64:
                str_off = struct.unpack_from(le + "Q", data, stroff + 0x18)[0]
                str_size = struct.unpack_from(le + "Q", data, stroff + 0x20)[0]
                name_field = 0
            else:
                str_off = struct.unpack_from(le + "I", data, stroff + 0x10)[0]
                str_size = struct.unpack_from(le + "I", data, stroff + 0x14)[0]
                name_field = 0
            strtab = data[str_off:str_off + str_size]
            n = sh_size // sh_entsize
            for s in range(n):
                sym = sh_offset + s * sh_entsize
                st_name = struct.unpack_from(le + "I", data, sym + name_field)[0]
                end = strtab.find(b"\x00", st_name)
                if end > st_name:
                    names.add(strtab[st_name:end].decode("latin1", "replace"))
            return names
    except Exception:
        return set()
    return set()


def _analyze_payload(data: bytes, label: str) -> dict:
    """Read all Flutter/Dart facts out of one in-memory library image."""
    hashes, sources = _scan_snapshot_hashes(data)
    syms = _elf_dynsym_names(data)
    aot_syms = sorted(s for s in _AOT_SYMS if s in syms)
    ver = _VER_RE.search(data)
    eng = _FLUTTER_ENGINE_RE.search(data)
    return {
        "name": label,
        "is_elf": data[:4] == b"\x7fELF",
        "dart_snapshot_sources": sources,
        "snapshot_hashes": hashes,
        "aot_snapshot_symbols": aot_syms,
        "is_dart_aot": len(aot_syms) >= 2 or sources > 0,
        "gnu_build_id": _gnu_build_id(data),
        "dart_vm_version": ver.group(1).decode("latin1") if ver else None,
        "flutter_engine": eng.group(0).decode("latin1", "replace")[:80] if eng else None,
    }


def _payloads_from_apk(path: str) -> list[tuple[str, bytes]]:
    """Return (arch/name, bytes) for each Flutter payload library inside an APK/ZIP."""
    out: list[tuple[str, bytes]] = []
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                base = info.filename.rsplit("/", 1)[-1]
                if base in ("libapp.so", "libflutter.so") and info.file_size <= 256 * 1024 * 1024:
                    with z.open(info) as f:
                        out.append((info.filename, f.read()))
    except Exception:
        pass
    return out


def inspect_flutter(path: str) -> dict:
    """identify_flutter_build: is this a Flutter app, and which build? Reads libapp.so/libflutter.so
    from an APK, or treats the file as a single Flutter payload ELF. Nothing executed; honest
    degradation when no Flutter payload is present."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except Exception as e:
        return {"ok": False, "tool": "flutter", "note": f"no se pudo abrir: {e}"}

    payloads: list[tuple[str, bytes]] = []
    if head == b"PK\x03\x04":
        payloads = _payloads_from_apk(path)
        if not payloads:
            return {"ok": True, "tool": "flutter", "is_flutter": False,
                    "note": "ZIP/APK sin libapp.so/libflutter.so: no parece una app Flutter",
                    "limitations": ["solo lectura estatica; no se ejecuta nada"]}
    else:
        try:
            with open(path, "rb") as f:
                data = f.read(256 * 1024 * 1024)
        except Exception as e:
            return {"ok": False, "tool": "flutter", "note": f"no se pudo leer: {e}"}
        payloads = [(path.rsplit("/", 1)[-1], data)]

    libs = [_analyze_payload(d, name) for name, d in payloads]
    is_flutter = any(l["is_dart_aot"] for l in libs) or any("flutter" in l["name"].lower() for l in libs)
    all_hashes = sorted({h for l in libs for h in l["snapshot_hashes"]})
    return {
        "ok": True, "tool": "flutter", "is_flutter": is_flutter,
        "libraries": libs, "snapshot_hashes": all_hashes,
        "note": ("app Flutter/Dart AOT detectada" if is_flutter
                 else "sin evidencia de payload Flutter/Dart AOT"),
        "limitations": ["solo lectura estatica (observacion de bytes); no se ejecuta nada",
                        "el hash de snapshot fija la revision del SDK/engine pero no se resuelve online"],
    }


def inspect_dart_aot(path: str) -> dict:
    """inspect_dart_aot: focus on the AOT snapshot layout of a single Dart library (libapp.so) --
    the four _kDart*Snapshot* symbols, snapshot magics/hashes and build-id."""
    try:
        with open(path, "rb") as f:
            data = f.read(256 * 1024 * 1024)
    except Exception as e:
        return {"ok": False, "tool": "dart_aot", "note": f"no se pudo leer: {e}"}
    if data[:4] == b"PK\x03\x04":
        payloads = [p for p in _payloads_from_apk(path) if p[0].endswith("libapp.so")]
        if not payloads:
            return {"ok": True, "tool": "dart_aot", "is_dart_aot": False,
                    "note": "APK sin libapp.so: no hay snapshot AOT de Dart que inspeccionar",
                    "limitations": ["solo lectura estatica; no se ejecuta nada"]}
        name, data = payloads[0]
    else:
        name = path.rsplit("/", 1)[-1]
    info = _analyze_payload(data, name)
    info.update({
        "ok": True, "tool": "dart_aot",
        "note": ("snapshot AOT de Dart presente" if info["is_dart_aot"]
                 else "no se detecto snapshot AOT de Dart (¿JIT o no-Dart?)"),
        "limitations": ["solo lectura estatica (observacion de bytes); no se ejecuta nada"],
    })
    return info


def render_flutter(r: dict) -> str:
    out = ["## Flutter / Dart AOT (lectura estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    out.append(f"- app Flutter: **{'SI' if r.get('is_flutter') else 'no'}**")
    if r.get("snapshot_hashes"):
        out.append(f"- hashes de snapshot Dart: `{', '.join(r['snapshot_hashes'][:4])}`"
                   + (" …" if len(r["snapshot_hashes"]) > 4 else ""))
    for lib in r.get("libraries", []):
        out.append(f"\n### {lib['name']}")
        out.append(f"- AOT Dart: {'si' if lib['is_dart_aot'] else 'no'}"
                   f" | magics snapshot: {lib['dart_snapshot_sources']}")
        if lib.get("aot_snapshot_symbols"):
            out.append(f"- simbolos AOT: `{', '.join(lib['aot_snapshot_symbols'])}`")
        if lib.get("gnu_build_id"):
            out.append(f"- build-id GNU: `{lib['gnu_build_id']}`")
        if lib.get("dart_vm_version"):
            out.append(f"- Dart VM: `{lib['dart_vm_version']}`")
    out.append("- " + r.get("note", ""))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)


def render_dart_aot(r: dict) -> str:
    out = ["## Dart AOT snapshot (lectura estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    out.append(f"- `{r.get('name')}` — AOT Dart: **{'SI' if r.get('is_dart_aot') else 'no'}**")
    if r.get("aot_snapshot_symbols"):
        out.append(f"- simbolos de snapshot: `{', '.join(r['aot_snapshot_symbols'])}`")
    out.append(f"- magics de snapshot: {r.get('dart_snapshot_sources', 0)}")
    if r.get("snapshot_hashes"):
        out.append(f"- hashes: `{', '.join(r['snapshot_hashes'][:4])}`")
    if r.get("gnu_build_id"):
        out.append(f"- build-id GNU: `{r['gnu_build_id']}`")
    if r.get("dart_vm_version"):
        out.append(f"- Dart VM: `{r['dart_vm_version']}`")
    out.append("- " + r.get("note", ""))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
