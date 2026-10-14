"""Flutter / Dart AOT static reader (no execution).

Flutter apps ship a Dart Ahead-Of-Time (AOT) runtime: the engine `libflutter.so` plus the compiled
app `libapp.so`, whose four AOT snapshot symbols (`_kDartVmSnapshotData/Instructions`,
`_kDartIsolateSnapshotData/Instructions`) carry the program. Every fact here is an observation of
bytes at read time -- nothing is executed and nothing is looked up externally.

This reader goes to the structure, not just a byte scan:

* it parses the ELF (both section-header `.dynsym` and the PT_DYNAMIC fallback used by
  section-stripped `ET_DYN` libraries), maps each AOT symbol's virtual address through PT_LOAD to a
  file offset, and reads the **Dart snapshot header** *at that symbol* -- magic `f5 f5 dc dc`, the
  64-bit length, the 32-hex version hash at +20 (pins the exact Dart SDK/engine revision), and the
  null-terminated **features string** at +52;
* it decodes the features string into the target architecture (`x64`/`arm64`/`arm`/`ia32`/`riscv*`)
  and the runtime mode (`product`/`profile`/`release`/`jit`) -- these are read out of the snapshot,
  never guessed;
* it reads the ELF machine (`e_machine`) and bitness, the GNU build-id note, and labelled `Dart VM
  version:` strings, and honestly reports when a release engine carries no version label.

Works on a raw ELF (`libapp.so`/`libflutter.so`) or straight on an APK (ZIP): it finds the Flutter
payload libraries under `lib/<abi>/`, records the ABI, and reads them in place. Design parity with
REA's Flutter tools (morluto/rea, MIT). Input is untrusted data; the reader only reads bytes."""
from __future__ import annotations

import re
import struct
import zipfile

DART_SNAPSHOT_MAGIC = b"\xf5\xf5\xdc\xdc"
_SNAP_HASH_OFFSET = 20          # version hash sits 20 bytes after the magic
_SNAP_HASH_LEN = 32
_SNAP_FEATURES_OFFSET = 52      # null-terminated features string follows the 32-byte version hash
_HASH_RE = re.compile(rb"^[0-9a-f]{32}$")
_AOT_SYMS = (
    "_kDartVmSnapshotData", "_kDartVmSnapshotInstructions",
    "_kDartIsolateSnapshotData", "_kDartIsolateSnapshotInstructions",
)
_SNAPSHOT_DATA_SYMS = ("_kDartVmSnapshotData", "_kDartIsolateSnapshotData")
_VER_RE = re.compile(rb"Dart VM version: ([0-9][0-9A-Za-z.\-+_]{0,63})")
_FLUTTER_ENGINE_RE = re.compile(rb"Flutter[ _-]?[Ee]ngine[^\x00]{0,80}")
_MAX_HASHES = 64

# Dart target architectures as they appear (first token word) in a snapshot features string.
_DART_ARCHS = ("x64", "arm64", "arm", "ia32", "riscv32", "riscv64", "x64c", "arm64c")
_RUNTIME_MODES = ("product", "profile", "release", "debug")
# ELF e_machine -> architecture label.
_EMACHINE = {0x03: "x86", 0x3e: "x86-64", 0x28: "arm", 0xb7: "aarch64",
             0xf3: "riscv", 0x08: "mips", 0x02: "sparc", 0x14: "ppc", 0x15: "ppc64"}

_SHT_DYNSYM = 11
_SHT_STRTAB = 3
_PT_LOAD = 1
_PT_DYNAMIC = 2
_ET_DYN = 3
_DT_NULL, _DT_STRTAB, _DT_SYMTAB, _DT_STRSZ, _DT_SYMENT = 0, 5, 6, 10, 11


# --- ELF parsing (section-header dynsym + PT_DYNAMIC fallback for stripped ET_DYN) ----------------

def _parse_elf(data: bytes) -> dict | None:
    """Parse enough of an ELF to resolve dynamic symbols and map VAs to file offsets. Returns None
    for anything that is not a little-endian ELF we can read; never raises."""
    try:
        if data[:4] != b"\x7fELF":
            return None
        is64 = data[4] == 2
        if data[5] != 1:                 # little-endian only (every Flutter target is LE)
            return None
        le = "<"
        e_machine = struct.unpack_from(le + "H", data, 0x12)[0]
        if is64:
            e_phoff = struct.unpack_from(le + "Q", data, 0x20)[0]
            e_phentsize, e_phnum = struct.unpack_from(le + "HH", data, 0x36)
            e_shoff = struct.unpack_from(le + "Q", data, 0x28)[0]
            e_shentsize, e_shnum = struct.unpack_from(le + "HH", data, 0x3a)
            symsz = 24
        else:
            e_phoff = struct.unpack_from(le + "I", data, 0x1c)[0]
            e_phentsize, e_phnum = struct.unpack_from(le + "HH", data, 0x2a)
            e_shoff = struct.unpack_from(le + "I", data, 0x20)[0]
            e_shentsize, e_shnum = struct.unpack_from(le + "HH", data, 0x2e)
            symsz = 16

        segments = []                    # PT_LOAD: (vaddr, offset, filesz)
        dyn_seg = None                   # PT_DYNAMIC: (offset, filesz)
        for i in range(min(e_phnum, 4096)):
            base = e_phoff + i * e_phentsize
            if base + e_phentsize > len(data):
                break
            ptype = struct.unpack_from(le + "I", data, base)[0]
            if ptype not in (_PT_LOAD, _PT_DYNAMIC):
                continue
            if is64:
                p_offset = struct.unpack_from(le + "Q", data, base + 8)[0]
                p_vaddr = struct.unpack_from(le + "Q", data, base + 0x10)[0]
                p_filesz = struct.unpack_from(le + "Q", data, base + 0x20)[0]
            else:
                p_offset = struct.unpack_from(le + "I", data, base + 4)[0]
                p_vaddr = struct.unpack_from(le + "I", data, base + 8)[0]
                p_filesz = struct.unpack_from(le + "I", data, base + 0x10)[0]
            if ptype == _PT_LOAD:
                segments.append((p_vaddr, p_offset, p_filesz))
            elif dyn_seg is None:
                dyn_seg = (p_offset, p_filesz)

        symbols = {}                     # name -> (vaddr, size)
        # 1) section-header .dynsym (the common, non-stripped case)
        if e_shoff and e_shnum:
            for i in range(min(e_shnum, 4096)):
                sh = e_shoff + i * e_shentsize
                if sh + e_shentsize > len(data):
                    break
                if struct.unpack_from(le + "I", data, sh + 4)[0] != _SHT_DYNSYM:
                    continue
                if is64:
                    link = struct.unpack_from(le + "I", data, sh + 0x28)[0]
                    off = struct.unpack_from(le + "Q", data, sh + 0x18)[0]
                    size = struct.unpack_from(le + "Q", data, sh + 0x20)[0]
                else:
                    link = struct.unpack_from(le + "I", data, sh + 0x18)[0]
                    off = struct.unpack_from(le + "I", data, sh + 0x10)[0]
                    size = struct.unpack_from(le + "I", data, sh + 0x14)[0]
                strh = e_shoff + link * e_shentsize
                if strh + e_shentsize > len(data):
                    continue
                if is64:
                    str_off = struct.unpack_from(le + "Q", data, strh + 0x18)[0]
                    str_size = struct.unpack_from(le + "Q", data, strh + 0x20)[0]
                else:
                    str_off = struct.unpack_from(le + "I", data, strh + 0x10)[0]
                    str_size = struct.unpack_from(le + "I", data, strh + 0x14)[0]
                _read_symtab(data, le, is64, off, size, symsz, str_off, str_size, symbols)
                break
        # 2) PT_DYNAMIC fallback for section-stripped ET_DYN images
        if not symbols and dyn_seg is not None:
            tags = {}
            doff, dsz = dyn_seg
            step = 16 if is64 else 8
            b = doff
            while b + step <= doff + dsz and b + step <= len(data):
                if is64:
                    tag = struct.unpack_from(le + "Q", data, b)[0]
                    val = struct.unpack_from(le + "Q", data, b + 8)[0]
                else:
                    tag = struct.unpack_from(le + "I", data, b)[0]
                    val = struct.unpack_from(le + "I", data, b + 4)[0]
                if tag == _DT_NULL:
                    break
                if tag in (_DT_STRTAB, _DT_SYMTAB, _DT_STRSZ, _DT_SYMENT):
                    tags[tag] = val
                b += step
            if _DT_SYMTAB in tags and _DT_STRTAB in tags and _DT_STRSZ in tags:
                sym_off = _va_to_off(segments, tags[_DT_SYMTAB], symsz)
                str_off = _va_to_off(segments, tags[_DT_STRTAB], tags[_DT_STRSZ])
                if sym_off is not None and str_off is not None:
                    # size unknown; walk until the string table or EOF
                    approx = min(len(data) - sym_off, 200000)
                    _read_symtab(data, le, is64, sym_off, approx, symsz,
                                 str_off, tags[_DT_STRSZ], symbols)

        return {"is64": is64, "le": le, "e_machine": e_machine,
                "arch": _EMACHINE.get(e_machine, "0x%x" % e_machine),
                "bits": 64 if is64 else 32, "segments": segments, "symbols": symbols}
    except Exception:
        return None


def _read_symtab(data, le, is64, off, size, symsz, str_off, str_size, out):
    """Fill `out` with name -> (st_value, st_size) from one symbol table."""
    try:
        strtab = data[str_off:str_off + str_size]
        n = min(size // symsz, 200000) if symsz else 0
        for s in range(n):
            e = off + s * symsz
            if e + symsz > len(data):
                break
            st_name = struct.unpack_from(le + "I", data, e)[0]
            if is64:
                st_value = struct.unpack_from(le + "Q", data, e + 8)[0]
                st_size = struct.unpack_from(le + "Q", data, e + 16)[0]
            else:
                st_value = struct.unpack_from(le + "I", data, e + 4)[0]
                st_size = struct.unpack_from(le + "I", data, e + 8)[0]
            end = strtab.find(b"\x00", st_name)
            if end > st_name:
                name = strtab[st_name:end].decode("latin1", "replace")
                if name and name not in out:
                    out[name] = (st_value, st_size)
    except Exception:
        pass


def _va_to_off(segments, vaddr: int, size: int):
    """Map a virtual address (+size) to a file offset through the PT_LOAD segments."""
    for (seg_va, seg_off, seg_filesz) in segments:
        if seg_va <= vaddr and vaddr - seg_va <= seg_filesz and size <= seg_filesz - (vaddr - seg_va):
            return seg_off + (vaddr - seg_va)
    return None


# --- Dart snapshot header -------------------------------------------------------------------------

def _parse_snapshot_at(data: bytes, off: int) -> dict | None:
    """Parse a Dart snapshot header at file offset `off`: magic, length, version hash, features."""
    if off < 0 or data[off:off + 4] != DART_SNAPSHOT_MAGIC:
        return None
    length = None
    if off + 12 <= len(data):
        length = struct.unpack_from("<q", data, off + 4)[0]
    hv = data[off + _SNAP_HASH_OFFSET:off + _SNAP_HASH_OFFSET + _SNAP_HASH_LEN]
    version = hv.decode("latin1") if _HASH_RE.match(hv) else None
    fstart = off + _SNAP_FEATURES_OFFSET
    fend = data.find(b"\x00", fstart, fstart + 512)
    features = data[fstart:fend].decode("latin1", "replace") if fend > fstart else None
    arch, mode, flags = _parse_features(features)
    return {"offset": off, "length": length, "version_hash": version,
            "features": features, "architecture": arch, "runtime_mode": mode, "flags": flags}


def _parse_features(features: str | None):
    """Pull the target architecture and runtime mode out of a snapshot features string."""
    if not features:
        return None, None, []
    toks = features.split()
    arch = None
    for t in toks:
        base = t.split("-")[0]           # e.g. 'x64-sysv' -> 'x64'
        if base in _DART_ARCHS:
            arch = base
            break
    mode = None
    for m in _RUNTIME_MODES:
        if m in toks:
            mode = m
            break
    if mode is None:
        mode = "release/jit"             # no explicit product/profile token -> release or JIT build
    return arch, mode, toks[:40]


def _scan_snapshot_hashes(data: bytes) -> tuple[list[str], int]:
    """Distinct 32-hex hashes that follow each Dart snapshot magic, in first-seen order (fallback)."""
    hashes, seen, sources = [], set(), 0
    idx = data.find(DART_SNAPSHOT_MAGIC)
    while idx != -1:
        sources += 1
        cand = data[idx + _SNAP_HASH_OFFSET:idx + _SNAP_HASH_OFFSET + _SNAP_HASH_LEN]
        if len(cand) == _SNAP_HASH_LEN and _HASH_RE.match(cand):
            h = cand.decode("latin1")
            if h not in seen and len(hashes) < _MAX_HASHES:
                seen.add(h)
                hashes.append(h)
        idx = data.find(DART_SNAPSHOT_MAGIC, idx + 4)
    return hashes, sources


def _gnu_build_id(data: bytes) -> str | None:
    """Pull the GNU build-id from a .note.gnu.build-id note (namesz=4, type=3, name='GNU\\0')."""
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


# --- payload analysis -----------------------------------------------------------------------------

def _analyze_payload(data: bytes, label: str, abi: str = None) -> dict:
    """Read all Flutter/Dart facts out of one in-memory library image."""
    elf = _parse_elf(data)
    syms = elf["symbols"] if elf else {}
    aot_syms = sorted(s for s in _AOT_SYMS if s in syms)

    # Parse each snapshot header precisely at its data symbol, when we resolved the symbol + segments.
    snapshots = []
    if elf:
        for sname in _SNAPSHOT_DATA_SYMS:
            if sname in syms:
                vaddr, _size = syms[sname]
                off = _va_to_off(elf["segments"], vaddr, 4)
                snap = _parse_snapshot_at(data, off) if off is not None else None
                if snap:
                    snap["symbol"] = sname
                    snapshots.append(snap)

    hashes, sources = _scan_snapshot_hashes(data)   # whole-file fallback / corroboration
    for s in snapshots:                             # prefer header-parsed hashes, keep order/uniqueness
        if s.get("version_hash") and s["version_hash"] not in hashes:
            hashes.insert(0, s["version_hash"])

    ver = _VER_RE.search(data)
    eng = _FLUTTER_ENGINE_RE.search(data)
    arch = next((s["architecture"] for s in snapshots if s.get("architecture")), None)
    mode = next((s["runtime_mode"] for s in snapshots if s.get("runtime_mode")), None)
    return {
        "name": label, "abi": abi,
        "is_elf": data[:4] == b"\x7fELF",
        "elf_arch": elf["arch"] if elf else None,
        "elf_bits": elf["bits"] if elf else None,
        "dart_target_arch": arch,
        "dart_runtime_mode": mode,
        "dart_snapshot_sources": sources,
        "snapshots": snapshots,
        "snapshot_hashes": hashes,
        "aot_snapshot_symbols": aot_syms,
        "is_dart_aot": len(aot_syms) >= 2 or sources > 0,
        "gnu_build_id": _gnu_build_id(data),
        "dart_vm_version": ver.group(1).decode("latin1") if ver else None,
        "dart_version_capped": ver is None and (len(aot_syms) >= 2 or sources > 0),
        "flutter_engine": eng.group(0).decode("latin1", "replace")[:80] if eng else None,
    }


def _abi_of(path: str) -> str | None:
    """Pull the Android ABI out of an APK member path like lib/arm64-v8a/libapp.so."""
    parts = path.split("/")
    if len(parts) >= 3 and parts[0] == "lib":
        return parts[1]
    return None


def _payloads_from_apk(path: str) -> list[tuple[str, bytes, str]]:
    """Return (member, bytes, abi) for each Flutter payload library inside an APK/ZIP."""
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                base = info.filename.rsplit("/", 1)[-1]
                if base in ("libapp.so", "libflutter.so") and info.file_size <= 256 * 1024 * 1024:
                    with z.open(info) as f:
                        out.append((info.filename, f.read(), _abi_of(info.filename)))
    except Exception:
        pass
    return out


def inspect_flutter(path: str) -> dict:
    """identify_flutter_build: is this a Flutter app, which build, which ABIs? Reads libapp.so/
    libflutter.so from an APK, or treats the file as a single Flutter payload ELF. Nothing executed;
    honest degradation when no Flutter payload is present."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except Exception as e:
        return {"ok": False, "tool": "flutter", "note": f"no se pudo abrir: {e}"}

    payloads = []
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
        payloads = [(path.rsplit("/", 1)[-1], data, None)]

    libs = [_analyze_payload(d, name, abi) for name, d, abi in payloads]
    is_flutter = any(l["is_dart_aot"] for l in libs) or any("flutter" in l["name"].lower() for l in libs)
    all_hashes = sorted({h for l in libs for h in l["snapshot_hashes"]})
    abis = sorted({l["abi"] for l in libs if l.get("abi")})
    arch = next((l["dart_target_arch"] for l in libs if l.get("dart_target_arch")), None)
    mode = next((l["dart_runtime_mode"] for l in libs if l.get("dart_runtime_mode")), None)
    notes = []
    if any(l.get("dart_version_capped") for l in libs):
        notes.append("una build de release no suele traer etiqueta de version de Dart; "
                     "la ausencia se reporta, no se adivina")
    return {
        "ok": True, "tool": "flutter", "is_flutter": is_flutter,
        "libraries": libs, "snapshot_hashes": all_hashes, "abis": abis,
        "dart_target_arch": arch, "dart_runtime_mode": mode,
        "note": ("app Flutter/Dart AOT detectada" if is_flutter
                 else "sin evidencia de payload Flutter/Dart AOT"),
        "limitations": ["solo lectura estatica (observacion de bytes); no se ejecuta nada",
                        "el hash de snapshot fija la revision del SDK/engine pero no se resuelve online"]
        + notes,
    }


def inspect_dart_aot(path: str) -> dict:
    """inspect_dart_aot: the AOT snapshot layout of a single Dart library (libapp.so) -- the four
    _kDart*Snapshot* symbols, each snapshot's parsed header (version hash, features -> arch + runtime
    mode), magics, and build-id."""
    try:
        with open(path, "rb") as f:
            data = f.read(256 * 1024 * 1024)
    except Exception as e:
        return {"ok": False, "tool": "dart_aot", "note": f"no se pudo leer: {e}"}
    name = path.rsplit("/", 1)[-1]
    abi = None
    if data[:4] == b"PK\x03\x04":
        payloads = [p for p in _payloads_from_apk(path) if p[0].endswith("libapp.so")]
        if not payloads:
            return {"ok": True, "tool": "dart_aot", "is_dart_aot": False,
                    "note": "APK sin libapp.so: no hay snapshot AOT de Dart que inspeccionar",
                    "limitations": ["solo lectura estatica; no se ejecuta nada"]}
        name, data, abi = payloads[0]
    info = _analyze_payload(data, name, abi)
    info.update({
        "ok": True, "tool": "dart_aot",
        "note": ("snapshot AOT de Dart presente" if info["is_dart_aot"]
                 else "no se detecto snapshot AOT de Dart (¿JIT o no-Dart?)"),
        "limitations": ["solo lectura estatica (observacion de bytes); no se ejecuta nada"]
        + (["build de release sin etiqueta de version de Dart; ausencia reportada, no adivinada"]
           if info.get("dart_version_capped") else []),
    })
    return info


# --- rendering ------------------------------------------------------------------------------------

def _render_lib(lib: dict) -> list:
    out = [f"\n### {lib['name']}" + (f"  (abi: {lib['abi']})" if lib.get("abi") else "")]
    out.append(f"- ELF: {lib.get('elf_arch')}/{lib.get('elf_bits')}-bit | AOT Dart: "
               f"{'si' if lib['is_dart_aot'] else 'no'} | magics snapshot: {lib['dart_snapshot_sources']}")
    if lib.get("dart_target_arch") or lib.get("dart_runtime_mode"):
        out.append(f"- Dart target: {lib.get('dart_target_arch') or '?'} | modo runtime: "
                   f"{lib.get('dart_runtime_mode') or '?'}")
    if lib.get("aot_snapshot_symbols"):
        out.append(f"- simbolos AOT: `{', '.join(lib['aot_snapshot_symbols'])}`")
    for s in lib.get("snapshots", []):
        feat = (s.get("features") or "")[:120]
        out.append(f"- snapshot `{s.get('symbol')}`: hash `{s.get('version_hash')}`"
                   + (f", features: `{feat}`" if feat else ""))
    if lib.get("gnu_build_id"):
        out.append(f"- build-id GNU: `{lib['gnu_build_id']}`")
    if lib.get("dart_vm_version"):
        out.append(f"- Dart VM: `{lib['dart_vm_version']}`")
    elif lib.get("dart_version_capped"):
        out.append("- Dart VM: (sin etiqueta de version — build de release; no se adivina)")
    return out


def render_flutter(r: dict) -> str:
    out = ["## Flutter / Dart AOT (lectura estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    out.append(f"- app Flutter: **{'SI' if r.get('is_flutter') else 'no'}**")
    if r.get("abis"):
        out.append(f"- ABIs: {', '.join(r['abis'])}")
    if r.get("dart_target_arch") or r.get("dart_runtime_mode"):
        out.append(f"- Dart target: {r.get('dart_target_arch') or '?'} | modo: {r.get('dart_runtime_mode') or '?'}")
    if r.get("snapshot_hashes"):
        out.append(f"- hashes de snapshot Dart: `{', '.join(r['snapshot_hashes'][:4])}`"
                   + (" …" if len(r["snapshot_hashes"]) > 4 else ""))
    for lib in r.get("libraries", []):
        out.extend(_render_lib(lib))
    out.append("\n- " + r.get("note", ""))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)


def render_dart_aot(r: dict) -> str:
    out = ["## Dart AOT snapshot (lectura estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    out.append(f"- `{r.get('name')}`" + (f" (abi: {r['abi']})" if r.get("abi") else "")
               + f" — AOT Dart: **{'SI' if r.get('is_dart_aot') else 'no'}**")
    out.append(f"- ELF: {r.get('elf_arch')}/{r.get('elf_bits')}-bit | Dart target: "
               f"{r.get('dart_target_arch') or '?'} | modo: {r.get('dart_runtime_mode') or '?'}")
    if r.get("aot_snapshot_symbols"):
        out.append(f"- simbolos de snapshot: `{', '.join(r['aot_snapshot_symbols'])}`")
    for s in r.get("snapshots", []):
        out.append(f"- `{s.get('symbol')}` @ off {s.get('offset')}: hash `{s.get('version_hash')}`"
                   + (f" len={s.get('length')}" if s.get('length') else ""))
        if s.get("features"):
            out.append(f"    features: `{s['features'][:160]}`")
    out.append(f"- magics de snapshot: {r.get('dart_snapshot_sources', 0)}")
    if r.get("snapshot_hashes"):
        out.append(f"- hashes: `{', '.join(r['snapshot_hashes'][:4])}`")
    if r.get("gnu_build_id"):
        out.append(f"- build-id GNU: `{r['gnu_build_id']}`")
    if r.get("dart_vm_version"):
        out.append(f"- Dart VM: `{r['dart_vm_version']}`")
    elif r.get("dart_version_capped"):
        out.append("- Dart VM: (sin etiqueta — build de release; no se adivina)")
    out.append("\n- " + r.get("note", ""))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
