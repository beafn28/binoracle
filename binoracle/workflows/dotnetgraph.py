"""`.NET` type graph by token: parse the CLI metadata tables and resolve TypeDef/TypeRef tokens.

This is REA's `projectManagedApplicationGraph` done properly: it parses the `#~` metadata-tables
stream per ECMA-335 -- the heap-index sizes, the `Valid` table bitmask + row counts, every present
table's row SIZE (so later tables can be located), the coded-index encodings -- and reads the
TypeDef / TypeRef / InterfaceImpl / NestedClass tables to build a type reference graph:

* nodes: each TypeDef (internal type, `Namespace.Name`) and each TypeRef (external type + its
  resolution scope);
* edges: `extends` (a TypeDef's base type, resolving the TypeDefOrRef coded token), `implements`
  (InterfaceImpl), and `nested_in` (NestedClass).

Tokens are resolved by table+row index, not by name matching, so this is a real token-level graph.
Nothing is executed; the assembly is only read. Bounded against malformed/oversized metadata."""
from __future__ import annotations

import struct

from .dotnetinspect import _BSJB

# --- table schemas (ECMA-335 II.22) ---------------------------------------------------------------
# Column kinds: "u8","u16","u32"; ("str"/"guid"/"blob") heap index; ("t", table_id) simple index;
# ("c", coded_name) coded index.
_STR, _GUID, _BLOB = ("str",), ("guid",), ("blob",)


def _t(i):
    return ("t", i)


def _c(name):
    return ("c", name)


_SCHEMA = {
    0: ["u16", _STR, _GUID, _GUID, _GUID],                                   # Module
    1: [_c("ResolutionScope"), _STR, _STR],                                  # TypeRef
    2: ["u32", _STR, _STR, _c("TypeDefOrRef"), _t(4), _t(6)],                # TypeDef
    3: [_t(4)],                                                              # FieldPtr
    4: ["u16", _STR, _BLOB],                                                 # Field
    5: [_t(6)],                                                              # MethodPtr
    6: ["u32", "u16", "u16", _STR, _BLOB, _t(8)],                            # MethodDef
    7: [_t(8)],                                                              # ParamPtr
    8: ["u16", "u16", _STR],                                                 # Param
    9: [_t(2), _c("TypeDefOrRef")],                                          # InterfaceImpl
    10: [_c("MemberRefParent"), _STR, _BLOB],                                # MemberRef
    11: ["u16", _c("HasConstant"), _BLOB],                                   # Constant
    12: [_c("HasCustomAttribute"), _c("CustomAttributeType"), _BLOB],        # CustomAttribute
    13: [_c("HasFieldMarshal"), _BLOB],                                      # FieldMarshal
    14: ["u16", _c("HasDeclSecurity"), _BLOB],                               # DeclSecurity
    15: ["u16", "u32", _t(2)],                                               # ClassLayout
    16: ["u32", _t(4)],                                                      # FieldLayout
    17: [_BLOB],                                                             # StandAloneSig
    18: [_t(2), _t(20)],                                                     # EventMap
    19: [_t(20)],                                                            # EventPtr
    20: ["u16", _STR, _c("TypeDefOrRef")],                                   # Event
    21: [_t(2), _t(23)],                                                     # PropertyMap
    22: [_t(23)],                                                            # PropertyPtr
    23: ["u16", _STR, _BLOB],                                                # Property
    24: ["u16", _t(6), _c("HasSemantics")],                                  # MethodSemantics
    25: [_t(2), _c("MethodDefOrRef"), _c("MethodDefOrRef")],                 # MethodImpl
    26: [_STR],                                                              # ModuleRef
    27: [_BLOB],                                                             # TypeSpec
    28: ["u16", _c("MemberForwarded"), _STR, _t(26)],                        # ImplMap
    29: ["u32", _t(4)],                                                      # FieldRVA
    30: ["u32", "u32"],                                                      # EncLog
    31: ["u32"],                                                             # EncMap
    32: ["u32", "u16", "u16", "u16", "u16", "u32", _BLOB, _STR, _STR],       # Assembly
    33: ["u32"],                                                             # AssemblyProcessor
    34: ["u32", "u32", "u32"],                                               # AssemblyOS
    35: ["u16", "u16", "u16", "u16", "u32", _BLOB, _STR, _STR, _BLOB],       # AssemblyRef
    36: ["u32", _t(35)],                                                     # AssemblyRefProcessor
    37: ["u32", "u32", "u32", _t(35)],                                       # AssemblyRefOS
    38: ["u32", _STR, _BLOB],                                                # File
    39: ["u32", "u32", _STR, _STR, _c("Implementation")],                    # ExportedType
    40: ["u32", "u32", _STR, _c("Implementation")],                          # ManifestResource
    41: [_t(2), _t(2)],                                                      # NestedClass
    42: ["u16", "u16", _c("TypeOrMethodDef"), _STR],                         # GenericParam
    43: [_c("MethodDefOrRef"), _BLOB],                                       # MethodSpec
    44: [_t(42), _c("TypeDefOrRef")],                                        # GenericParamConstraint
}

# coded index -> (tag_bits, [table_id per tag, None = unused])
_CODED = {
    "TypeDefOrRef": (2, [2, 1, 27]),
    "HasConstant": (2, [4, 8, 23]),
    "HasCustomAttribute": (5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43]),
    "HasFieldMarshal": (1, [4, 8]),
    "HasDeclSecurity": (2, [2, 6, 32]),
    "MemberRefParent": (3, [2, 1, 26, 6, 27]),
    "HasSemantics": (1, [20, 23]),
    "MethodDefOrRef": (1, [6, 10]),
    "MemberForwarded": (1, [4, 6]),
    "Implementation": (2, [38, 35, 39]),
    "CustomAttributeType": (3, [None, None, 6, 10, None]),
    "ResolutionScope": (2, [0, 26, 35, 1]),
    "TypeOrMethodDef": (1, [2, 6]),
}


class _MDError(Exception):
    pass


def _streams(md: bytes) -> dict:
    """Map stream name -> (offset, size) within the metadata root blob."""
    if len(md) < 20 or struct.unpack_from("<I", md, 0)[0] != _BSJB:
        raise _MDError("sin magic BSJB")
    ver_len = struct.unpack_from("<I", md, 12)[0]
    off = 16 + ((ver_len + 3) & ~3) + 2
    nstreams = struct.unpack_from("<H", md, off)[0]
    off += 2
    out = {}
    for _ in range(nstreams):
        soff, ssize = struct.unpack_from("<II", md, off)
        off += 8
        end = md.index(b"\x00", off)
        name = md[off:end].decode("ascii", "replace")
        off = (end + 1 + 3) & ~3
        out[name] = (soff, ssize)
    return out


def _index_size(kind, rows, heap_sizes) -> int:
    if kind == "u8":
        return 1
    if kind == "u16":
        return 2
    if kind == "u32":
        return 4
    if kind == _STR:
        return 4 if (heap_sizes & 0x01) else 2
    if kind == _GUID:
        return 4 if (heap_sizes & 0x02) else 2
    if kind == _BLOB:
        return 4 if (heap_sizes & 0x04) else 2
    tag = kind[0]
    if tag == "t":
        return 4 if rows.get(kind[1], 0) >= (1 << 16) else 2
    if tag == "c":
        tag_bits, tables = _CODED[kind[1]]
        maxrows = max((rows.get(t, 0) for t in tables if t is not None), default=0)
        return 2 if maxrows < (1 << (16 - tag_bits)) else 4
    raise _MDError(f"columna desconocida: {kind}")


def _row_size(table_id, rows, heap_sizes) -> int:
    return sum(_index_size(c, rows, heap_sizes) for c in _SCHEMA.get(table_id, []))


def _read_index(t, p, kind, rows, heap_sizes):
    sz = _index_size(kind, rows, heap_sizes)
    v = struct.unpack_from("<I" if sz == 4 else "<H", t, p)[0]
    return v, p + sz


def _decode_coded(v, coded_name):
    tag_bits, tables = _CODED[coded_name]
    tag = v & ((1 << tag_bits) - 1)
    row = v >> tag_bits
    table = tables[tag] if tag < len(tables) else None
    return table, row          # row is 1-based; 0 = null


def _str_at(strings: bytes, off: int) -> str:
    if off <= 0 or off >= len(strings):
        return ""
    end = strings.find(b"\x00", off)
    return strings[off:(end if end >= 0 else len(strings))].decode("utf-8", "replace")


def build_graph_from_metadata(md: bytes, max_types: int = 20000) -> dict:
    """Build the type graph from a metadata-root blob (from the BSJB magic onward)."""
    streams = _streams(md)
    ts = streams.get("#~") or streams.get("#-")
    if not ts:
        raise _MDError("sin stream de tablas (#~/#-)")
    t = md[ts[0]:ts[0] + ts[1]]
    if len(t) < 24:
        raise _MDError("stream de tablas truncado")
    heap_sizes = t[6]
    valid = struct.unpack_from("<Q", t, 8)[0]
    present = [i for i in range(64) if valid & (1 << i)]
    p = 24
    rows = {}
    for i in present:
        rows[i] = struct.unpack_from("<I", t, p)[0]
        p += 4
    # p now points at the first table's rows. Compute each present table's base offset.
    base = {}
    cur = p
    for i in present:
        base[i] = cur
        cur += _row_size(i, rows, heap_sizes) * rows[i]

    sidx = streams.get("#Strings")
    strings = md[sidx[0]:sidx[0] + sidx[1]] if sidx else b"\x00"

    def read_table(tid):
        if tid not in base:
            return []
        rs = _row_size(tid, rows, heap_sizes)
        out = []
        for k in range(min(rows[tid], max_types)):
            pos = base[tid] + k * rs
            cols = []
            for col in _SCHEMA[tid]:
                v, pos = _read_index(t, pos, col, rows, heap_sizes)
                cols.append((col, v))
            out.append(cols)
        return out

    # TypeRef: [ResolutionScope, Name, Namespace]
    typerefs = []
    for cols in read_table(1):
        scope = _decode_coded(cols[0][1], "ResolutionScope")
        name = _str_at(strings, cols[1][1])
        ns = _str_at(strings, cols[2][1])
        typerefs.append({"name": (f"{ns}.{name}" if ns else name), "scope": scope})

    # TypeDef: [Flags, Name, Namespace, Extends, FieldList, MethodList]
    typedefs = []
    for cols in read_table(2):
        name = _str_at(strings, cols[1][1])
        ns = _str_at(strings, cols[2][1])
        ext = _decode_coded(cols[3][1], "TypeDefOrRef")
        typedefs.append({"name": (f"{ns}.{name}" if ns else name), "extends": ext})

    def resolve(tok):
        table, row = tok
        if row == 0 or table is None:
            return None
        if table == 2 and 1 <= row <= len(typedefs):
            return {"ref": "TypeDef", "name": typedefs[row - 1]["name"]}
        if table == 1 and 1 <= row <= len(typerefs):
            return {"ref": "TypeRef", "name": typerefs[row - 1]["name"], "external": True}
        if table == 27:
            return {"ref": "TypeSpec", "name": f"<TypeSpec#{row}>"}
        return None

    edges = []
    for td in typedefs:
        tgt = resolve(td["extends"])
        if tgt and tgt["name"] not in ("System.Object", ""):
            edges.append({"from": td["name"], "to": tgt["name"], "kind": "extends",
                          "external": tgt.get("external", False)})
    # InterfaceImpl: [Class(TypeDef), Interface(TypeDefOrRef)]
    for cols in read_table(9):
        cls_row = cols[0][1]
        iface = resolve(_decode_coded(cols[1][1], "TypeDefOrRef"))
        if 1 <= cls_row <= len(typedefs) and iface:
            edges.append({"from": typedefs[cls_row - 1]["name"], "to": iface["name"],
                          "kind": "implements", "external": iface.get("external", False)})
    # NestedClass: [NestedClass(TypeDef), EnclosingClass(TypeDef)]
    for cols in read_table(41):
        nrow, erow = cols[0][1], cols[1][1]
        if 1 <= nrow <= len(typedefs) and 1 <= erow <= len(typedefs):
            edges.append({"from": typedefs[nrow - 1]["name"], "to": typedefs[erow - 1]["name"],
                          "kind": "nested_in", "external": False})

    return {"typedef_count": len(typedefs), "typeref_count": len(typerefs),
            "types": [td["name"] for td in typedefs][:400],
            "external_types": [tr["name"] for tr in typerefs][:400],
            "edges": edges[:4000], "edge_count": len(edges)}


# --- reusable table index (shared by the type graph and the CIL call graph) ----------------------

class _Tables:
    """Parse the #~ metadata-tables stream once and expose row reads + heap/coded helpers."""

    def __init__(self, md: bytes):
        self.md = md
        streams = _streams(md)
        ts = streams.get("#~") or streams.get("#-")
        if not ts:
            raise _MDError("sin stream de tablas (#~/#-)")
        self.t = md[ts[0]:ts[0] + ts[1]]
        if len(self.t) < 24:
            raise _MDError("stream de tablas truncado")
        self.heap_sizes = self.t[6]
        valid = struct.unpack_from("<Q", self.t, 8)[0]
        self.present = [i for i in range(64) if valid & (1 << i)]
        p = 24
        self.rows = {}
        for i in self.present:
            self.rows[i] = struct.unpack_from("<I", self.t, p)[0]
            p += 4
        self.base = {}
        cur = p
        for i in self.present:
            self.base[i] = cur
            cur += _row_size(i, self.rows, self.heap_sizes) * self.rows[i]
        sidx = streams.get("#Strings")
        self.strings = md[sidx[0]:sidx[0] + sidx[1]] if sidx else b"\x00"

    def string(self, off):
        return _str_at(self.strings, off)

    def row(self, tid, k):
        """Read row k (0-based) of table tid as a list of (col, value). None if out of range."""
        if tid not in self.base or k < 0 or k >= self.rows[tid]:
            return None
        rs = _row_size(tid, self.rows, self.heap_sizes)
        pos = self.base[tid] + k * rs
        cols = []
        for col in _SCHEMA[tid]:
            v, pos = _read_index(self.t, pos, col, self.rows, self.heap_sizes)
            cols.append((col, v))
        return cols

    def iter_rows(self, tid, cap=200000):
        if tid not in self.base:
            return
        for k in range(min(self.rows[tid], cap)):
            yield k, self.row(tid, k)


# --- CIL method-body decoding (ECMA-335 III) ------------------------------------------------------
# Operand size (in bytes) per single-byte opcode; InlineSwitch(0x45) is special; unknown -> stop.
_OPSIZE = {}
for _o in list(range(0x00, 0x0E)) + [0x14] + list(range(0x15, 0x1F)) + [0x25, 0x26, 0x2A] + \
        list(range(0x46, 0x6F)) + [0x76, 0x7A] + list(range(0x82, 0x8D)) + [0x8E] + \
        list(range(0x90, 0xA3)) + [0xB3] + list(range(0xB4, 0xBB)) + [0xC3] + \
        list(range(0xD1, 0xDC)) + [0xDC, 0xDF, 0xE0]:
    _OPSIZE[_o] = 0
for _o in (0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x1F) + tuple(range(0x2B, 0x38)) + (0xDE,):
    _OPSIZE[_o] = 1                                 # ShortInline* (1-byte)
for _o in (0x20, 0x22, 0x27, 0x28, 0x29, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79,
           0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x8D, 0x8F, 0xA3, 0xA4, 0xA5, 0xC2,
           0xC6, 0xD0, 0xDD) + tuple(range(0x38, 0x45)):
    _OPSIZE[_o] = 4                                 # Inline* 4-byte (incl. branches/tokens)
for _o in (0x21, 0x23):
    _OPSIZE[_o] = 8                                 # InlineI8 / InlineR
# two-byte 0xFE xx
_OPSIZE_FE = {0x00: 0, 0x01: 0, 0x02: 0, 0x03: 0, 0x04: 0, 0x05: 0, 0x06: 4, 0x07: 4,
              0x09: 2, 0x0A: 2, 0x0B: 2, 0x0C: 2, 0x0D: 2, 0x0E: 2, 0x0F: 0, 0x11: 0,
              0x12: 1, 0x13: 0, 0x14: 0, 0x15: 4, 0x16: 4, 0x17: 0, 0x18: 0, 0x19: 1,
              0x1A: 0, 0x1C: 4, 0x1D: 0, 0x1E: 0}
# opcodes whose 4-byte token names a method (call family)
_CALL_OPS = {0x28, 0x6F, 0x73, 0x27}                # call, callvirt, newobj, jmp
_CALL_OPS_FE = {0x06, 0x07}                         # ldftn, ldvirtftn


def _method_body_il(body: bytes):
    """Return the IL bytecode of a method body (tiny or fat header), or b'' on a bad header."""
    if not body:
        return b""
    b0 = body[0]
    if (b0 & 0x03) == 0x02:                         # tiny format
        size = b0 >> 2
        return body[1:1 + size]
    if (b0 & 0x03) == 0x03:                         # fat format
        if len(body) < 12:
            return b""
        code_size = struct.unpack_from("<I", body, 4)[0]
        return body[12:12 + code_size]
    return b""


def _scan_il_calls(il: bytes):
    """Linear-sweep the IL, returning the metadata tokens of call/callvirt/newobj/jmp/ldftn."""
    tokens = []
    i = 0
    n = len(il)
    while i < n:
        op = il[i]
        i += 1
        if op == 0xFE:                              # two-byte opcode
            if i >= n:
                break
            op2 = il[i]
            i += 1
            sz = _OPSIZE_FE.get(op2)
            if sz is None:
                break                               # unknown -> stop (avoid desync)
            if op2 in _CALL_OPS_FE and i + 4 <= n:
                tokens.append(struct.unpack_from("<I", il, i)[0])
            i += sz
            continue
        if op == 0x45:                              # switch: uint32 N, then N*int32
            if i + 4 > n:
                break
            cnt = struct.unpack_from("<I", il, i)[0]
            i += 4 + 4 * cnt
            continue
        sz = _OPSIZE.get(op)
        if sz is None:
            break
        if op in _CALL_OPS and i + 4 <= n:
            tokens.append(struct.unpack_from("<I", il, i)[0])
        i += sz
    return tokens


def build_call_graph(tables: "_Tables", read_body, max_methods: int = 40000) -> dict:
    """Build the method call graph. `read_body(rva)` returns a method's raw body bytes (header+IL),
    or None. Tokens in call instructions are resolved by table+row to method display names."""
    # type names
    typedef_name = {}
    typedef_methodlist = []        # (methodlist_start_1based, typename) sorted
    for k, cols in tables.iter_rows(2):
        name = tables.string(cols[1][1])
        ns = tables.string(cols[2][1])
        full = f"{ns}.{name}" if ns else name
        typedef_name[k + 1] = full
        typedef_methodlist.append((cols[5][1], full))   # MethodList is col index 5
    typedef_methodlist.sort()
    typeref_name = {}
    for k, cols in tables.iter_rows(1):
        name = tables.string(cols[1][1])
        ns = tables.string(cols[2][1])
        typeref_name[k + 1] = (f"{ns}.{name}" if ns else name)

    def owner_type(method_row_1based):
        # last type whose MethodList start <= method_row
        lo, hi, found = 0, len(typedef_methodlist) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if typedef_methodlist[mid][0] <= method_row_1based:
                found = typedef_methodlist[mid][1]
                lo = mid + 1
            else:
                hi = mid - 1
        return found or "<global>"

    # MethodDef rows: (rva, name, owner)
    methods = []                   # index 0 == MethodDef row 1
    for k, cols in tables.iter_rows(6):
        rva = cols[0][1]
        name = tables.string(cols[3][1])
        methods.append({"rva": rva, "name": name, "owner": owner_type(k + 1)})

    def resolve_methodref_parent(coded_v):
        table, row = _decode_coded(coded_v, "MemberRefParent")
        if table == 2:
            return typedef_name.get(row, f"<TypeDef#{row}>")
        if table == 1:
            return typeref_name.get(row, f"<TypeRef#{row}>")
        if table == 27:
            return f"<TypeSpec#{row}>"
        if table == 26:
            return "<ModuleRef>"
        if table == 6 and 1 <= row <= len(methods):
            return methods[row - 1]["owner"]
        return "<?>"

    def resolve_token(tok):
        table = (tok >> 24) & 0xFF
        row = tok & 0x00FFFFFF
        if table == 0x06 and 1 <= row <= len(methods):      # MethodDef
            m = methods[row - 1]
            return f"{m['owner']}::{m['name']}", False
        if table == 0x0A:                                   # MemberRef
            cols = tables.row(10, row - 1)
            if cols:
                parent = resolve_methodref_parent(cols[0][1])
                return f"{parent}::{tables.string(cols[1][1])}", True
        if table == 0x2B:                                   # MethodSpec -> underlying method
            cols = tables.row(43, row - 1)
            if cols:
                mt, mr = _decode_coded(cols[0][1], "MethodDefOrRef")
                return resolve_token(((0x06 if mt == 6 else 0x0A) << 24) | mr)
        return None

    edges = []
    scanned = 0
    for m in methods[:max_methods]:
        if not m["rva"]:
            continue
        body = read_body(m["rva"])
        if not body:
            continue
        scanned += 1
        caller = f"{m['owner']}::{m['name']}"
        seen = set()
        for tok in _scan_il_calls(_method_body_il(body)):
            callee = resolve_token(tok)
            if not callee or callee[0] in seen:
                continue
            seen.add(callee[0])
            edges.append({"from": caller, "to": callee[0], "external": callee[1]})
            if len(edges) >= 20000:
                break
        if len(edges) >= 20000:
            break
    return {"method_count": len(methods), "scanned_methods": scanned,
            "edge_count": len(edges), "edges": edges[:4000],
            "callers": sorted({e["from"] for e in edges})[:400]}


def project_call_graph(path: str) -> dict:
    """CIL-level call graph: decode each method body's IL and resolve call tokens to methods."""
    try:
        import pefile
    except Exception as e:
        return {"ok": False, "tool": "dotnet_callgraph", "note": f"falta pefile: {e}"}
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]])
    except Exception as e:
        return {"ok": False, "tool": "dotnet_callgraph", "note": f"no es PE: {e}"}
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if not dd.VirtualAddress or not dd.Size:
            return {"ok": False, "tool": "dotnet_callgraph", "note": "PE nativo (no es .NET)"}
        cli = pe.get_data(dd.VirtualAddress, min(dd.Size, 72))
        md_rva, md_size = struct.unpack_from("<II", cli, 8)
        md = pe.get_data(md_rva, md_size)
        tables = _Tables(md)

        def read_body(rva):
            try:
                hdr = pe.get_data(rva, 12)
            except Exception:
                return None
            b0 = hdr[0]
            if (b0 & 0x03) == 0x02:
                size = (b0 >> 2) + 1
            elif (b0 & 0x03) == 0x03:
                size = 12 + struct.unpack_from("<I", hdr, 4)[0]
            else:
                return None
            try:
                return pe.get_data(rva, min(size, 2 * 1024 * 1024))
            except Exception:
                return None

        g = build_call_graph(tables, read_body)
    except _MDError as e:
        return {"ok": False, "tool": "dotnet_callgraph", "note": f"metadata ilegible: {e}"}
    except Exception as e:
        return {"ok": False, "tool": "dotnet_callgraph", "note": f"error: {e.__class__.__name__}"}
    finally:
        try:
            pe.close()
        except Exception:
            pass
    g.update({"ok": True, "tool": "dotnet_callgraph",
              "limitations": ["grafo de llamadas por IL (call/callvirt/newobj/jmp/ldftn), tokens "
                              "resueltos por tabla+fila; calli y llamadas por delegado/reflexion no "
                              "se resuelven; genericos via MethodSpec se mapean al metodo base"]})
    return g


def render_call_graph(r: dict) -> str:
    out = ["## Grafo de llamadas .NET (CIL, por token)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    out.append(f"- metodos: {r['method_count']} | con cuerpo escaneado: {r['scanned_methods']} | "
               f"aristas: {r['edge_count']}")
    for e in r["edges"][:60]:
        mark = " (ext)" if e.get("external") else ""
        out.append(f"  - {e['from']} -> {e['to']}{mark}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)


def _metadata_blob(path: str):
    """Extract the metadata-root blob from a managed PE via pefile. Returns (md, None) or (None, err)."""
    try:
        import pefile
    except Exception as e:
        return None, f"falta pefile: {e}"
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]])
    except Exception as e:
        return None, f"no es PE: {e}"
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if not dd.VirtualAddress or not dd.Size:
            return None, "PE nativo (sin COM descriptor / no es .NET)"
        cli = pe.get_data(dd.VirtualAddress, min(dd.Size, 72))
        md_rva, md_size = struct.unpack_from("<II", cli, 8)
        return pe.get_data(md_rva, md_size), None
    except Exception as e:
        return None, f"metadata CLI malformada: {e}"
    finally:
        try:
            pe.close()
        except Exception:
            pass


def project_type_graph(path: str) -> dict:
    """projectManagedApplicationGraph: the token-resolved type graph of a .NET assembly."""
    md, err = _metadata_blob(path)
    if md is None:
        return {"ok": False, "tool": "dotnet_graph", "note": err}
    try:
        g = build_graph_from_metadata(md)
    except _MDError as e:
        return {"ok": False, "tool": "dotnet_graph", "note": f"metadata ilegible: {e}"}
    except Exception as e:
        return {"ok": False, "tool": "dotnet_graph", "note": f"error parseando tablas: {e.__class__.__name__}"}
    g.update({"ok": True, "tool": "dotnet_graph",
              "limitations": ["grafo por token (TypeDef/TypeRef/InterfaceImpl/NestedClass) de la "
                              "metadata CLI; no sigue llamadas dentro de los cuerpos CIL",
                              "System.Object se omite como base por defecto"]})
    return g


def render_type_graph(r: dict) -> str:
    out = ["## Grafo de tipos .NET (por token)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    out.append(f"- TypeDef (internos): {r['typedef_count']} | TypeRef (externos): {r['typeref_count']} "
               f"| aristas: {r['edge_count']}")
    for e in r["edges"][:50]:
        mark = " (ext)" if e.get("external") else ""
        out.append(f"  - {e['from']} --{e['kind']}--> {e['to']}{mark}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
