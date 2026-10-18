"""Static EVM bytecode reader: function selectors, opcode capabilities, Solidity metadata.

Parses EVM runtime bytecode (raw bytes or a hex string) with no external library and nothing
executed. Extracts: the 4-byte function selectors the dispatcher compares (a PUSH4 heuristic --
grounded but not a full symbolic recovery like evmole), capability-relevant opcodes (CALL,
DELEGATECALL, CREATE/CREATE2, SELFDESTRUCT, SSTORE), and the Solidity metadata CBOR trailer the
compiler appends (solc version, IPFS/Swarm source hash). Heuristic limits are reported. Design
adapted from REA's EVM tooling (morluto/rea, MIT); the selector/metadata parsing here is a
self-contained re-implementation (REA uses the external `evmole` for full argument/mutability
recovery, which this does not attempt)."""
from __future__ import annotations

# opcodes of interest for a capability read
_OPS = {0xF1: "CALL", 0xF2: "CALLCODE", 0xF4: "DELEGATECALL", 0xFA: "STATICCALL",
        0xF0: "CREATE", 0xF5: "CREATE2", 0xFF: "SELFDESTRUCT", 0x55: "SSTORE", 0xF3: "RETURN"}


def _load_bytecode(path: str):
    from ._artifact import read_bounded
    raw = read_bounded(path)
    stripped = raw.strip()
    # accept a hex string (optionally 0x-prefixed) or raw bytes
    text = stripped.decode("ascii", "ignore") if stripped else ""
    hexchars = set(b"0123456789abcdefABCDEF")
    body = stripped[2:] if stripped[:2] in (b"0x", b"0X") else stripped
    if body and len(body) % 2 == 0 and all(c in hexchars for c in body):
        try:
            return bytes.fromhex(body.decode("ascii"))
        except Exception:
            pass
    return raw


def _extract_selectors(code: bytes):
    """Collect 4-byte selectors pushed with PUSH4 (0x63). Respects PUSH operands so we don't read a
    selector out of PUSH data. Heuristic: a dispatcher compares each selector with EQ before a
    JUMPI, but we report every PUSH4 value (deduped) as a candidate."""
    sels = []
    seen = set()
    i = 0
    n = len(code)
    while i < n:
        op = code[i]
        if op == 0x63 and i + 5 <= n:            # PUSH4 <4 bytes>
            val = code[i + 1:i + 5]
            h = "0x" + val.hex()
            if h not in seen:
                seen.add(h)
                sels.append(h)
            i += 5
            continue
        if 0x60 <= op <= 0x7F:                   # PUSH1..PUSH32: skip operand bytes
            i += 1 + (op - 0x5F)
            continue
        i += 1
    return sels


def _cbor_metadata(code: bytes):
    """Parse the Solidity metadata CBOR trailer: <cbor map><2-byte big-endian cbor length>."""
    if len(code) < 4:
        return None
    clen = int.from_bytes(code[-2:], "big")
    if clen <= 0 or clen + 2 > len(code):
        return None
    blob = code[-2 - clen:-2]
    try:
        m, _ = _cbor_value(blob, 0)
    except Exception:
        return None
    if not isinstance(m, dict):
        return None
    out = {}
    for k, v in m.items():
        if k == "solc" and isinstance(v, (bytes, bytearray)) and len(v) == 3:
            out["solc"] = f"{v[0]}.{v[1]}.{v[2]}"
        elif k in ("ipfs", "bzzr0", "bzzr1") and isinstance(v, (bytes, bytearray)):
            out[k] = v.hex()
        elif isinstance(v, (bytes, bytearray)):
            out[k] = v.hex()
        else:
            out[k] = v
    return out or None


def _cbor_value(b: bytes, off: int):
    first = b[off]
    major = first >> 5
    info = first & 0x1F
    off += 1
    if info < 24:
        arg = info
    elif info == 24:
        arg = b[off]; off += 1
    elif info == 25:
        arg = int.from_bytes(b[off:off + 2], "big"); off += 2
    elif info == 26:
        arg = int.from_bytes(b[off:off + 4], "big"); off += 4
    elif info == 27:
        arg = int.from_bytes(b[off:off + 8], "big"); off += 8
    else:
        raise ValueError("cbor arg no soportado")
    if major == 0:
        return arg, off
    if major == 1:
        return -1 - arg, off
    if major == 2:                               # byte string
        return b[off:off + arg], off + arg
    if major == 3:                               # text string
        return b[off:off + arg].decode("utf-8", "replace"), off + arg
    if major == 4:                               # array
        out = []
        for _ in range(arg):
            v, off = _cbor_value(b, off)
            out.append(v)
        return out, off
    if major == 5:                               # map
        out = {}
        for _ in range(arg):
            k, off = _cbor_value(b, off)
            v, off = _cbor_value(b, off)
            out[k] = v
        return out, off
    if major == 7:
        return {20: False, 21: True, 22: None}.get(info, arg), off
    raise ValueError("cbor major no soportado")


def inspect_evm(path: str) -> dict:
    """Parse EVM runtime bytecode. Returns {ok, selectors, opcodes, metadata, ...}."""
    try:
        code = _load_bytecode(path)
    except Exception as e:
        return {"ok": False, "note": f"no se pudo leer: {e}"}
    if not code:
        return {"ok": True, "is_evm": False, "note": "vacio"}
    selectors = _extract_selectors(code)
    caps, i, n = {}, 0, len(code)
    while i < n:
        op = code[i]
        if op in _OPS:
            caps[_OPS[op]] = caps.get(_OPS[op], 0) + 1
        if 0x60 <= op <= 0x7F:
            i += 1 + (op - 0x5F)
            continue
        i += 1
    metadata = _cbor_metadata(code)
    return {"ok": True, "is_evm": True, "size": len(code), "selectors": selectors,
            "opcodes": caps, "metadata": metadata,
            "limitations": ["selectores por heuristica PUSH4 (no recuperacion simbolica de "
                            "argumentos/mutabilidad; eso requiere evmole)"]}


def render_evm(r: dict) -> str:
    out = ["## Inspeccion de bytecode EVM (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_evm"):
        return "\n".join(out + ["- " + r.get("note", "")])
    out.append(f"- tamano: {r.get('size')} bytes")
    sels = r.get("selectors") or []
    out.append(f"- selectores de funcion (PUSH4): {len(sels)}")
    for s in sels[:60]:
        out.append(f"  - {s}")
    caps = r.get("opcodes") or {}
    if caps:
        out.append("- capacidades (opcodes): " + ", ".join(f"{k}x{v}" for k, v in caps.items()))
    md = r.get("metadata")
    if md:
        out.append("\n### Metadata de Solidity (CBOR)")
        for k, v in md.items():
            out.append(f"- {k}: {v}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
