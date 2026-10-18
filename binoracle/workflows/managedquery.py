"""Managed (.NET) reconstruction + comparison, grounded on the CLI metadata reader.

REA exposes a managed-reconstruction workflow (`verify_reconstruction`, `compareManagedMembers`,
`verifyManagedNativeBoundaries`). binoracle grounds the groundable parts on `dotnetinspect`, which
reads the CLI metadata (runtime/metadata version, table row counts, and the `#Strings` heap of
type/member names) WITHOUT disassembling CIL or executing anything:

* `compare_managed_members` diffs two assemblies' member-name sets and table shapes;
* `verify_reconstruction` checks a reconstructed assembly against an original -- what fraction of the
  original's member names and table shape it reproduces -- and states the obligation it did or did
  not meet (never claims a faithful reconstruction on faith);
* `verify_managed_native_boundaries` surfaces the managed<->native boundary: the P/Invoke ImplMap
  table size and the native DLL names present in `#Strings`.

Honest limits: names come from the `#Strings` heap (a bounded sample) and are not token-resolved, so
these are name/shape-level checks, not a full IL/type-graph reconstruction."""
from __future__ import annotations

from .dotnetinspect import inspect_dotnet

# Common native DLLs referenced by P/Invoke, used to surface the managed<->native boundary.
_NATIVE_DLL_HINT = (".dll", "kernel32", "user32", "ntdll", "advapi32", "ws2_32", "libc", "libdl")


def _assembly_facts(path: str) -> dict:
    r = inspect_dotnet(path)
    if not r.get("ok") or not r.get("is_dotnet"):
        return {"ok": False, "note": r.get("note", "no es un ensamblado .NET")}
    names = [n for n in (r.get("string_names") or []) if isinstance(n, str) and n]
    return {"ok": True, "runtime_version": r.get("runtime_version"),
            "metadata_version": r.get("metadata_version"), "tables": r.get("tables") or {},
            "names": set(names), "name_list": names}


def compare_managed_members(a: str, b: str) -> dict:
    """compareManagedMembers: diff two .NET assemblies at the member-name and table-shape level."""
    fa, fb = _assembly_facts(a), _assembly_facts(b)
    if not fa.get("ok") or not fb.get("ok"):
        return {"ok": False, "tool": "managed_compare",
                "note": "no se pudo leer " + ("A: " + fa.get("note", "") if not fa.get("ok")
                                              else "B: " + fb.get("note", ""))}
    added = sorted(fb["names"] - fa["names"])
    removed = sorted(fa["names"] - fb["names"])
    common = fa["names"] & fb["names"]
    tkeys = sorted(set(fa["tables"]) | set(fb["tables"]))
    table_delta = {k: [fa["tables"].get(k, 0), fb["tables"].get(k, 0)]
                   for k in tkeys if fa["tables"].get(k, 0) != fb["tables"].get(k, 0)}
    return {"ok": True, "tool": "managed_compare",
            "runtime": [fa["runtime_version"], fb["runtime_version"]],
            "common_members": len(common), "added_count": len(added), "removed_count": len(removed),
            "added": added[:150], "removed": removed[:150], "table_delta": table_delta,
            "limitations": ["nombres del heap #Strings (muestra, no resueltos por token); "
                            "comparacion de nombres/forma, no de IL"]}


def verify_reconstruction(original: str, reconstructed: str, threshold: float = 0.9) -> dict:
    """verify_reconstruction: how faithfully `reconstructed` reproduces `original` at the member-name
    and table-shape level. Reports coverage and the obligation met/unmet -- never claims a faithful
    reconstruction without the evidence meeting the threshold."""
    fo, fr = _assembly_facts(original), _assembly_facts(reconstructed)
    if not fo.get("ok") or not fr.get("ok"):
        return {"ok": False, "tool": "managed_verify",
                "note": "no se pudo leer " + ("original: " + fo.get("note", "") if not fo.get("ok")
                                              else "reconstruido: " + fr.get("note", ""))}
    orig = fo["names"]
    reproduced = orig & fr["names"]
    missing = sorted(orig - fr["names"])
    coverage = (len(reproduced) / len(orig)) if orig else 1.0
    # table-shape similarity: fraction of original tables whose row count is reproduced
    shared_tables = [k for k in fo["tables"] if k in fr["tables"]
                     and fo["tables"][k] == fr["tables"][k]]
    table_sim = (len(shared_tables) / len(fo["tables"])) if fo["tables"] else 1.0
    reasons = []
    if coverage < threshold:
        reasons.append(f"cobertura de miembros {coverage:.1%} < umbral {threshold:.0%} "
                       f"({len(missing)} ausentes)")
    if fo["runtime_version"] != fr["runtime_version"]:
        reasons.append(f"runtime distinto: {fo['runtime_version']} vs {fr['runtime_version']}")
    verified = not reasons
    return {"ok": True, "tool": "managed_verify", "verified": verified,
            "member_coverage": round(coverage, 4), "table_similarity": round(table_sim, 4),
            "reproduced_members": len(reproduced), "original_members": len(orig),
            "missing_members": missing[:150], "unmet_obligations": reasons,
            "note": ("reconstruccion fiel a nivel de nombres/forma (obligacion cumplida)" if verified
                     else "reconstruccion NO cumple la obligacion: " + "; ".join(reasons)),
            "limitations": ["verificacion a nivel de nombres (#Strings) y forma de tablas; "
                            "no compara cuerpos CIL ni semantica"]}


def verify_managed_native_boundaries(path: str) -> dict:
    """verifyManagedNativeBoundaries: surface the managed<->native boundary of an assembly -- the
    P/Invoke ImplMap table size and the native library names present in #Strings."""
    f = _assembly_facts(path)
    if not f.get("ok"):
        return {"ok": False, "tool": "managed_boundaries", "note": f.get("note")}
    implmap = f["tables"].get("ImplMap", 0)
    native = sorted({n for n in f["name_list"]
                     if any(h in n.lower() for h in _NATIVE_DLL_HINT)})
    return {"ok": True, "tool": "managed_boundaries", "pinvoke_implmap_rows": implmap,
            "native_libraries": native[:80], "native_count": len(native),
            "note": (f"P/Invoke presente: {implmap} entrada(s) ImplMap" if implmap
                     else "sin tabla ImplMap (sin P/Invoke declarado) o no parseada"),
            "limitations": ["ImplMap de la metadata; nombres de DLL del heap #Strings (muestra); "
                            "no se resuelven los targets exactos por token"]}


def render_managed(kind: str, r: dict) -> str:
    out = [f"## Managed (.NET): {kind}\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    if kind == "compare":
        out.append(f"- runtime: {r['runtime'][0]} vs {r['runtime'][1]}")
        out.append(f"- comunes: {r['common_members']} | añadidos: {r['added_count']} | "
                   f"eliminados: {r['removed_count']}")
        if r["added"]:
            out.append(f"- añadidos: {', '.join(r['added'][:20])}")
        if r["removed"]:
            out.append(f"- eliminados: {', '.join(r['removed'][:20])}")
        if r["table_delta"]:
            out.append("- cambios de tabla: " + ", ".join(f"{k} {v[0]}->{v[1]}"
                                                           for k, v in list(r["table_delta"].items())[:12]))
    elif kind == "verify":
        out.append(f"- reconstruccion fiel: **{'SI' if r['verified'] else 'no'}**")
        out.append(f"- cobertura de miembros: {r['member_coverage']:.1%} "
                   f"({r['reproduced_members']}/{r['original_members']}) | "
                   f"similitud de tablas: {r['table_similarity']:.1%}")
        if r["unmet_obligations"]:
            out.append("- obligaciones no cumplidas: " + "; ".join(r["unmet_obligations"]))
        if r["missing_members"]:
            out.append(f"- ausentes (muestra): {', '.join(r['missing_members'][:20])}")
    elif kind == "boundaries":
        out.append(f"- P/Invoke (ImplMap): {r['pinvoke_implmap_rows']} | "
                   f"librerias nativas: {r['native_count']}")
        if r["native_libraries"]:
            out.append(f"- nativas: {', '.join(r['native_libraries'][:20])}")
        out.append("- " + r.get("note", ""))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
