"""Static SQLite database reader: schema (tables, columns, indexes, views, triggers) + row peek.

Opens a `.sqlite`/`.db` file READ-ONLY (sqlite3 immutable URI) and reports its schema and a bounded
sample of ordinary-table rows -- no writes, no triggers fired, no attached databases. A grounded
way to understand what an app stores. Uses Python's built-in sqlite3 (no external dependency).
Design adapted from REA's SQLite tooling (morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

_MAGIC = b"SQLite format 3\x00"
_MAX_ROWS = 20


def inspect_sqlite(path: str, rows_per_table: int = 5) -> dict:
    """Return the schema + a small row sample. Opens read-only/immutable; never modifies the file."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except Exception as e:
        return {"ok": False, "is_sqlite": False, "note": f"no se pudo leer: {e}"}
    if head != _MAGIC:
        return {"ok": True, "is_sqlite": False, "note": "sin cabecera 'SQLite format 3' (no es SQLite)"}
    import os
    import sqlite3
    rows_per_table = max(0, min(int(rows_per_table or 0), _MAX_ROWS))
    uri = "file:" + os.path.abspath(path).replace("?", "%3f") + "?mode=ro&immutable=1"
    try:
        con = sqlite3.connect(uri, uri=True, timeout=2)
    except Exception as e:
        return {"ok": True, "is_sqlite": True, "note": f"no se pudo abrir read-only: {e}"}
    try:
        cur = con.cursor()
        objs = cur.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").fetchall()
        tables, views, indexes, triggers = [], [], [], []
        for otype, name, tbl, sql in objs:
            if otype == "table":
                cols = []
                try:
                    for cid, cname, ctype, notnull, dflt, pk in cur.execute(
                            f'PRAGMA table_info("{name}")').fetchall():
                        cols.append({"name": cname, "type": ctype, "notnull": bool(notnull),
                                     "pk": bool(pk)})
                except Exception:
                    pass
                count = None
                try:
                    count = cur.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
                except Exception:
                    pass
                sample = []
                if rows_per_table:
                    try:
                        colnames = [c["name"] for c in cols]
                        for r in cur.execute(f'SELECT * FROM "{name}" LIMIT {rows_per_table}').fetchall():
                            sample.append({colnames[i] if i < len(colnames) else str(i):
                                           _cell(v) for i, v in enumerate(r)})
                    except Exception:
                        pass
                tables.append({"name": name, "columns": cols, "row_count": count, "sample": sample})
            elif otype == "view":
                views.append({"name": name, "sql": sql})
            elif otype == "index":
                indexes.append({"name": name, "table": tbl})
            elif otype == "trigger":
                triggers.append({"name": name, "table": tbl})
        return {"ok": True, "is_sqlite": True, "tables": tables, "views": views,
                "indexes": indexes, "triggers": triggers,
                "limitations": ["abierto en modo solo-lectura/immutable; sin ejecutar triggers ni "
                                "adjuntar otras bases; muestra de filas acotada"]}
    except Exception as e:
        return {"ok": True, "is_sqlite": True, "note": f"error leyendo el esquema: {e}"}
    finally:
        try:
            con.close()
        except Exception:
            pass


def _cell(v):
    if isinstance(v, bytes):
        return f"<blob {len(v)}B>"
    s = str(v)
    return s if len(s) <= 120 else s[:117] + "..."


def render_sqlite(r: dict) -> str:
    out = ["## Inspeccion de base SQLite (estatica, solo lectura)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_sqlite"):
        return "\n".join(out + ["- No es una base SQLite: " + r.get("note", "")])
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    tables = r.get("tables") or []
    out.append(f"- tablas: {len(tables)}  |  vistas: {len(r.get('views') or [])}  |  "
               f"indices: {len(r.get('indexes') or [])}  |  triggers: {len(r.get('triggers') or [])}")
    for t in tables:
        cols = ", ".join(f"{c['name']}:{c['type']}" + ("(pk)" if c["pk"] else "") for c in t["columns"])
        out.append(f"\n### tabla `{t['name']}` ({t.get('row_count')} filas)")
        out.append(f"- columnas: {cols}")
        for row in (t.get("sample") or [])[:5]:
            out.append(f"  - {row}")
    for v in (r.get("views") or [])[:20]:
        out.append(f"\n### vista `{v['name']}`\n```sql\n{(v.get('sql') or '').strip()[:300]}\n```")
    tg = r.get("triggers") or []
    if tg:
        out.append("\n### triggers: " + ", ".join(f"`{t['name']}`(on {t['table']})" for t in tg))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
