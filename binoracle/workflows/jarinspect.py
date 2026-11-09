"""Static Java reader: JAR archives and standalone .class files.

Reads a Java artifact with no JVM and nothing executed. For a JAR (a ZIP) it parses
META-INF/MANIFEST.MF (Main-Class, versions, Class-Path), inventories the .class entries and their
packages, detects the embedded framework by package prefix (Spring, Jakarta/Java EE, Kotlin,
Scala, Android), flags signing (META-INF/*.RSA|DSA|EC), and reads the bytecode major version from
the first class to report the Java release it targets. For a standalone .class file it reads the
magic/version and the class/super names from the constant pool. Bytecode method bodies are not
disassembled (that needs a decompiler like CFR/Procyon); that limit is reported. The .class magic
0xCAFEBABE collides with the Mach-O fat magic, so detection disambiguates by the version field.
Design adapted from REA's JVM tooling (morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

# constant-pool tags we need to resolve a class name
_CONSTANT_UTF8 = 1
_CONSTANT_CLASS = 7
# tag -> number of bytes to skip (for tags we don't resolve); None = special handling
_TAG_SIZE = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4,
             15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}

_JAVA_VERSION = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6", 51: "7",
                 52: "8", 53: "9", 54: "10", 55: "11", 56: "12", 57: "13", 58: "14",
                 59: "15", 60: "16", 61: "17", 62: "18", 63: "19", 64: "20", 65: "21",
                 66: "22", 67: "23", 68: "24"}

_FRAMEWORK_PREFIXES = [
    ("org/springframework/", "Spring"), ("jakarta/", "Jakarta EE"), ("javax/", "Java EE (javax)"),
    ("kotlin/", "Kotlin"), ("scala/", "Scala"), ("android/", "Android"),
    ("com/android/", "Android"), ("org/apache/", "Apache Commons/libs"),
    ("io/netty/", "Netty"), ("com/google/gson/", "Gson"), ("org/hibernate/", "Hibernate"),
]


def _parse_class_header(data: bytes) -> dict:
    """Read magic/version and (this_class, super_class) names from a .class constant pool."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return {"is_class": False}
    minor = int.from_bytes(data[4:6], "big")
    major = int.from_bytes(data[6:8], "big")
    cp_count = int.from_bytes(data[8:10], "big")
    off = 10
    utf8 = {}
    class_ref = {}
    idx = 1
    try:
        while idx < cp_count:
            tag = data[off]
            off += 1
            if tag == _CONSTANT_UTF8:
                ln = int.from_bytes(data[off:off + 2], "big")
                off += 2
                utf8[idx] = data[off:off + ln].decode("utf-8", "replace")
                off += ln
            elif tag == _CONSTANT_CLASS:
                class_ref[idx] = int.from_bytes(data[off:off + 2], "big")
                off += 2
            elif tag in (5, 6):                 # long/double take two cp slots
                off += _TAG_SIZE[tag]
                idx += 1
            else:
                off += _TAG_SIZE.get(tag, 0)
            idx += 1
    except Exception:
        pass
    this_name = super_name = None
    try:
        # after the constant pool: access_flags(2), this_class(2), super_class(2)
        this_idx = int.from_bytes(data[off + 2:off + 4], "big")
        super_idx = int.from_bytes(data[off + 4:off + 6], "big")
        this_name = utf8.get(class_ref.get(this_idx))
        super_name = utf8.get(class_ref.get(super_idx))
    except Exception:
        pass
    return {"is_class": True, "minor": minor, "major": major,
            "java_version": _JAVA_VERSION.get(major, f"major {major}"),
            "this_class": this_name, "super_class": super_name}


def inspect_jar(path: str) -> dict:
    """Read a JAR (zip) or a standalone .class. Returns {ok, kind, ...}."""
    import zipfile
    from ._artifact import read_bounded, ArtifactTooLarge
    # standalone .class?
    try:
        head = read_bounded(path, cap=64 * 1024 * 1024)
    except ArtifactTooLarge:
        head = None
    except Exception as e:
        return {"ok": False, "note": f"no se pudo leer: {e}"}
    if head is not None and head[:4] == b"\xca\xfe\xba\xbe" \
            and 43 <= int.from_bytes(head[6:8], "big") <= 75:
        ch = _parse_class_header(head)
        if ch.get("is_class"):
            ch.update({"ok": True, "kind": "class",
                       "limitations": ["solo cabecera/constant-pool; no se desensambla el bytecode "
                                       "(requiere un decompilador como CFR/Procyon)"]})
            return ch
    # JAR / ZIP
    try:
        if not zipfile.is_zipfile(path):
            return {"ok": True, "kind": "unknown", "note": "ni .class ni ZIP/JAR"}
        zf = zipfile.ZipFile(path)
    except Exception as e:
        return {"ok": False, "note": f"no se pudo abrir: {e}"}
    try:
        names = zf.namelist()
        classes = [n for n in names if n.endswith(".class")]
        if not classes and "META-INF/MANIFEST.MF" not in names:
            return {"ok": True, "kind": "zip", "note": "ZIP sin .class ni manifiesto (no es un JAR)"}
        manifest = {}
        if "META-INF/MANIFEST.MF" in names:
            try:
                for line in zf.read("META-INF/MANIFEST.MF").decode("utf-8", "replace").splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        manifest[k.strip()] = v.strip()
            except Exception:
                pass
        packages = {}
        frameworks = set()
        for c in classes:
            pkg = c.rsplit("/", 1)[0] if "/" in c else "(default)"
            packages[pkg] = packages.get(pkg, 0) + 1
            for prefix, fw in _FRAMEWORK_PREFIXES:
                if c.startswith(prefix):
                    frameworks.add(fw)
        bytecode = None
        if classes:
            try:
                bytecode = _parse_class_header(zf.read(classes[0]))
            except Exception:
                bytecode = None
        signing = sorted(n for n in names if n.startswith("META-INF/")
                         and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF")))
        top_pkgs = sorted(packages.items(), key=lambda kv: -kv[1])[:30]
        return {"ok": True, "kind": "jar", "entry_count": len(names), "class_count": len(classes),
                "manifest": {k: manifest[k] for k in
                             ("Main-Class", "Manifest-Version", "Implementation-Title",
                              "Implementation-Version", "Created-By", "Class-Path", "Bundle-Name")
                             if k in manifest},
                "main_class": manifest.get("Main-Class"),
                "packages": dict(top_pkgs), "package_count": len(packages),
                "frameworks": sorted(frameworks), "signing": signing,
                "bytecode": bytecode,
                "limitations": ["se inventaria el JAR y se lee la version de bytecode; NO se "
                                "desensambla ni decompila el codigo (requiere CFR/Procyon/javap)"]}
    except Exception as e:
        return {"ok": True, "kind": "jar", "note": f"JAR malformado: {e}"}
    finally:
        try:
            zf.close()
        except Exception:
            pass


def render_jar(r: dict) -> str:
    out = ["## Inspeccion de Java (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    kind = r.get("kind")
    if kind == "class":
        out.append("- tipo: fichero .class suelto")
        out.append(f"- version de bytecode: major {r.get('major')} → Java {r.get('java_version')}")
        if r.get("this_class"):
            out.append(f"- clase: `{r['this_class']}`")
        if r.get("super_class"):
            out.append(f"- superclase: `{r['super_class']}`")
        for lim in r.get("limitations", []):
            out.append(f"\n_limite: {lim}_")
        return "\n".join(out)
    if kind != "jar":
        return "\n".join(out + ["- " + r.get("note", "no es un JAR")])
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    out.append(f"- entradas: {r.get('entry_count')}  |  clases: {r.get('class_count')}  |  "
               f"paquetes: {r.get('package_count')}")
    if r.get("main_class"):
        out.append(f"- **Main-Class: {r['main_class']}**")
    bc = r.get("bytecode") or {}
    if bc.get("is_class"):
        out.append(f"- version de bytecode: major {bc.get('major')} → Java {bc.get('java_version')}")
    if r.get("frameworks"):
        out.append(f"- framework detectado: **{', '.join(r['frameworks'])}**")
    man = r.get("manifest") or {}
    if man:
        out.append("\n### MANIFEST.MF")
        for k, v in man.items():
            out.append(f"- {k}: {v}")
    pkgs = r.get("packages") or {}
    if pkgs:
        out.append(f"\n### Paquetes principales ({r.get('package_count')})")
        for p, n in list(pkgs.items())[:20]:
            out.append(f"- {p} ({n})")
    sig = r.get("signing") or []
    out.append(f"\n- firma JAR: {', '.join(sig) if sig else 'no firmado'}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
