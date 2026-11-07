"""Universal static IOC / secret scanner: works on ANY artifact's bytes.

Extracts printable strings (ASCII and UTF-16LE) from a file without executing it and scans them for
indicators a reverse engineer wants surfaced first: embedded URLs and hostnames, IPv4 addresses,
e-mail addresses, cloud/API credentials (AWS/GCP/Slack/GitHub/Stripe), JWTs, private-key PEM
headers, high-entropy tokens that look like keys, and CTF-style flag strings. Every hit is
heuristic and labelled as such; secret values are redacted in the rendered output (flags and
URLs/emails/IPs are shown in full -- redacting them would defeat the point). This is the
cross-cutting companion to the format-specific readers -- point it at an ELF, a PE, a firmware
blob or a config dump and it tells you what secrets and network indicators are baked in. Nothing
is executed. Design adapted from REA's secret/indicator tooling (morluto/rea, MIT);
re-implemented in Python.

Gap found testing this live against a real reversing CTF binary (ShadowCTF 2021's "Intro"
warmup, not a synthetic fixture): its flag ("{steppingstone}") sits in plain sight among its
strings -- the published writeup solves it with nothing more than `strings` -- but this scanner,
built for REAL credentials (AWS/Stripe/GitHub keys...), had no pattern for the ubiquitous
`name{...}` / bare `{...}` CTF flag shape, so it reported "sin credenciales detectadas" on a
binary whose entire challenge WAS the flag sitting in `.rodata`. Added `ctf-flag` (two forms:
`word{...}` and a bare `{...}`, content restricted to alnum/underscore/hyphen so it doesn't swallow
code/JSON snippets that happen to contain braces) and confirmed live: finds exactly the one real
flag in the real binary, finds nothing in a second real CTF binary whose flag is NOT present as
plain text (ROP Emporium-style XOR-chained, confirming no over-eager false positive), and stays
clean (zero hits) against /bin/ls and /bin/bash; a large, unrelated interpreter binary
(/usr/bin/python3.13, full of embedded bytecode) does produce some noise (~16 candidates, mostly
obvious byte-garbage) -- acceptable for a heuristic explicitly meant to be eyeballed, same as
every other pattern here, and bounded by the existing max_hits_per_kind cap."""
from __future__ import annotations

import math
import re

_MIN_STR = 5

# (name, compiled regex, whether to entropy-gate the capture group)
_PATTERNS = [
    ("url", re.compile(r"\b(?:https?|ftp|ws|wss)://[^\s\"'<>\\]{4,200}"), False),
    ("private-key-pem", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), False),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), False),
    ("aws-secret-key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}"), False),
    ("gcp-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), False),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), False),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), False),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), False),
    ("google-oauth", re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}\b"), False),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b"), False),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{2,}\.[A-Za-z]{2,}\b"), False),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), False),
    ("secret-assignment", re.compile(
        r"(?i)(?:api[_\-]?key|secret|token|passwd|password|pwd|auth)"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9/+_\-]{12,})"), True),
    ("ctf-flag", re.compile(
        r"\b[A-Za-z][A-Za-z0-9_]{2,30}\{[^{}\n]{1,100}\}"
        r"|(?<![A-Za-z0-9_])\{[A-Za-z][A-Za-z0-9_\-]{2,60}\}"), False),
]

# noisy IPv4 hits we never want to report as indicators
_IP_SKIP = re.compile(r"^(?:0\.0\.0\.0|127\.|255\.|0\.\d|\d+\.0\.0\.0)")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _iter_strings(data: bytes, min_len: int = _MIN_STR):
    """Yield printable ASCII runs and collapsed UTF-16LE runs."""
    # ASCII runs
    run = bytearray()
    for b in data:
        if 0x20 <= b < 0x7F:
            run.append(b)
        else:
            if len(run) >= min_len:
                yield run.decode("ascii")
            run = bytearray()
    if len(run) >= min_len:
        yield run.decode("ascii")
    # UTF-16LE runs: printable byte followed by 0x00
    run = bytearray()
    i, n = 0, len(data) - 1
    while i < n:
        if 0x20 <= data[i] < 0x7F and data[i + 1] == 0x00:
            run.append(data[i])
            i += 2
            continue
        if len(run) >= min_len:
            yield run.decode("ascii")
        run = bytearray()
        i += 1
    if len(run) >= min_len:
        yield run.decode("ascii")


def _redact(s: str, keep: int = 10) -> str:
    s = s.strip()
    if len(s) <= keep + 4:
        return s
    return s[:keep] + "…(" + str(len(s)) + "B)"


_ZIP_MAX_ENTRIES = 4000
_ZIP_MAX_ENTRY_BYTES = 8 * 1024 * 1024
_ZIP_MAX_TOTAL_BYTES = 64 * 1024 * 1024


def _expand_zip(data: bytes) -> bytes:
    """If `data` is a ZIP (APK/JAR/AAR/.zip...), append each inner entry's DECOMPRESSED bytes so
    the string/secret scan below sees real file contents instead of just the outer ZIP's
    (compressed, hence string-opaque) bytes and its central-directory filename table.

    Gap found testing this live against a REAL deliberately-vulnerable Android app
    (OWASP InsecureBankv2, InsecureBankv2.apk): MobSF's own secrets scanner found ~24
    high-entropy base64-looking strings (AES keys/IVs embedded in the decompiled
    resources/Java) in it, while `binoracle secrets` on the raw .apk found NOTHING but
    'res/layout/...' filename-table noise -- every byte that mattered was DEFLATE-compressed
    inside the ZIP and therefore invisible to a flat strings scan. Bounded (entries/per-entry/
    total) so a hostile/huge archive (zip bomb) can't make this unboundedly slow or exhaust
    memory; degrades silently to the original bytes when `data` isn't a valid ZIP."""
    import io
    import zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return data
    # Decompressed content first, outer (compressed) bytes last: the outer ZIP's own bytes are
    # mostly the central-directory filename table (e.g. hundreds of "res/layout/..." entries) --
    # real findings live in the inner files, so they must not be crowded out of a capped bucket
    # (like high_entropy's max_hits) by that filename-table noise being scanned first.
    chunks = []
    total = 0
    for i, info in enumerate(zf.infolist()):
        if i >= _ZIP_MAX_ENTRIES or total >= _ZIP_MAX_TOTAL_BYTES:
            break
        if info.is_dir() or info.file_size == 0 or info.file_size > _ZIP_MAX_ENTRY_BYTES:
            continue
        try:
            inner = zf.read(info)
        except Exception:
            continue
        chunks.append(inner)
        chunks.append(b"\x00")
        total += len(inner)
    if not total:
        return data
    chunks.append(data)
    return b"".join(chunks)


def scan_iocs(path: str, max_hits_per_kind: int = 50) -> dict:
    """Scan any file's strings for IOCs/secrets. Returns {ok, findings:{kind:[...]}, hosts, ...}."""
    from ._artifact import read_bounded, ArtifactTooLarge
    try:
        data = read_bounded(path)
    except ArtifactTooLarge as e:
        return {"ok": False, "note": str(e)}
    except Exception as e:
        return {"ok": False, "note": f"no se pudo leer: {e}"}
    data = _expand_zip(data)
    findings = {}
    seen = {}
    hosts = {}
    high_entropy = []
    he_seen = set()
    from urllib.parse import urlsplit
    for s in _iter_strings(data):
        for name, rx, entropy_gate in _PATTERNS:
            for m in rx.finditer(s):
                val = m.group(1) if (entropy_gate and m.groups()) else m.group(0)
                if not val:
                    continue
                if name == "ipv4" and _IP_SKIP.match(val):
                    continue
                if entropy_gate and _entropy(val) < 3.0:
                    continue          # looks like a placeholder, not a real secret
                bucket = seen.setdefault(name, set())
                if val in bucket:
                    continue
                if len(bucket) >= max_hits_per_kind:
                    continue
                bucket.add(val)
                shown = val if name in ("url", "email", "ipv4", "ctf-flag") else _redact(val)
                findings.setdefault(name, []).append(shown)
                if name == "url":
                    h = urlsplit(val).netloc
                    if h:
                        hosts[h] = hosts.get(h, 0) + 1
        # standalone high-entropy token flag (possible key material without a labelled context).
        # Collected into an uncapped-ish pool and ranked by entropy at the end (not first-seen):
        # with ZIP expansion (see _expand_zip) a real APK's structured resource-table strings
        # (@style/..., res/layout/...) have moderate entropy too and appear early in scan order,
        # so capping by arrival order let them crowd out genuinely higher-entropy material
        # (base64 keys/IVs) found later in the stream -- confirmed live against a real
        # deliberately-vulnerable app (OWASP InsecureBankv2: MobSF's own scanner surfaced ~24
        # base64 AES keys/IVs that this bucket was missing before the fix).
        if 24 <= len(s) <= 100 and " " not in s and "/" not in s[:4]:
            e = _entropy(s)
            if e >= 4.3 and s not in he_seen and len(high_entropy) < 2000:
                he_seen.add(s)
                high_entropy.append({"evidence": s, "entropy": round(e, 2)})
    high_entropy.sort(key=lambda h: -h["entropy"])
    high_entropy = [{"evidence": _redact(h["evidence"]), "entropy": h["entropy"]}
                    for h in high_entropy[:30]]
    counts = {k: len(v) for k, v in findings.items()}
    secret_kinds = [k for k in findings if k not in ("url", "email", "ipv4", "ctf-flag")]
    return {"ok": True, "size": len(data), "findings": findings, "counts": counts,
            "hosts": hosts, "high_entropy": high_entropy,
            "secret_kinds": sorted(secret_kinds),
            "limitations": ["heuristico: coincidencias por regex + entropia sobre cadenas extraidas "
                            "(ASCII y UTF-16LE); no se descifra ni se deofusca; posibles falsos "
                            "positivos/negativos"]}


def render_iocs(r: dict) -> str:
    out = ["## Escaneo de IOCs / secretos (estatico)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- bytes escaneados: {r.get('size')}")
    sk = r.get("secret_kinds") or []
    if sk:
        out.append(f"- **tipos de secreto detectados: {', '.join(sk)}**")
    else:
        out.append("- sin credenciales de alto riesgo detectadas por la heuristica")
    findings = r.get("findings") or {}
    flags = findings.get("ctf-flag") or []
    if flags:
        out.append(f"- **{len(flags)} posible(s) flag CTF detectada(s) en las strings**")
    order = ["ctf-flag", "private-key-pem", "aws-access-key", "aws-secret-key", "gcp-api-key",
             "github-token", "slack-token", "stripe-key", "google-oauth", "jwt", "secret-assignment",
             "url", "email", "ipv4"]
    for kind in order:
        vals = findings.get(kind)
        if not vals:
            continue
        out.append(f"\n### {kind} ({len(vals)})")
        for v in vals[:40]:
            out.append(f"- `{v}`")
    hosts = r.get("hosts") or {}
    if hosts:
        top = sorted(hosts.items(), key=lambda kv: -kv[1])[:20]
        out.append("\n### hosts (de URLs)")
        out.append(", ".join(f"{h}({n})" for h, n in top))
    he = r.get("high_entropy") or []
    if he:
        out.append(f"\n### tokens de alta entropia ({len(he)}) — posible material de clave")
        for h in he[:20]:
            out.append(f"- `{h['evidence']}`  (entropia {h['entropy']})")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
