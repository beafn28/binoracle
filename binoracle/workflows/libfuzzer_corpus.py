"""LibFuzzer corpus seeded from CVE PoC descriptions.

Extracts interesting byte patterns from a CVE NVD description and optional PoC
source/text, then generates:
  1. A set of seed files (libFuzzer corpus) covering edge cases for that vulnerability.
  2. A C skeleton harness (LLVMFuzzerTestOneInput) targeting the specified function.

The seeds are designed to cover:
  - Boundary inputs (empty, 1 byte, max length)
  - Format-specific triggers (SQL keywords, shell metacharacters, format strings, etc.)
  - Patterns extracted from the PoC text (string literals, hex escapes)
  - Overflow triggers (long byte runs with 'A', null bytes)

SOLO USO AUTORIZADO — solo en software propio o con permiso escrito del propietario.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CorpusSeed:
    filename: str
    content: bytes
    rationale: str


@dataclass
class CorpusResult:
    cve_id: str
    target_func: str = "target_function"
    seeds: List[CorpusSeed] = field(default_factory=list)
    harness: str = ""
    vuln_class: str = ""
    ok: bool = False
    note: str = ""


# ---------------------------------------------------------------------------
# Vuln class heuristic (similar to cvss.py _RULES but for input shaping)
# ---------------------------------------------------------------------------

_CLASS_MAP: List[Tuple[str, Tuple[str, ...]]] = [
    ("sqli",        ("sql injection", "sqli", "mysql", "postgresql", "sqlite", "where clause",
                     "order by", "union select", "1=1")),
    ("cmdinj",      ("command injection", "os.system", "subprocess", "shell=true", "popen",
                     "exec(", "system(", "injection via", "unsanitized")),
    ("overflow",    ("buffer overflow", "stack overflow", "heap overflow", "out-of-bounds",
                     "oob write", "oob read", "gets(", "strcpy(", "memcpy(")),
    ("fmt",         ("format string", "printf(", "fprintf(", "%s", "%n", "user-controlled format")),
    ("path_trav",   ("path traversal", "directory traversal", "../", "..", "arbitrary file",
                     "open(", "fopen(", "file read")),
    ("deserial",    ("deserialization", "pickle", "unserialize", "yaml.load", "marshal.loads",
                     "jsonpickle")),
    ("ssrf",        ("ssrf", "server-side request forgery", "url redirection", "open redirect",
                     "fetch(", "requests.get(", "urllib")),
    ("xxe",         ("xxe", "xml external entity", "doctype", "entity", "xml parsing")),
    ("heap_uaf",    ("use-after-free", "uaf", "heap use after", "dangling pointer")),
    ("rop",         ("return-oriented", "rop chain", "ret2libc", "ret2win", "aslr bypass")),
]


def _classify(description: str, poc_text: str = "") -> str:
    blob = (description + " " + poc_text).lower()
    for cls, kws in _CLASS_MAP:
        if any(k in blob for k in kws):
            return cls
    return "generic"


# ---------------------------------------------------------------------------
# Seed generators per vulnerability class
# ---------------------------------------------------------------------------

def _seeds_sqli() -> List[Tuple[str, bytes, str]]:
    return [
        ("sqli_tautology.txt",  b"' OR '1'='1",           "classic tautology"),
        ("sqli_union.txt",      b"' UNION SELECT NULL--",  "UNION-based probe"),
        ("sqli_comment.txt",    b"admin'--",               "comment-out suffix"),
        ("sqli_time.txt",       b"' OR SLEEP(5)--",        "time-based blind"),
        ("sqli_error.txt",      b"'",                      "single quote — triggers parse error"),
        ("sqli_null.txt",       b"\x00",                   "null byte injection"),
        ("sqli_long.txt",       b"A" * 512 + b"'",         "long string + quote"),
    ]


def _seeds_cmdinj() -> List[Tuple[str, bytes, str]]:
    return [
        ("cmdinj_semicolon.sh", b"; id",                   "semicolon separator"),
        ("cmdinj_pipe.sh",      b"| id",                   "pipe separator"),
        ("cmdinj_backtick.sh",  b"`id`",                   "backtick substitution"),
        ("cmdinj_dollar.sh",    b"$(id)",                  "dollar-paren substitution"),
        ("cmdinj_newline.sh",   b"\nid\n",                 "newline injection"),
        ("cmdinj_null.bin",     b"\x00; id",               "null-byte + command"),
        ("cmdinj_long.sh",      b"A" * 1024 + b"; id",     "long prefix + separator"),
    ]


def _seeds_overflow() -> List[Tuple[str, bytes, str]]:
    return [
        ("overflow_empty.bin",  b"",                       "empty input"),
        ("overflow_1.bin",      b"A",                      "single byte"),
        ("overflow_256.bin",    b"A" * 256,                "256 bytes — small overflow"),
        ("overflow_1k.bin",     b"A" * 1024,               "1 KiB"),
        ("overflow_4k.bin",     b"A" * 4096,               "4 KiB — typical page boundary"),
        ("overflow_null.bin",   b"\x00" * 64,              "null bytes — off-by-one"),
        ("overflow_pattern.bin",bytes(range(256)) * 2,     "0x00-0xFF pattern × 2 — DIEHARD"),
        ("overflow_mixed.bin",  b"\xff\xfe\xfd" * 100,     "high bytes — integer overflow trigger"),
    ]


def _seeds_fmt() -> List[Tuple[str, bytes, str]]:
    return [
        ("fmt_read.txt",        b"%s%s%s%s%s",             "read-from-stack"),
        ("fmt_write.txt",       b"%n",                     "write-to-addr — classic"),
        ("fmt_width.txt",       b"%99999d",                "huge width — integer overflow in printf"),
        ("fmt_hex.txt",         b"%08x.%08x.%08x.%08x",   "hex dump of stack"),
        ("fmt_long.txt",        b"%" + b"s" * 100,         "repeated %s"),
        ("fmt_null.txt",        b"\x00%s",                 "null-byte prefix"),
    ]


def _seeds_path_trav() -> List[Tuple[str, bytes, str]]:
    return [
        ("trav_simple.txt",     b"../etc/passwd",          "simple traversal"),
        ("trav_double.txt",     b"../../etc/shadow",       "double traversal"),
        ("trav_url.txt",        b"%2e%2e%2fetc%2fpasswd",  "URL-encoded traversal"),
        ("trav_null.txt",       b"../etc/passwd\x00.jpg",  "null-byte extension bypass"),
        ("trav_abs.txt",        b"/etc/passwd",            "absolute path"),
        ("trav_win.txt",        b"..\\..\\Windows\\System32\\drivers\\etc\\hosts",
                                "Windows-style traversal"),
    ]


def _seeds_deserial() -> List[Tuple[str, bytes, str]]:
    return [
        ("pickle_rce.bin",      b"cos\nsystem\n(S'id'\ntR.",
                                "Python pickle RCE payload (os.system)"),
        ("yaml_merge.txt",      b"!!python/object/apply:os.system ['id']",
                                "PyYAML arbitrary call"),
        ("json_deep.txt",       b'{"a":' * 50 + b'"x"' + b'}' * 50,
                                "deeply nested JSON — stack overflow in parser"),
        ("empty.bin",           b"",                       "empty — crash on empty input"),
        ("null.bin",            b"\x00",                   "single null"),
    ]


def _seeds_ssrf() -> List[Tuple[str, bytes, str]]:
    return [
        ("ssrf_internal.txt",   b"http://169.254.169.254/latest/meta-data/",
                                "AWS IMDS endpoint"),
        ("ssrf_loopback.txt",   b"http://127.0.0.1:22",   "loopback SSH"),
        ("ssrf_file.txt",       b"file:///etc/passwd",     "file:// scheme"),
        ("ssrf_gopher.txt",     b"gopher://127.0.0.1:6379/_PING\r\n",
                                "gopher to Redis"),
        ("ssrf_dict.txt",       b"dict://127.0.0.1:11211/",
                                "dict to Memcached"),
    ]


def _seeds_xxe() -> List[Tuple[str, bytes, str]]:
    payload = (b'<?xml version="1.0"?><!DOCTYPE foo ['
               b'<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               b'<foo>&xxe;</foo>')
    return [
        ("xxe_etc_passwd.xml",  payload,                   "classic XXE /etc/passwd"),
        ("xxe_empty.xml",       b"<a/>",                   "minimal valid XML"),
        ("xxe_broken.xml",      b"<a>",                    "unclosed tag — parser error"),
        ("xxe_deep.xml",        b"<a>" * 200 + b"</a>" * 200,
                                "deeply nested — stack overflow"),
    ]


def _seeds_heap_uaf() -> List[Tuple[str, bytes, str]]:
    return [
        ("uaf_empty.bin",       b"",                       "empty — base case"),
        ("uaf_alloc.bin",       b"\x00" * 64,              "64-byte allocation chunk"),
        ("uaf_spray.bin",       b"\x41\x41\x41\x41" * 128, "heap spray pattern"),
        ("uaf_trigger.bin",     b"\xff" * 8 + b"\x00" * 8, "type-confusion boundary"),
    ]


def _seeds_rop() -> List[Tuple[str, bytes, str]]:
    return [
        ("rop_overflow.bin",    b"A" * 256,                "padding to reach return address"),
        ("rop_ret2win.bin",     b"A" * 256 + b"\xde\xad\xbe\xef\xde\xad\xbe\xef",
                                "overflow + crafted address (placeholder)"),
        ("rop_cyclic.bin",      bytes(b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabz"),
                                "pwntools cyclic pattern — identifies offset"),
    ]


def _seeds_generic() -> List[Tuple[str, bytes, str]]:
    return [
        ("generic_empty.bin",   b"",                       "empty input"),
        ("generic_null.bin",    b"\x00",                   "single null byte"),
        ("generic_1k.bin",      b"A" * 1024,               "1 KiB of 'A'"),
        ("generic_highbytes.bin", bytes(range(128, 256)),  "high bytes 0x80-0xFF"),
        ("generic_pattern.bin", bytes(range(256)),         "0x00-0xFF byte range"),
    ]


_SEED_GENERATORS = {
    "sqli":       _seeds_sqli,
    "cmdinj":     _seeds_cmdinj,
    "overflow":   _seeds_overflow,
    "fmt":        _seeds_fmt,
    "path_trav":  _seeds_path_trav,
    "deserial":   _seeds_deserial,
    "ssrf":       _seeds_ssrf,
    "xxe":        _seeds_xxe,
    "heap_uaf":   _seeds_heap_uaf,
    "rop":        _seeds_rop,
    "generic":    _seeds_generic,
}


# ---------------------------------------------------------------------------
# PoC text mining — extract literal strings and byte patterns
# ---------------------------------------------------------------------------

_STR_LITERAL_RE = re.compile(r'"([^"\\]{2,80})"')
_HEX_STR_RE = re.compile(r'\\x([0-9a-fA-F]{2})')


def _extract_poc_seeds(poc_text: str) -> List[Tuple[str, bytes, str]]:
    seeds: List[Tuple[str, bytes, str]] = []
    if not poc_text:
        return seeds
    for i, m in enumerate(_STR_LITERAL_RE.finditer(poc_text)):
        val = m.group(1)
        if len(val) >= 3:
            seeds.append((f"poc_str_{i:02d}.txt", val.encode("utf-8", "replace"),
                          f"string literal from PoC: {val[:40]!r}"))
    # Reconstruct hex-escaped byte sequences from C-like source
    hex_spans: List[bytes] = []
    for m in _HEX_STR_RE.finditer(poc_text):
        hex_spans.append(bytes.fromhex(m.group(1)))
    if hex_spans:
        raw = b"".join(hex_spans)
        seeds.append(("poc_hexbytes.bin", raw, "concatenated \\xNN bytes from PoC"))
    return seeds


# ---------------------------------------------------------------------------
# Harness skeleton
# ---------------------------------------------------------------------------

_HARNESS_TMPL = """\
/* LibFuzzer harness — generated by binoracle cve-corpus for {cve_id}
 * Vulnerability class : {vuln_class}
 * Target function     : {target_func}
 *
 * Build:
 *   clang -g -O1 -fsanitize=fuzzer,address -o fuzzer_harness harness.c <target.a or target.c>
 * Run:
 *   mkdir corpus && cp corpus_seeds/* corpus/
 *   ./fuzzer_harness corpus/ -max_len=4096
 *
 * SOLO USO AUTORIZADO — solo en software propio o con permiso escrito del propietario.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Forward-declare the target.  Adjust signature to match the real function. */
int {target_func}(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;

    /* Provide a null-terminated copy when the target expects a C string. */
    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\\0';

    {target_func}((const uint8_t *)buf, size);

    free(buf);
    return 0;
}}
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_corpus(cve_id: str, poc_text: str = "", description: str = "",
                 target_func: str = "target_function", hint: str = "") -> CorpusResult:
    """Build a libFuzzer corpus from a CVE description and optional PoC text."""
    result = CorpusResult(cve_id=cve_id, target_func=target_func or "target_function")

    # Classify vulnerability to pick the right seed set
    vuln_class = _classify(description + " " + hint, poc_text)
    result.vuln_class = vuln_class

    gen = _SEED_GENERATORS.get(vuln_class, _seeds_generic)
    base_seeds = gen()

    # Always add generic boundary seeds on top
    extra = [
        ("boundary_empty.bin",  b"",              "empty — always a boundary case"),
        ("boundary_1.bin",      b"\x00",          "single null byte"),
        ("boundary_max.bin",    b"A" * 4096,      "4 KiB — libFuzzer default max_len"),
    ]

    all_seeds: List[Tuple[str, bytes, str]] = base_seeds + extra
    all_seeds += _extract_poc_seeds(poc_text)

    # Deduplicate by content
    seen: set = set()
    for fname, content, rationale in all_seeds:
        key = (fname, content)
        if key not in seen:
            seen.add(key)
            result.seeds.append(CorpusSeed(filename=fname, content=content, rationale=rationale))

    result.harness = _HARNESS_TMPL.format(
        cve_id=cve_id,
        vuln_class=vuln_class,
        target_func=result.target_func,
    )
    result.ok = bool(result.seeds)
    result.note = (f"{len(result.seeds)} seeds for class '{vuln_class}'"
                   + (f" (hint: {hint})" if hint else ""))
    return result


def write_corpus(corpus: CorpusResult, out_dir: str = ".") -> str:
    """Write corpus seeds and harness to <out_dir>/<cve_id>_corpus/.
    Returns the directory path."""
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", corpus.cve_id)
    dest = Path(out_dir or ".") / f"{slug}_corpus"
    dest.mkdir(parents=True, exist_ok=True)

    seeds_dir = dest / "seeds"
    seeds_dir.mkdir(exist_ok=True)
    for seed in corpus.seeds:
        (seeds_dir / seed.filename).write_bytes(seed.content)

    harness_path = dest / "harness.c"
    harness_path.write_text(corpus.harness, encoding="utf-8")

    index_lines = [f"# {corpus.cve_id} corpus — {len(corpus.seeds)} seeds\n"]
    index_lines.append(f"Vulnerability class: {corpus.vuln_class}\n")
    index_lines.append(f"Target function: {corpus.target_func}\n\n")
    index_lines.append("| File | Bytes | Rationale |\n")
    index_lines.append("|------|------:|-----------|\n")
    for s in corpus.seeds:
        index_lines.append(f"| `{s.filename}` | {len(s.content)} | {s.rationale} |\n")
    (dest / "README.md").write_text("".join(index_lines), encoding="utf-8")

    return str(dest)


def render_corpus(corpus: CorpusResult, wrote_to: Optional[str] = None) -> str:
    lines = [f"\n## LibFuzzer corpus — {corpus.cve_id}\n"]
    lines.append(f"Vulnerability class : **{corpus.vuln_class}**")
    lines.append(f"Target function     : `{corpus.target_func}`")
    lines.append(f"Seeds generated     : {len(corpus.seeds)}")
    if wrote_to:
        lines.append(f"Output directory    : `{wrote_to}`")
    lines.append("")
    lines.append("### Seeds\n")
    lines.append("| # | File | Bytes | Rationale |")
    lines.append("|---|------|------:|-----------|")
    for i, s in enumerate(corpus.seeds, 1):
        lines.append(f"| {i} | `{s.filename}` | {len(s.content)} | {s.rationale} |")
    lines.append("")
    lines.append("### Harness skeleton (`harness.c`)\n")
    lines.append("```c")
    lines.append(corpus.harness.strip())
    lines.append("```")
    lines.append("")
    lines.append("```")
    lines.append(f"# Build & run:")
    lines.append(f"clang -g -O1 -fsanitize=fuzzer,address -o fuzzer_harness {wrote_to or '.'}/harness.c <target.c>")
    lines.append(f"./fuzzer_harness {wrote_to or '.'}/seeds/ -max_len=4096")
    lines.append("```")
    lines.append("\n_SOLO USO AUTORIZADO — solo en software propio o con permiso escrito del propietario._")
    return "\n".join(lines)
