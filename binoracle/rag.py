"""RAG local sobre la base de conocimiento de explotacion (solo stdlib).

Indexa los cheat sheets de binoracle/kb/*.md por secciones y recupera los fragmentos
mas relevantes para una consulta o para los hechos verificados de un binario. Sin
dependencias externas: TF-IDF + coseno con collections/math.

El LLM (audit, enrich, primitives) consulta este RAG para razonar sobre tecnica real
en vez de generar de memoria. Recuperacion != verdad: los snippets son referencia, la
verificacion sigue siendo de los oraculos (grounded over generated).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_KB_DIR = Path(__file__).parent / "kb"

# Sinonimos/expansion: mapea lo que aparece en un binario a vocabulario de la KB.
_EXPAND = {
    "gets": "overflow stack ret2win buffer",
    "strcpy": "overflow stack buffer",
    "sprintf": "overflow format",
    "printf": "format string got overwrite",
    "system": "ret2libc shell command",
    "malloc": "heap tcache chunk",
    "free": "heap tcache double free uaf",
    "nx": "rop ret2libc ret2syscall shellcode",
    "pie": "pie leak base aslr partial overwrite",
    "canary": "canary stack protector leak",
    "relro": "relro got overwrite",
    "execve": "rop ret2syscall syscall",
    "puts": "ret2libc leak got plt",
    "win": "ret2win",
    "double": "heap double free tcache",
    "uaf": "heap use after free tcache",
    "fmt": "format string %n got",
    "rop": "rop gadget ret2syscall ret2libc",
}

_STOP = {
    "the", "a", "de", "la", "el", "en", "y", "o", "un", "una", "los", "las", "con",
    "por", "para", "que", "se", "es", "al", "del", "lo", "si", "no", "su", "of", "to",
    "in", "and", "or", "is", "on", "for", "with", "un",
}

_WORD = re.compile(r"[a-zA-Z_%$][a-zA-Z0-9_%$]+")


def _tokens(text: str) -> list[str]:
    out = []
    for w in _WORD.findall(text.lower()):
        if len(w) < 2 or w in _STOP:
            continue
        out.append(w)
    return out


@dataclass
class Chunk:
    doc: str          # nombre del cheat sheet (ret2win, heap, ...)
    title: str        # titulo de la seccion (## ...)
    text: str         # cuerpo de la seccion
    tf: Counter       # frecuencias de termino


class KnowledgeBase:
    """Indice TF-IDF sobre los cheat sheets. Se carga una vez y se reutiliza."""

    def __init__(self, kb_dir: Path = _KB_DIR):
        self.chunks: list[Chunk] = []
        self.idf: dict[str, float] = {}
        self._load(kb_dir)
        self._build_idf()

    def _load(self, kb_dir: Path) -> None:
        if not kb_dir.is_dir():
            return
        for md in sorted(kb_dir.glob("*.md")):
            doc = md.stem
            raw = md.read_text(encoding="utf-8", errors="replace")
            # Partir por secciones "## ". El preambulo (titulo #) va como seccion 0.
            parts = re.split(r"^##\s+", raw, flags=re.MULTILINE)
            head = parts[0].strip()
            title0 = head.splitlines()[0].lstrip("# ").strip() if head else doc
            body0 = "\n".join(head.splitlines()[1:]).strip()
            if body0:
                self._add(doc, title0, body0)
            for sec in parts[1:]:
                lines = sec.splitlines()
                title = lines[0].strip() if lines else doc
                body = "\n".join(lines[1:]).strip()
                if body:
                    self._add(doc, title, body)

    def _add(self, doc: str, title: str, text: str) -> None:
        tf = Counter(_tokens(title + " " + text))
        self.chunks.append(Chunk(doc=doc, title=title, text=text, tf=tf))

    def _build_idf(self) -> None:
        n = len(self.chunks) or 1
        df: Counter = Counter()
        for c in self.chunks:
            for term in c.tf:
                df[term] += 1
        for term, d in df.items():
            self.idf[term] = math.log((n + 1) / (d + 1)) + 1.0

    def _vec(self, tf: Counter) -> dict[str, float]:
        v = {}
        total = sum(tf.values()) or 1
        for term, f in tf.items():
            v[term] = (f / total) * self.idf.get(term, math.log(len(self.chunks) + 1) + 1.0)
        return v

    @staticmethod
    def _cos(a: dict[str, float], b: dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        common = set(a) & set(b)
        num = sum(a[t] * b[t] for t in common)
        na = math.sqrt(sum(x * x for x in a.values()))
        nb = math.sqrt(sum(x * x for x in b.values()))
        return num / (na * nb) if na and nb else 0.0

    def _expand(self, terms: Iterable[str]) -> list[str]:
        out = list(terms)
        for t in list(terms):
            exp = _EXPAND.get(t)
            if exp:
                out.extend(_tokens(exp))
        return out

    def retrieve(self, query: str, k: int = 4, min_score: float = 0.03):
        """Devuelve [(Chunk, score)] top-k para la consulta.

        Al coseno TF-IDF se le suma un pequeno boost cuando los terminos de la consulta
        coinciden con el NOMBRE del cheat sheet (p.ej. 'format string' -> doc 'format-string'):
        una consulta que nombra una tecnica debe priorizar su propia hoja, no las que solo la
        mencionan de pasada."""
        q_raw = set(_tokens(query))
        q_terms = self._expand(q_raw)
        if not q_terms:
            return []
        qvec = self._vec(Counter(q_terms))
        scored = []
        for c in self.chunks:
            s = self._cos(qvec, self._vec(c.tf))
            name_tokens = set(re.split(r"[-_]", c.doc))
            hit = q_raw & name_tokens
            if hit:
                s += 0.12 * len(hit)          # boost por coincidencia con el nombre del doc
            if s >= min_score:
                scored.append((c, s))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    def context_for(self, query: str, k: int = 4, max_chars: int = 1800) -> str:
        """Bloque de texto listo para inyectar en el prompt del LLM."""
        hits = self.retrieve(query, k=k)
        if not hits:
            return ""
        blocks = []
        used = 0
        for c, score in hits:
            snippet = c.text.strip()
            header = f"[{c.doc} / {c.title}]"
            block = f"{header}\n{snippet}"
            if used + len(block) > max_chars:
                block = block[: max(0, max_chars - used)]
            blocks.append(block)
            used += len(block)
            if used >= max_chars:
                break
        return "\n\n".join(blocks)


_CACHE: KnowledgeBase | None = None


def get_kb() -> KnowledgeBase:
    global _CACHE
    if _CACHE is None:
        _CACHE = KnowledgeBase()
    return _CACHE


def query_from_facts(facts: dict) -> str:
    """Construye una consulta a partir de los hechos verificados de un binario.

    `facts` acepta llaves opcionales: mitigations (dict), imports (list[str]),
    primitives (list[str]), category (str).
    """
    parts: list[str] = []
    mit = facts.get("mitigations") or {}
    for name, val in mit.items():
        s = str(val).lower()
        if name.lower() in ("nx", "pie", "canary", "relro"):
            if "no" in s or "disabled" in s or val is False or "partial" in s:
                parts.append(name)
            elif val is True or "enabled" in s or "full" in s:
                parts.append(name)
    for imp in (facts.get("imports") or []):
        parts.append(str(imp))
    for prim in (facts.get("primitives") or []):
        parts.append(str(prim))
    if facts.get("category"):
        parts.append(str(facts["category"]))
    return " ".join(parts)
