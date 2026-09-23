"""RAG local sobre la base de conocimiento de explotacion.

Indexa recursivamente binoracle/kb/**/*.md por secciones (cheat sheets curados + skills
importados de ctf-pwn/ctf-reverse) y recupera los fragmentos mas relevantes para una consulta
o para los hechos verificados de un binario.

Retrieval hibrido en capas (el nucleo es stdlib puro y determinista; el resto opt-in, todas
con fallback si el modelo local no responde):
  - TF-IDF + coseno (siempre) + boost por coincidencia con el nombre del cheat sheet.
  - Embeddings semanticos del modelo local (Ollama), cacheados en disco. Env BINORACLE_RAG_EMBED=1
    (modelo BINORACLE_EMBED_MODEL, def. nomic-embed-text; sirve tambien un LLM que soporte /api/embed).
  - Expansion de consulta con el LLM (terminos relacionados). Env BINORACLE_RAG_EXPAND=1.
  - Rerank de candidatos con el LLM. Env BINORACLE_RAG_RERANK=1.
  - BINORACLE_RAG_FULL=1 activa las tres.

El LLM (audit, enrich, primitives) consulta este RAG para razonar sobre tecnica real en vez de
generar de memoria. Recuperacion != verdad: los snippets son referencia, la verificacion sigue
siendo de los oraculos (grounded over generated).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


def _truthy(v: str) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _http_post_json(url: str, payload: dict, timeout: float = 120.0) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _cos_list(a, b) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    num = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return num / (na * nb) if na and nb else 0.0

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
        # Capa semantica opcional (embeddings del modelo local). Off por defecto: el retrieval
        # base es TF-IDF puro y determinista. Se activa con BINORACLE_RAG_EMBED=1.
        self.embeds: Optional[list] = None
        self._embed_model = os.environ.get("BINORACLE_EMBED_MODEL", "nomic-embed-text")
        self._ollama = os.environ.get("BINORACLE_OLLAMA_URL", "http://localhost:11434").rstrip("/")
        self._llm_model = (os.environ.get("BINORACLE_RAG_LLM_MODEL")
                           or os.environ.get("BINORACLE_MODEL") or "qwen2.5-coder:7b")
        self.embed_mode = "off"
        _full = _truthy(os.environ.get("BINORACLE_RAG_FULL", ""))
        self._use_expand_llm = _full or _truthy(os.environ.get("BINORACLE_RAG_EXPAND", ""))
        self._use_rerank = _full or _truthy(os.environ.get("BINORACLE_RAG_RERANK", ""))
        self._expand_cache: dict = {}
        if _full or _truthy(os.environ.get("BINORACLE_RAG_EMBED", "")):
            self._init_embeddings()

    def status(self) -> str:
        """Resumen del modo del RAG (para doctor/tools)."""
        layers = [f"lexico TF-IDF ({len(self.chunks)} chunks)"]
        layers.append(f"embeddings: {self.embed_mode}")
        layers.append("expansion LLM: " + ("on" if self._use_expand_llm else "off"))
        layers.append("rerank LLM: " + ("on" if self._use_rerank else "off"))
        return " | ".join(layers)

    def _ollama_generate(self, prompt: str, timeout: float = 30.0) -> Optional[str]:
        try:
            r = _http_post_json(self._ollama + "/api/generate",
                                {"model": self._llm_model, "prompt": prompt, "stream": False,
                                 "options": {"temperature": 0.0}}, timeout=timeout)
            return r.get("response")
        except Exception:
            return None

    def _expand_query_llm(self, query: str) -> list:
        """Pide al modelo terminos tecnicos relacionados para ampliar la consulta (semantico
        barato). Cacheado por consulta. Best-effort; si falla, no anade nada."""
        if query in self._expand_cache:
            return self._expand_cache[query]
        prompt = ("Eres un experto en explotacion de binarios. Para esta consulta de busqueda, "
                  "lista SOLO de 6 a 10 terminos o sinonimos tecnicos relacionados (nombres de "
                  "tecnica, funciones, registros), separados por comas, sin explicar nada.\n"
                  f"Consulta: {query}\nTerminos:")
        resp = self._ollama_generate(prompt, timeout=20.0)
        terms: list = []
        if resp:
            for piece in re.split(r"[,\n;]+", resp):
                terms.extend(_tokens(piece))
        terms = terms[:24]
        self._expand_cache[query] = terms
        return terms

    def _rerank_llm(self, query: str, candidates: list, k: int) -> list:
        """Reordena los candidatos (Chunk, score) pidiendo al modelo los mas relevantes.
        Devuelve la lista reordenada; si el modelo falla, devuelve los candidatos tal cual."""
        items = []
        for i, (c, _s) in enumerate(candidates):
            snippet = c.text.strip().replace("\n", " ")[:180]
            items.append(f"[{i}] {c.doc} / {c.title}: {snippet}")
        prompt = ("Ordena estos fragmentos por relevancia a la consulta. Devuelve SOLO los "
                  f"indices de los {k} mas relevantes, de mas a menos, separados por comas.\n"
                  f"Consulta: {query}\n\n" + "\n".join(items) + "\n\nIndices:")
        resp = self._ollama_generate(prompt, timeout=30.0)
        if not resp:
            return candidates
        order = []
        for m in re.findall(r"\d+", resp):
            i = int(m)
            if 0 <= i < len(candidates) and i not in order:
                order.append(i)
        if not order:
            return candidates
        picked = [candidates[i] for i in order]
        rest = [candidates[i] for i in range(len(candidates)) if i not in order]
        return picked + rest

    # ---- capa de embeddings (hibrido semantico + lexico) ----
    def _ollama_embed(self, texts: list) -> Optional[list]:
        """Devuelve un vector por texto usando /api/embed (batched) o /api/embeddings
        (uno a uno) del Ollama local. None si el servicio no responde."""
        try:
            out: list = []
            B = 64
            for i in range(0, len(texts), B):
                r = _http_post_json(self._ollama + "/api/embed",
                                    {"model": self._embed_model, "input": texts[i:i + B]})
                embs = r.get("embeddings")
                if not embs:
                    raise ValueError("no embeddings")
                out.extend(embs)
            return out if len(out) == len(texts) else None
        except Exception:
            pass
        try:  # fallback: endpoint antiguo, uno por texto
            out = []
            for t in texts:
                r = _http_post_json(self._ollama + "/api/embeddings",
                                    {"model": self._embed_model, "prompt": t})
                e = r.get("embedding")
                if not e:
                    return None
                out.append(e)
            return out
        except Exception:
            return None

    def _init_embeddings(self) -> None:
        """Calcula (o carga de cache) el embedding de cada chunk. Best-effort; si el modelo
        de embeddings no esta disponible, queda en TF-IDF puro sin romper nada."""
        try:
            if not self.chunks:
                return
            payloads = [f"{c.doc} :: {c.title}\n{c.text}" for c in self.chunks]
            key = hashlib.sha256(
                (self._embed_model + "\x00" + "\x00".join(payloads)).encode()
            ).hexdigest()[:16]
            cache = Path.home() / ".cache" / "binoracle" / f"emb_{key}.json"
            if cache.exists():
                vecs = json.loads(cache.read_text())
                if isinstance(vecs, list) and len(vecs) == len(self.chunks):
                    self.embeds = vecs
                    self.embed_mode = "hybrid (cache)"
                    return
            vecs = self._ollama_embed(payloads)
            if vecs and len(vecs) == len(self.chunks):
                self.embeds = vecs
                self.embed_mode = "hybrid"
                try:
                    cache.parent.mkdir(parents=True, exist_ok=True)
                    cache.write_text(json.dumps(vecs))
                except Exception:
                    pass
            else:
                self.embed_mode = "off (sin modelo de embeddings; TF-IDF)"
        except Exception:
            self.embeds = None
            self.embed_mode = "off (error; TF-IDF)"

    def _load(self, kb_dir: Path) -> None:
        if not kb_dir.is_dir():
            return
        # Recursivo: los cheat sheets curados estan en la raiz; los skills importados
        # (ctf-pwn/ctf-reverse) en subdirectorios. El doc id es la ruta relativa sin .md,
        # asi "skills/pwn/heap-techniques" no colisiona con el curado "heap".
        for md in sorted(kb_dir.rglob("*.md")):
            doc = str(md.relative_to(kb_dir).with_suffix("")).replace("\\", "/")
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

    _NOISE_TITLES = {"table of contents", "contents", "index", "additional resources",
                     "see also", "references", "further reading"}

    def _add(self, doc: str, title: str, text: str) -> None:
        # Descarta secciones de indice/navegacion (TOC, listas de enlaces) que solo meten ruido.
        t = title.strip().lower().lstrip("# ")
        if t in self._NOISE_TITLES:
            return
        lines = [l for l in text.splitlines() if l.strip()]
        if lines:
            linkish = sum(1 for l in lines if l.lstrip().startswith(("- [", "* [", "[")) or "](" in l)
            if linkish / len(lines) > 0.6:      # seccion mayormente enlaces -> es un indice
                return
        tf = Counter(_tokens(title + " " + text))
        if not tf:
            return
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
        """Devuelve [(Chunk, score)] top-k para la consulta. Retrieval hibrido en capas
        (todas opt-in; el nucleo es TF-IDF puro y determinista):

        1. TF-IDF lexico + boost por coincidencia con el NOMBRE del cheat sheet.
        2. Embeddings (semantico): si estan activos, se mezcla el coseno de embeddings 50/50
           con el lexico -> capta parafrasis que las palabras exactas no matchean.
        3. Expansion de consulta con el LLM: anade terminos tecnicos relacionados (env
           BINORACLE_RAG_EXPAND) ademas del mapa de sinonimos estatico.
        4. Rerank con el LLM: reordena un pool mayor de candidatos por relevancia
           (env BINORACLE_RAG_RERANK)."""
        q_raw = set(_tokens(query))
        q_terms = self._expand(q_raw)
        if self._use_expand_llm:
            q_terms = list(q_terms) + self._expand_query_llm(query)
        if not q_terms:
            return []
        qvec = self._vec(Counter(q_terms))

        q_emb = None
        if self.embeds is not None:
            qe = self._ollama_embed([query])
            if qe:
                q_emb = qe[0]

        scored = []
        for i, c in enumerate(self.chunks):
            s_lex = self._cos(qvec, self._vec(c.tf))
            if q_emb is not None:
                s = 0.5 * _cos_list(q_emb, self.embeds[i]) + 0.5 * s_lex
            else:
                s = s_lex
            name_tokens = set(re.split(r"[-_/]", c.doc))
            hit = q_raw & name_tokens
            if hit:
                s += 0.12 * len(hit)          # boost por coincidencia con el nombre del doc
            if s >= min_score:
                scored.append((c, s))
        scored.sort(key=lambda x: x[1], reverse=True)

        if self._use_rerank and len(scored) > k:
            pool = scored[:max(k, 8)]
            return self._rerank_llm(query, pool, k)[:k]
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
