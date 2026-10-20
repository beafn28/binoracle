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
import threading
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


# Ficheros que NO son conocimiento de reversing sino navegacion/routing de un skill
# (manifiestos y plantillas). Se excluyen del indice: solo meten ruido o instrucciones.
_MANIFEST_DOCS = {"readme", "skill", "_index", "index", "_template",
                  "contribute-back", "tool-index",
                  # andamiaje de orquestacion de tareas (plantillas MCP/task), no conocimiento:
                  "task-artifacts", "task-input-template", "mcp-task-template"}


def _truthy(v: str) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _http_post_json(url: str, payload: dict, timeout: float = 120.0) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _cache_dir() -> Path:
    """Directorio de cache (prefs + embeddings). Configurable con BINORACLE_CACHE_DIR
    (util para tests hermeticos)."""
    d = os.environ.get("BINORACLE_CACHE_DIR")
    return Path(d) if d else (Path.home() / ".cache" / "binoracle")


def _rag_prefs_path() -> Path:
    return _cache_dir() / "rag_prefs.json"


def _load_rag_prefs() -> dict:
    try:
        p = _rag_prefs_path()
        if p.exists():
            d = json.loads(p.read_text())
            return d if isinstance(d, dict) else {}
    except Exception:
        pass
    return {}


def _save_rag_prefs(prefs: dict) -> None:
    try:
        p = _rag_prefs_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(prefs))
    except Exception:
        pass


def _cos_list(a, b) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    num = sum(x * y for x, y in zip(a, b, strict=True))
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
    "in", "and", "or", "is", "on", "for", "with",
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
        self._seen_chunks: set = set()   # dedup exacto (title, text) durante la carga
        self.idf: dict[str, float] = {}
        self._load(kb_dir)
        self._load_tools()      # hila el saber-herramientas (toolcheck) dentro del RAG
        self._build_idf()
        # Capa semantica opcional (embeddings del modelo local). Off por defecto: el retrieval
        # base es TF-IDF puro y determinista. Se activa con BINORACLE_RAG_EMBED=1.
        self.embeds: Optional[list] = None
        self._ollama = os.environ.get("BINORACLE_OLLAMA_URL", "http://localhost:11434").rstrip("/")
        # Elige el mejor embedder disponible: el fijado por env, si no el mejor instalado
        # (bge-m3 multilingue es superior para consultas en espanol contra contenido en ingles).
        self._llm_model = (os.environ.get("BINORACLE_RAG_LLM_MODEL")
                           or os.environ.get("BINORACLE_MODEL") or "qwen2.5-coder:7b")
        self._embed_model = os.environ.get("BINORACLE_EMBED_MODEL") or self._pick_embed_model()
        self.embed_mode = "off"
        # Prioridad de cada capa: env var explicita > preferencia persistida (toggle web) >
        # AUTOMATICO. Automatico = si hay modelo local disponible, se enciende semantico +
        # expansion solos (el mejor retrieval sin que el usuario toque nada); si no, TF-IDF.
        # Rerank NO es automatico (es la capa mas lenta): solo por toggle/env. Poner
        # BINORACLE_RAG_AUTO=0 desactiva el automatico (util para entornos deterministas).
        prefs = _load_rag_prefs()
        _full = _truthy(os.environ.get("BINORACLE_RAG_FULL", ""))
        auto_allowed = os.environ.get("BINORACLE_RAG_AUTO", "1") != "0"
        self._auto = auto_allowed and self._model_reachable()

        def _flag(env_name, pref_key, auto_default):
            v = os.environ.get(env_name)
            if v is not None:
                return _truthy(v)
            if pref_key in prefs:
                return bool(prefs[pref_key])
            return _full or (auto_default and self._auto)

        self._use_expand_llm = _flag("BINORACLE_RAG_EXPAND", "expand", auto_default=True)
        self._use_rerank = _flag("BINORACLE_RAG_RERANK", "rerank", auto_default=True)
        self._expand_cache: dict = {}
        # _embed_requested = CONFIGURADO/activo (aunque el hilo de fondo siga construyendo), a
        # diferencia de `self.embeds is not None` que solo es True cuando YA esta listo. Sin esta
        # distincion, la casilla "Semantico" del panel web (que lee este flag) salia DESMARCADA
        # durante todo el tiempo de construccion (embed_mode='construyendo...'), pareciendo
        # apagada cuando en realidad esta activa y a punto de terminar -- confuso para el usuario.
        self._embed_requested = _flag("BINORACLE_RAG_EMBED", "embed", auto_default=True)
        if self._embed_requested:
            # No bloquear el arranque: construir/cargar embeddings en un hilo de fondo. Hasta
            # que esten listos el retrieval usa TF-IDF; luego pasa a hibrido solo.
            self.embed_mode = "construyendo..."
            threading.Thread(target=self._init_embeddings, daemon=True).start()

    def _installed_models(self) -> list:
        try:
            with urllib.request.urlopen(self._ollama + "/api/tags", timeout=1.5) as r:
                data = json.loads(r.read().decode())
            return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            return []

    def _model_reachable(self) -> bool:
        return bool(self._installed_models())

    def _pick_embed_model(self) -> str:
        """Elige el mejor modelo de embeddings instalado. Preferencia multilingue > EN;
        si no hay ninguno dedicado, usa el LLM (que suele soportar /api/embed)."""
        installed = [m.split(":")[0] for m in self._installed_models()]
        for pref in ("bge-m3", "mxbai-embed-large", "snowflake-arctic-embed2",
                     "nomic-embed-text", "all-minilm"):
            if pref in installed:
                return pref
        if self._llm_model.split(":")[0] in installed:
            return self._llm_model
        return "nomic-embed-text"   # ultimo recurso (se descargaria / o fallback a TF-IDF)

    def sources(self) -> dict:
        """Reparto de chunks por fuente (curados vs cada corpus de skills importado)."""
        out: dict = {}
        for c in self.chunks:
            if c.doc.startswith("skills/"):
                parts = c.doc.split("/")
                key = "skills/" + (parts[1] if len(parts) > 1 else "?")
            else:
                key = "curados"
            out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: kv[1], reverse=True))

    def sources_summary(self) -> str:
        return " | ".join(f"{k}: {v}" for k, v in self.sources().items())

    def status(self) -> str:
        """Resumen del modo del RAG (para doctor/tools)."""
        layers = [f"lexico TF-IDF ({len(self.chunks)} chunks)"]
        layers.append(f"embeddings: {self.embed_mode}")
        layers.append("expansion LLM: " + ("on" if self._use_expand_llm else "off"))
        layers.append("rerank LLM: " + ("on" if self._use_rerank else "off"))
        return " | ".join(layers)

    def health(self) -> dict:
        """Chequeo de integridad del conocimiento (para evitar 'cosas falsas'): cuenta chunks/docs,
        duplicados exactos y fuga de chino sin traducir (CJK >2%). clean=True si no hay ninguno."""
        import hashlib
        seen, dups = set(), 0
        cjk_docs = []
        for c in self.chunks:
            t = (c.text or "").strip()
            h = hashlib.sha256(t.encode("utf-8", "ignore")).hexdigest()
            if h in seen:
                dups += 1
            else:
                seen.add(h)
            if t:
                n = sum(1 for ch in t if "一" <= ch <= "鿿")
                if n / max(1, len(t)) > 0.02:
                    cjk_docs.append(c.doc)
        docs = {(c.doc.split("#", 1)[0]) for c in self.chunks}
        return {"chunks": len(self.chunks), "docs": len(docs), "duplicates": dups,
                "cjk_chunks": len(cjk_docs), "cjk_docs": sorted(set(cjk_docs))[:5],
                "sources": len(self.sources()),
                "clean": dups == 0 and len(cjk_docs) == 0}

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
        # Fallback uno-a-uno solo para pocos textos (p.ej. la query): con muchos seria lentisimo
        # y bloquearia el build; ahi preferimos fallar rapido y quedarnos en TF-IDF.
        if len(texts) > 16:
            return None
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
            # Trunca cada chunk: los modelos de embeddings tienen limite de contexto y un
            # chunk enorme da HTTP 400. Titulo + inicio del cuerpo basta para la similitud.
            _cap = int(os.environ.get("BINORACLE_EMBED_MAXCHARS", "1800"))
            payloads = [f"{c.doc} :: {c.title}\n{c.text}"[:_cap] for c in self.chunks]
            key = hashlib.sha256(
                (self._embed_model + "\x00" + "\x00".join(payloads)).encode()
            ).hexdigest()[:16]
            cache = _cache_dir() / f"emb_{key}.json"
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
            # README/SKILL/_index/_template son manifiestos de navegacion o routers de skill
            # (instrucciones "ACTION REQUIRED / NOW: ejecuta ...", no conocimiento de reversing):
            # solo meten ruido en el retrieval, se saltan.
            if doc.rsplit("/", 1)[-1].lower() in _MANIFEST_DOCS:
                continue
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

    def _load_tools(self) -> None:
        """Inyecta el catalogo de herramientas (toolcheck) como conocimiento recuperable: un
        chunk por herramienta con PARA QUE sirve y su categoria. Asi, al auditar, la IA no solo
        tira de los cheat sheets sino que sabe QUE herramienta aplicar (todo hilado). Fuente
        unica: si se anade una herramienta a toolcheck, aparece sola en el RAG. Best-effort."""
        try:
            from .toolcheck import tool_catalog
            cats = {"static": "analisis estatico / triage", "rop": "ROP / gadgets",
                    "symbolic": "simbolico / fuzzing", "dynamic": "dinamico / debug",
                    "exploit": "explotacion / sandbox"}
            for t in tool_catalog():
                cat = cats.get(t.kind, t.kind)
                title = f"{t.name} ({cat})"
                text = (f"Herramienta de {cat}: {t.name}. Se usa para: {t.used_for}. "
                        f"binoracle la detecta con el comando 'tools'.")
                self._add("tools/" + re.sub(r"[^a-z0-9]+", "-", t.name.lower()).strip("-"),
                          title, text)
        except Exception:
            pass

    _NOISE_TITLES = {"table of contents", "contents", "index", "additional resources",
                     "see also", "references", "further reading"}

    def _add(self, doc: str, title: str, text: str) -> None:
        # Descarta secciones de indice/navegacion (TOC, listas de enlaces) que solo meten ruido.
        t = title.strip().lower().lstrip("# ")
        if t in self._NOISE_TITLES or t.startswith("---"):   # TOC o frontmatter YAML
            return
        body = f"{title}\n{text}"
        # Descarta contenido con CJK (chino) residual: binoracle trabaja en ES/EN. El umbral es
        # bajo (2%) para cazar traducciones parciales que dejaron titulos/terminos en chino.
        cjk = sum(1 for ch in body if "一" <= ch <= "鿿")
        if cjk / max(len(body), 1) > 0.02:
            return
        lines = [l for l in text.splitlines() if l.strip()]
        if lines:
            linkish = sum(1 for l in lines if l.lstrip().startswith(("- [", "* [", "[")) or "](" in l)
            if linkish / len(lines) > 0.6:      # seccion mayormente enlaces -> es un indice
                return
        # Dedup exacto: el mismo tema aparece en varios corpus importados (p.ej. anti-analysis
        # esta en ctf-reverse y en reverse-skill). Un chunk identico repetido gasta un slot del
        # top-k con contenido que ya tienes; nos quedamos con la primera aparicion.
        key = (title.strip(), text.strip())
        if key in self._seen_chunks:
            return
        self._seen_chunks.add(key)
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
        for c, _score in hits:
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


def reload_kb() -> KnowledgeBase:
    """Reconstruye la base de conocimiento desde disco tras aprender material nuevo (comando
    learn). Reindexa y, si las capas semanticas estaban activas (env/pref/auto), el nuevo
    __init__ las vuelve a levantar solo; los embeddings se recalculan solo si el contenido
    cambio (la cache va por hash de contenido)."""
    global _CACHE
    _CACHE = KnowledgeBase()
    return _CACHE


def configure(embed=None, expand=None, rerank=None) -> str:
    """Reconfigura el RAG en caliente (desde la web, sin reiniciar). Cada flag None se deja
    igual. Al activar embeddings, carga de cache (instantaneo) o los construye. Devuelve el
    status resultante."""
    kb = get_kb()
    if expand is not None:
        kb._use_expand_llm = bool(expand)
    if rerank is not None:
        kb._use_rerank = bool(rerank)
    if embed is not None:
        kb._embed_requested = bool(embed)
        if embed and kb.embeds is None:
            kb._init_embeddings()          # carga cache o construye
        elif not embed:
            kb.embeds = None
            kb.embed_mode = "off"
    # Persistir el estado CONFIGURADO (no si ya termino de cargar) para que sobreviva a
    # reinicios del servidor y no se guarde 'false' solo por pillar el toggle en pleno build.
    _save_rag_prefs({"embed": kb._embed_requested,
                     "expand": kb._use_expand_llm, "rerank": kb._use_rerank})
    return kb.status()


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
    # Arch/formato: hacen que el audit tire tambien del conocimiento de REVERSING de la
    # plataforma (Mach-O, PE/DLL, DEX/APK, ARM/MIPS, .NET...), no solo de los cheat sheets pwn.
    for key in ("arch", "format"):
        v = str(facts.get(key) or "").strip()
        if v and v not in ("?", "unknown"):
            parts.append(v)
    if facts.get("category"):
        parts.append(str(facts["category"]))
    return " ".join(parts)
