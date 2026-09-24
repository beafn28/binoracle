#!/usr/bin/env python3
"""Traduce notas de reversing en chino a ingles con el modelo local (Ollama) e integra el
resultado en la base de conocimiento de binoracle. Reanudable: salta lo ya traducido.

Uso: python3 scripts/translate_cn.py            (usa /tmp/cn_list.txt como entrada)
Env: BINORACLE_OLLAMA_URL, BINORACLE_RAG_LLM_MODEL (def. qwen2.5-coder:7b)
"""
import json, os, re, sys, time, urllib.request
from pathlib import Path

OLLAMA = os.environ.get("BINORACLE_OLLAMA_URL", "http://localhost:11434").rstrip("/")
MODEL = os.environ.get("BINORACLE_RAG_LLM_MODEL", "qwen2.5-coder:7b")
SRC_ROOT = "/tmp/cn_stage"
DST_ROOT = str(Path(__file__).resolve().parent.parent / "binoracle" / "kb" / "skills" / "reverse-skill")
LOG = "/tmp/translate_cn.log"
CJK = re.compile(r"[一-鿿]")


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def gen(prompt, timeout=300):
    data = json.dumps({"model": MODEL, "prompt": prompt, "stream": False,
                       "options": {"temperature": 0.1, "num_ctx": 8192}}).encode()
    req = urllib.request.Request(OLLAMA + "/api/generate", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode()).get("response", "")


def translate_block(text):
    prompt = ("Translate the following binary reverse-engineering / CTF technique note from "
              "Chinese to English. Keep ALL code, shell commands, hex, addresses, tool names "
              "and technical terms verbatim; translate only the prose. Keep the Markdown "
              "structure (headings, lists, code fences). Output ONLY the translated Markdown, "
              "no preamble.\n\n" + text)
    for attempt in range(2):
        try:
            out = gen(prompt)
            if out and CJK.findall(out).__len__() / max(len(out), 1) < 0.05:
                return out
        except Exception as e:
            log(f"  retry ({e})")
            time.sleep(2)
    return None


def _hard_split(part, cap):
    """Trocea una parte grande (sin '## ' internos) por parrafos/lineas para que ningun
    bloque supere 'cap'. Evita mandar un doc de 16k chars entero (revienta num_ctx y timeout)."""
    if len(part) <= cap:
        return [part]
    out, cur = [], ""
    for para in part.split("\n\n"):
        piece = para + "\n\n"
        if len(piece) > cap:                      # parrafo gigante: parte por lineas
            if cur:
                out.append(cur); cur = ""
            line_buf = ""
            for ln in piece.splitlines(keepends=True):
                if len(line_buf) + len(ln) > cap and line_buf:
                    out.append(line_buf); line_buf = ""
                line_buf += ln
            if line_buf:
                cur = line_buf
            continue
        if len(cur) + len(piece) > cap and cur:
            out.append(cur); cur = piece
        else:
            cur += piece
    if cur:
        out.append(cur)
    return out


def split_sections(raw, cap=2500):
    """Trocea por '## ' para caber en contexto; agrupa hasta ~cap chars y ademas parte en
    duro cualquier seccion que por si sola supere el cap (docs largos sin subsecciones)."""
    parts = re.split(r"(?m)^(?=## )", raw)
    blocks, cur = [], ""
    for p in parts:
        if len(p) > cap:                          # seccion grande: agrupa lo pendiente y trocea
            if cur:
                blocks.append(cur); cur = ""
            blocks.extend(_hard_split(p, cap))
        elif len(cur) + len(p) > cap and cur:
            blocks.append(cur); cur = p
        else:
            cur += p
    if cur:
        blocks.append(cur)
    return blocks


def main():
    files = [l.strip() for l in open("/tmp/cn_list.txt") if l.strip()]
    # Sharding para varios workers en paralelo: cada worker procesa un subconjunto disjunto.
    shard_i = int(os.environ.get("SHARD_I", "0"))
    shard_n = int(os.environ.get("SHARD_N", "1"))
    if shard_n > 1:
        files = [f for k, f in enumerate(files) if k % shard_n == shard_i]
        log(f"== worker {shard_i}/{shard_n}: {len(files)} ficheros | modelo {MODEL} ==")
    else:
        log(f"== traduccion CN->EN: {len(files)} ficheros | modelo {MODEL} ==")
    done = 0
    for i, src in enumerate(files, 1):
        rel = os.path.relpath(src, SRC_ROOT)
        dst = os.path.join(DST_ROOT, rel)
        if os.path.exists(dst):
            body = open(dst, encoding="utf-8", errors="replace").read()
            if body and CJK.findall(body).__len__() / max(len(body), 1) < 0.05:
                done += 1
                continue  # ya traducido
        raw = open(src, encoding="utf-8", errors="replace").read()
        if not raw.strip():
            continue
        log(f"[{i}/{len(files)}] {rel} ({len(raw)} chars)")
        blocks = split_sections(raw)
        out_parts, ok = [], True
        for b in blocks:
            tr = translate_block(b)
            if tr is None:
                ok = False; break
            out_parts.append(tr)
        if not ok:
            log(f"  FALLO, se deja para otra pasada")
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as f:
            f.write("\n\n".join(out_parts))
        done += 1
        log(f"  ok -> {rel}  ({done} traducidos)")
    log(f"== fin: {done}/{len(files)} traducidos ==")


if __name__ == "__main__":
    main()
