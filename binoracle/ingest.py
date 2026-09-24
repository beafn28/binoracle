"""Aprendizaje automatico: absorbe carpetas de skills/docs a la base de conocimiento.

Automatiza lo que antes se hacia a mano al importar un corpus (ghidra-rpc, r0crawl...):
1. Recorre la carpeta buscando .md.
2. Clasifica cada fichero: se queda si es reversing de binarios, se descarta si es
   web/appsec/meta/router (misma politica que el resto de binoracle).
3. Detecta contenido en chino y lo separa para traducir (no lo indexa a medias).
4. Copia lo que se queda a kb/skills/<nombre>/ (los manifiestos/routers se saltan solos
   al indexar, via _MANIFEST_DOCS).

Todo local y deterministico. `learn()` es dry-run por defecto; con apply=True escribe.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

_KB_SKILLS = Path(__file__).resolve().parent / "kb" / "skills"
_CJK = re.compile(r"[一-鿿]")

# --- Politica de clasificacion (reversing de binarios se queda; web/appsec/meta fuera) ---

# Nombres/carpeta que se descartan enteros (web/anti-bot/captcha/negocio).
_DROP_PREFIX = ("vendor-", "web-")
_DROP_SUBSTR = (
    "anti-bot", "captcha", "fingerprint", "recaptcha", "turnstile", "waf", "akamai",
    "datadome", "perimeterx", "cloud-api", "graphql", "websocket", "miniprogram",
    "webpack", "source-map", "webcrypto", "detection-engineering", "detection-rule",
    "llm-agent", "mass-assignment", "browser-env", "browser-runtime", "hybrid-webview",
    "airline", "ecommerce", "finance-market", "government-procurement", "hotel-travel",
    "logistics-query", "media-streaming", "mobile-pentest", "proxy-traffic",
    # Active Directory / Windows-identidad / red interna (no binario):
    "kerberos", "ad-certificate", "certificate-abuse", "relay-coercion", "credential-pivot",
    "credential-chain", "dpapi", "identity-windows", "windows-pivot", "mailbox", "ntlm-relay",
    # cloud / k8s / contenedores / supply-chain / colas (no binario):
    "k8s", "kubernetes", "control-plane", "container-runtime", "agent-cloud", "supply-chain",
    "queue-worker", "cloud-metadata",
    # web / smuggling / render / forense / stego (no binario):
    "smuggling", "template-render", "normalization", "forensic", "stego", "mailbox-abuse",
    # andamiaje / doc-tooling / web-bundling (no conocimiento de reversing):
    "router-matrix", "src-hunter", "sourcemap", "diagram-generator", "docs-generator",
    "api-security",
)
# Basenames que nunca son conocimiento (manifiestos/plantillas/indices/meta de repo).
_DROP_BASENAME = {
    "readme", "index", "_index", "_template", "contribute-back", "tool-index",
    "agents", "claude", "changelog", "contributing", "git_commit_checklist",
    "task-artifacts", "task-input-template", "mcp-task-template",
    "rules", "routing", "router-matrix", "reporting", "master-routing",
}
# SKILL.md es ambiguo: unas veces es un ROUTER (fuera) y otras el propio modulo de
# conocimiento (se queda). Se distingue por contenido: un router da ordenes de orquestacion.
_ROUTER_SIGNALS = re.compile(
    r"action required|hands?\s*off|routing\.json|sidecar|thin primary|case-init|门闩|"
    r"\bNOW:\s|\bMUST NOT\b|orchestrator", re.I)
# Senales de que el TEXTO es web/appsec (si dominan claramente, se descarta).
_WEB_KW = re.compile(
    r"\b(sqli|xss|ssrf|xxe|csrf|graphql|jwt|oauth|http smuggl|kerberoast|ntlm|"
    r"log4shell|jndi|kubernetes|k8s|actuator|cookie|waf|captcha|recaptcha|"
    r"prompt injection|cors|open redirect)\b", re.I)
# Senales de reversing de binarios (si aparecen, se queda aunque toque temas mixtos).
_BIN_KW = re.compile(
    r"\b(revers|disassembl|decompil|exploit|shellcode|\brop\b|ret2|heap|glibc|tcache|"
    r"\belf\b|\bpe\b|\bdll\b|\bso\b|dex|apk|smali|frida|ghidra|\bida\b|radare|rizin|"
    r"unicorn|angr|qemu|firmware|malware|packer|unpack|obfuscat|ollvm|syscall|seccomp|"
    r"kernel|driver|arm64|aarch64|mips|assembly|gadget|libc|got|plt|canary|format string|"
    r"il2cpp|unity|dotnet|\bjni\b|mach-o|macho|pwn|debugger|breakpoint|patch)\b", re.I)


def _cjk_ratio(text: str) -> float:
    return len(_CJK.findall(text)) / max(len(text), 1)


@dataclass
class Decision:
    path: Path
    rel: str
    verdict: str          # keep | drop | translate
    reason: str


@dataclass
class LearnReport:
    name: str
    kept: list = field(default_factory=list)
    dropped: list = field(default_factory=list)
    to_translate: list = field(default_factory=list)
    applied: bool = False
    dest: str = ""

    def summary(self) -> str:
        lines = [f"aprendizaje '{self.name}': {len(self.kept)} se quedan | "
                 f"{len(self.dropped)} fuera | {len(self.to_translate)} a traducir"
                 + ("  (APLICADO)" if self.applied else "  (dry-run; usa --apply)")]
        if self.applied and self.dest:
            lines.append(f"  destino: {self.dest}")
        by_reason: dict = {}
        for d in self.dropped:
            by_reason[d.reason] = by_reason.get(d.reason, 0) + 1
        if by_reason:
            lines.append("  descartes: " + ", ".join(f"{k}={v}" for k, v in
                                                      sorted(by_reason.items(), key=lambda x: -x[1])))
        if self.to_translate:
            lines.append("  a traducir (chino): " +
                         ", ".join(d.rel for d in self.to_translate[:8]) +
                         (" ..." if len(self.to_translate) > 8 else ""))
        return "\n".join(lines)


def classify(rel: str, text: str) -> tuple[str, str]:
    """Decide keep|drop|translate para un fichero. rel = ruta relativa; text = contenido."""
    low = rel.lower()
    base = low.rsplit("/", 1)[-1].removesuffix(".md")
    seg0 = low.split("/", 1)[0]
    if base in _DROP_BASENAME:
        return "drop", "manifiesto/meta"
    if base == "skill":
        # Router (orquestacion) -> fuera; modulo de conocimiento con contenido real -> se queda.
        # Un SKILL corto sin ninguna senal binaria tambien es router/placeholder.
        if _ROUTER_SIGNALS.search(text) or (len(text.strip()) < 200 and not _BIN_KW.search(text)):
            return "drop", "router (SKILL)"
    if seg0.startswith(_DROP_PREFIX) or any(s in low for s in _DROP_SUBSTR):
        return "drop", "web/appsec (nombre)"
    if not text.strip():
        return "drop", "vacio"
    # Chino: separar para traducir (no indexar a medias).
    if _cjk_ratio(text) >= 0.02:
        return "translate", "chino"
    # Senal de contenido: si es claramente web y no hay senal binaria, fuera.
    web = len(_WEB_KW.findall(text))
    binv = len(_BIN_KW.findall(text))
    if web > binv and binv < 2:
        return "drop", "web/appsec (contenido)"
    return "keep", "binario/RE"


def learn(src: str, name: str | None = None, apply: bool = False,
          kb_skills: Path = _KB_SKILLS) -> LearnReport:
    """Aprende de una carpeta: clasifica y (si apply) copia lo binario-RE a kb/skills/<name>/.

    Devuelve un LearnReport. Es idempotente: reescribe los ficheros que se quedan.
    """
    root = Path(src).expanduser().resolve()
    name = name or re.sub(r"[^a-z0-9_-]+", "-", root.name.lower()).strip("-") or "corpus"
    rep = LearnReport(name=name)
    dest = kb_skills / name
    rep.dest = str(dest)
    if not root.is_dir():
        rep.dropped.append(Decision(root, str(root), "drop", "no existe"))
        return rep
    for md in sorted(root.rglob("*.md")):
        rel = str(md.relative_to(root)).replace("\\", "/")
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        verdict, reason = classify(rel, text)
        dec = Decision(md, rel, verdict, reason)
        if verdict == "keep":
            rep.kept.append(dec)
        elif verdict == "translate":
            rep.to_translate.append(dec)
        else:
            rep.dropped.append(dec)
    if apply and rep.kept:
        for dec in rep.kept:
            # Aplana SKILL.md al nombre del modulo para que no lo excluya _MANIFEST_DOCS.
            out_rel = dec.rel
            parts = out_rel.rsplit("/", 1)
            if parts[-1].lower() == "skill.md":
                out_rel = (parts[0] + ".md") if len(parts) > 1 else dec.path.parent.name + ".md"
            out = dest / out_rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(dec.path, out)
        rep.applied = True
    return rep
