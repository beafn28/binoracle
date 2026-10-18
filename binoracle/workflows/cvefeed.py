"""Vigila el canal publico de Telegram @CVENotify (notifica CVEs nuevas en cuanto se publican)
para alimentar binoracle automaticamente: lee su vista previa web publica (t.me/s/<canal>, sin
necesitar token de bot ni cuenta de Telegram), detecta los CVE-ID mencionados en mensajes NUEVOS
desde la ultima vez que se miro, y marca cuales tienen pinta de ser de un CMS (WordPress/Drupal/
Joomla) -- no para descartar el resto (investigate-watch es GENERICO por defecto: procesa
cualquier CVE, de cualquier tecnologia, desarrollando hipotesis+PoC igual), sino para que se
pueda priorizar/filtrar las que SI pueden llegar a un laboratorio real y VERIFICADO de principio
a fin hoy (ver wpverify.py/drupalverify.py/joomlaverify.py) cuando interese ahorrar tiempo/Docker.

Solo stdlib (urllib + html.parser), sin dependencias nuevas -- consistente con el resto del
proyecto (ver pyproject.toml: "Core runtime uses ONLY the Python standard library").

Es best-effort: la vista previa publica de Telegram no es una API estable ni documentada -- si
Telegram cambia su HTML, esto puede dejar de encontrar mensajes (se degrada a 'sin novedades
nuevas', nunca lanza una excepcion que tumbe un watch loop)."""
from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import List

from .cvelookup import is_cve_id  # noqa: F401  (reexportado por comodidad para quien importe esto)

_PREVIEW_URL_TMPL = "https://t.me/s/{channel}"
_DEFAULT_CHANNEL = "CVENotify"

_STATE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle")

# cada mensaje real del canal lleva data-post="<canal>/<id numerico>" en su div contenedor --
# es el unico ancla estable que usamos para saber "esto es un mensaje" y "es mas nuevo que el
# ultimo que vimos" (el HTML interno de Telegram, con o sin enlaces/emoji/formato, varia mucho
# mas y no conviene depender de el para eso).
_POST_ID_RE = re.compile(r'data-post="[^"/]+/(\d+)"')
_MESSAGE_TEXT_CLASS = "tgme_widget_message_text"

_CVE_FINDALL_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)

_CMS_KEYWORDS = ("wordpress", "wp-", "wp plugin", "drupal", "joomla", "plugin for wordpress",
                 "wordpress plugin", "wordpress theme")


class _TextExtractor(HTMLParser):
    """Extrae el texto plano de un fragmento HTML, tratando <br> como salto de linea (asi se ve
    el mensaje real en Telegram) -- mas robusto que un regex de 'quita todas las etiquetas'
    porque el propio parser de la stdlib gestiona etiquetas sin cerrar y entidades HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._parts: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "br":
            self._parts.append("\n")

    def handle_data(self, data):
        self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


def _strip_html(fragment: str) -> str:
    p = _TextExtractor()
    try:
        p.feed(fragment)
    except Exception:
        pass
    return p.text()


@dataclass
class TelegramMessage:
    post_id: int
    text: str


def _fetch_preview_html(channel: str, timeout: float = 20.0) -> str:
    req = urllib.request.Request(
        _PREVIEW_URL_TMPL.format(channel=channel),
        headers={"User-Agent": "Mozilla/5.0 (binoracle authorized-research CVE feed watcher)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def fetch_channel_messages(channel: str = _DEFAULT_CHANNEL, timeout: float = 20.0
                           ) -> List[TelegramMessage]:
    """Descarga y parsea la vista previa publica del canal. Devuelve los mensajes encontrados,
    en el mismo orden en que Telegram los sirve en esa pagina (del mas antiguo al mas reciente
    de los ~20 ultimos). Nunca lanza: si la pagina no se puede descargar o no se reconoce ningun
    mensaje, devuelve [] (el canal puede haber cambiado de nombre, estar caido, o Telegram haber
    cambiado el HTML de la vista previa)."""
    try:
        doc = _fetch_preview_html(channel, timeout=timeout)
    except Exception:
        return []
    messages: List[TelegramMessage] = []
    # se recorre por posiciones (cada bloque "data-post=...", hasta el siguiente) en vez de un
    # regex monolitico que intente casar mensaje+texto a la vez -- mas tolerante a que varien
    # los atributos/orden de clases alrededor de cada mensaje en el HTML real de Telegram.
    post_matches = list(_POST_ID_RE.finditer(doc))
    for idx, pm in enumerate(post_matches):
        start = pm.end()
        end = post_matches[idx + 1].start() if idx + 1 < len(post_matches) else len(doc)
        block = doc[start:end]
        text_pos = block.find(_MESSAGE_TEXT_CLASS)
        if text_pos == -1:
            continue
        gt = block.find(">", text_pos)
        if gt == -1:
            continue
        close = block.find("</div>", gt)
        if close == -1:
            continue
        text = _strip_html(block[gt + 1:close]).strip()
        if text:
            messages.append(TelegramMessage(post_id=int(pm.group(1)), text=text))
    return messages


def looks_cms_related(text: str) -> bool:
    """Heuristica simple: True si el texto del aviso menciona WordPress/Drupal/Joomla -- las
    unicas plataformas donde wpverify.py/drupalverify.py/joomlaverify.py pueden levantar un
    laboratorio real y confirmar el exploit de principio a fin hoy. Pensado solo para PRIORIZAR
    (el CLI la desactiva con --all), no para descartar nada de forma definitiva: una CVE que no
    la cumple simplemente se investiga igual que con 'binoracle investigate' normal (hipotesis +
    PoC HTTP desarrollado), solo que no se lanza sola porque no hay verificacion dinamica real
    para ella hoy."""
    low = (text or "").lower()
    return any(k in low for k in _CMS_KEYWORDS)


def _state_path(channel: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", channel) or "_"
    return os.path.join(_STATE_DIR, "feed_state", f"{safe}.json")


def _load_last_seen_id(channel: str) -> int:
    try:
        with open(_state_path(channel), "r", encoding="utf-8") as f:
            return int(json.load(f).get("last_post_id", 0))
    except Exception:
        return 0


def _save_last_seen_id(channel: str, post_id: int) -> None:
    path = _state_path(channel)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + f".tmp-{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"last_post_id": post_id}, f)
        os.replace(tmp, path)
    except Exception:
        pass


@dataclass
class CVEMention:
    cve_id: str
    post_id: int
    text: str
    cms_related: bool


def poll_new_cve_mentions(channel: str = _DEFAULT_CHANNEL, timeout: float = 20.0,
                          mark_seen: bool = True) -> List[CVEMention]:
    """Un ciclo de sondeo: descarga la vista previa del canal, se queda solo con los mensajes MAS
    NUEVOS que la ultima vez (segun el estado local persistido en _STATE_DIR), y devuelve una
    mencion por cada CVE-ID DISTINTO citado en ellos (un mismo mensaje puede citar varios, y el
    mismo CVE puede repetirse en mensajes distintos -- solo la primera mencion de cada uno en
    este ciclo). La primera vez que se sondea un canal (sin estado previo), procesa el backlog
    completo que ya esta en la pagina (~20 mensajes) en vez de nada -- es intencional, es la
    forma de "ponerse al dia" en el primer arranque.

    Si `mark_seen` (por defecto), actualiza el estado local al mayor post_id visto EN ESTE
    CICLO, incluso si ninguno de los mensajes nuevos citaba un CVE -- para no quedarse pegado
    reprocesando ruido del canal (anuncios, estadisticas...) que nunca va a convertirse en un
    CVE-ID por mucho que se vuelva a mirar."""
    messages = fetch_channel_messages(channel, timeout=timeout)
    if not messages:
        return []
    last_seen = _load_last_seen_id(channel)
    new_messages = [m for m in messages if m.post_id > last_seen]
    if not new_messages:
        return []
    mentions: List[CVEMention] = []
    seen_cves = set()
    for m in new_messages:
        for cm in _CVE_FINDALL_RE.finditer(m.text):
            cve_id = cm.group(0).upper()
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            mentions.append(CVEMention(cve_id=cve_id, post_id=m.post_id, text=m.text,
                                       cms_related=looks_cms_related(m.text)))
    if mark_seen:
        _save_last_seen_id(channel, max(m.post_id for m in new_messages))
    return mentions
