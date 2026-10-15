"""Cliente MCP para la extension OFICIAL de Burp Suite (github.com/PortSwigger/mcp-server,
instalada en Burp via su tab Extensions -- ver burpmcp.py/BurpMCPClient.connect()). Deja que los
verificadores manden sus peticiones HTTP A TRAVES de Burp (via la tool que esa extension expone
para mandar una peticion HTTP/1.1 cruda) en vez de directo con `requests` -- asi cada intento
aparece en el Proxy/Repeater/historial de Burp mientras corre una verificacion.

La extension genera el nombre real de cada tool en tiempo de build de Kotlin, a partir del
nombre de su data class de parametros (no son constantes documentadas/estables) -- por eso
BurpMCPClient NUNCA asume un nombre fijo: descubre las tools reales al conectar
(`session.list_tools()`) y busca la que necesita por FRAGMENTOS normalizados (ver find_tool()).
Si la extension cambia el nombre exacto en una version futura, esto sigue encontrandola; un
nombre hardcodeado se habria roto en silencio.

Transporte: SSE (Server-Sent Events) contra la URL que la extension publica en su tab MCP de
Burp (por defecto http://127.0.0.1:9876/sse). El SDK oficial de MCP es asincrono (asyncio); el
resto de binoracle es sincrono (requests), asi que BurpMCPClient corre su propio event loop en
un hilo de fondo y expone una API sincrona normal -- ningun verificador necesita saber que por
debajo hay asyncio."""
from __future__ import annotations

import asyncio
import re
import threading
from dataclasses import dataclass, field
from email.parser import Parser
from typing import Dict, Optional
from urllib.parse import urlencode, urlsplit


class BurpMCPError(Exception):
    pass


def _normalize(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


class BurpMCPClient:
    """Conexion sincrona al servidor MCP de la extension de Burp. Uso:

        client = BurpMCPClient("http://127.0.0.1:9876/sse")
        client.connect()
        try:
            ...
        finally:
            client.close()

    o como context manager (`with BurpMCPClient(url) as client:`)."""

    def __init__(self, sse_url: str = "http://127.0.0.1:9876/sse", timeout: float = 20.0):
        self.sse_url = sse_url
        self.timeout = timeout
        self.tools: Dict[str, object] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._sse_cm = None
        self._session_cm = None
        self._session = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def connect(self):
        if self._loop is not None:
            return
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        fut = asyncio.run_coroutine_threadsafe(self._connect_async(), self._loop)
        try:
            fut.result(self.timeout)
        except Exception as e:
            self.close()
            raise BurpMCPError(
                f"no se pudo conectar al servidor MCP de Burp en {self.sse_url} -- comprueba "
                f"que la extension 'MCP Server' este instalada Y MARCADA 'Extension loaded' en "
                f"la tab Extensions de Burp, y que su tab MCP tenga el servidor activado "
                f"('Enabled') en el host/puerto configurado aqui ({e})") from e

    async def _connect_async(self):
        from mcp import ClientSession
        from mcp.client.sse import sse_client
        self._sse_cm = sse_client(self.sse_url)
        read, write = await self._sse_cm.__aenter__()
        self._session_cm = ClientSession(read, write)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()
        listed = await self._session.list_tools()
        self.tools = {t.name: t for t in listed.tools}

    def close(self):
        if self._loop is None:
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(self._close_async(), self._loop)
            fut.result(self.timeout)
        except Exception:
            pass
        try:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
        except Exception:
            pass
        self._loop = None

    async def _close_async(self):
        if self._session_cm is not None:
            try:
                await self._session_cm.__aexit__(None, None, None)
            except Exception:
                pass
        if self._sse_cm is not None:
            try:
                await self._sse_cm.__aexit__(None, None, None)
            except Exception:
                pass

    def find_tool(self, *name_fragments: str) -> Optional[str]:
        """Nombre REAL de la tool que contiene TODOS los fragmentos dados (normalizados: solo
        a-z0-9, minuscula) -- p.ej. find_tool('send','http1','request') encuentra tanto
        'send_http1_request' como 'sendHttp1Request' o 'SendHttp1Request', lo que sea que la
        extension haya generado en esa build concreta."""
        fragments = [_normalize(f) for f in name_fragments]
        for name in self.tools:
            n = _normalize(name)
            if all(f in n for f in fragments):
                return name
        return None

    def call_tool(self, name: str, arguments: dict) -> str:
        if self._loop is None:
            raise BurpMCPError("BurpMCPClient.call_tool() llamado sin connect()")
        fut = asyncio.run_coroutine_threadsafe(self._call_tool_async(name, arguments), self._loop)
        return fut.result(self.timeout)

    async def _call_tool_async(self, name: str, arguments: dict) -> str:
        result = await self._session.call_tool(name, arguments)
        parts = []
        for c in result.content:
            text = getattr(c, "text", None)
            if text is not None:
                parts.append(text)
        if getattr(result, "isError", False):
            raise BurpMCPError(f"la tool '{name}' de Burp devolvio error: {''.join(parts)}")
        return "".join(parts)


@dataclass
class BurpMCPResponse:
    """Analoga minima de requests.Response -- solo los atributos que los verificadores de
    binoracle de verdad usan (confirmado por grep: .status_code, .text, .headers.get(...))."""
    status_code: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    set_cookie_headers: list = field(default_factory=list)
    text: str = ""
    raw_response: str = ""


def _parse_raw_http_response(raw: str) -> BurpMCPResponse:
    """Parsea una respuesta HTTP/1.1 cruda (texto exacto que devuelve la tool send_http1_request
    de Burp) en un objeto compatible -- usa email.parser (libreria estandar, no una regex casera)
    para las cabeceras, igual que hace internamente http.client."""
    if not raw:
        return BurpMCPResponse(status_code=0, reason="(sin respuesta)", raw_response=raw)
    head, _, body = raw.partition("\r\n\r\n")
    if "\r\n\r\n" not in raw:
        head, _, body = raw.partition("\n\n")
    lines = head.split("\r\n") if "\r\n" in head else head.split("\n")
    status_line = lines[0] if lines else ""
    m = re.match(r"HTTP/\d\.\d\s+(\d+)\s*(.*)", status_line)
    status_code = int(m.group(1)) if m else 0
    reason = m.group(2).strip() if m else ""
    header_text = "\n".join(lines[1:])
    msg = Parser().parsestr(header_text)
    # dict(msg.items()) colapsaria cabeceras repetidas a la ULTIMA (confirmado: un Message de
    # email.parser SI guarda todas las ocurrencias, pero dict() se queda solo con la ultima clave
    # repetida) -- Set-Cookie casi siempre viene repetida (una por cada cookie), asi que se
    # extrae aparte con get_all() para no perder ninguna; el resto de cabeceras (donde un
    # duplicado es raro y el uso real de binoracle es .get() de una sola, p.ej. Location) se
    # queda como dict simple.
    headers = dict(msg.items())
    set_cookie_headers = msg.get_all("Set-Cookie") or []
    return BurpMCPResponse(status_code=status_code, reason=reason, headers=headers,
                           set_cookie_headers=set_cookie_headers, text=body, raw_response=raw)


def _build_raw_http1_request(method: str, path_with_query: str, host: str, headers: dict,
                             body: str) -> str:
    hdrs = dict(headers or {})
    hdrs.setdefault("Host", host)
    hdrs.setdefault("Connection", "close")
    if body:
        hdrs["Content-Length"] = str(len(body.encode("utf-8", errors="replace")))
    header_block = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    return f"{method} {path_with_query} HTTP/1.1\r\n{header_block}\r\n{body}"


class BurpHttpTransport:
    """Adaptador con la MISMA firma que `requests.request()` (method, url, params=, data=,
    headers=, timeout=, allow_redirects=) que los verificadores genericos ya llaman -- pero manda
    la peticion REAL a traves de Burp (via su tool de peticion HTTP/1.1), asi que aparece en el
    Proxy/historial/Repeater de Burp. `allow_redirects` se ignora (Burp manda la peticion cruda
    exacta y devuelve la respuesta cruda exacta -- no sigue redirects por su cuenta, que es
    justo lo que necesitan los verificadores de open-redirect: inspeccionar el 3xx real)."""

    def __init__(self, client: BurpMCPClient):
        self.client = client
        self._tool_name = client.find_tool("send", "http1", "request")
        if not self._tool_name:
            raise BurpMCPError(
                "no se encontro en el servidor MCP de Burp ninguna tool de enviar peticion "
                "HTTP/1.1 cruda (se buscaron fragmentos 'send'+'http1'+'request' en "
                f"{sorted(client.tools.keys())}) -- revisa que la extension cargada sea la "
                "oficial github.com/PortSwigger/mcp-server")

    def request(self, method: str, url: str, params=None, data=None, headers=None,
               timeout: float = 20.0, allow_redirects: bool = True, **_ignored) -> BurpMCPResponse:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        https = parsed.scheme == "https"
        path = parsed.path or "/"
        query = parsed.query
        if params:
            extra = urlencode(params, doseq=True)
            query = f"{query}&{extra}" if query else extra
        if query:
            path = f"{path}?{query}"

        body = ""
        hdrs = dict(headers or {})
        if data is not None:
            if isinstance(data, dict):
                body = urlencode(data, doseq=True)
                hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, bytes):
                body = data.decode("latin-1")
            else:
                body = str(data)

        raw_request = _build_raw_http1_request((method or "GET").upper(), path, host, hdrs, body)
        raw_response = self.client.call_tool(self._tool_name, {
            "content": raw_request, "targetHostname": host, "targetPort": port,
            "usesHttps": https,
        })
        return _parse_raw_http_response(raw_response)

    def get(self, url: str, **kwargs) -> BurpMCPResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> BurpMCPResponse:
        return self.request("POST", url, **kwargs)


@dataclass
class _SimpleCookie:
    """Lo minimo que los verificadores de verdad leen de requests.Session().cookies (confirmado
    por grep: .name/.value, nunca dominio/expiracion/flags)."""
    name: str
    value: str


class _CookieJarAdapter:
    """requests.Session().cookies soporta DOS formas de acceso a la vez -- iterar (da objetos
    Cookie con .name/.value) Y lookup tipo dict (.get(nombre) -> valor) -- confirmado en vivo
    contra requests de verdad. joomlaverify.py usa la segunda (`s.cookies.get(...)`), el resto
    la primera; esta clase imita ambas sobre el dict interno de BurpSession."""

    def __init__(self, values: Dict[str, str]):
        self._values = values

    def __iter__(self):
        return iter(_SimpleCookie(k, v) for k, v in self._values.items())

    def get(self, name: str, default=None):
        return self._values.get(name, default)


class BurpSession:
    """Analogo de requests.Session() -- incluido su cookie jar persistente entre peticiones --
    pero mandando cada peticion REAL a traves de Burp. Los verificadores CMS-especificos
    (WordPress/Drupal/Joomla) necesitan esto, a diferencia de los genericos (BurpHttpTransport a
    secas vale ahi: no hay login de por medio): un login real manda un Set-Cookie que hay que
    reenviar en TODAS las peticiones siguientes de la misma sesion, o el 'segundo login' que
    prueba account-takeover (y todo lo demas que depende de estar autenticado) nunca veria la
    sesion activa.

    Simplificado a proposito frente a un CookieJar completo (RFC 6265, dominio/path/expiracion):
    cada verificador opera contra UN SOLO host (el laboratorio efimero propio), nunca sigue
    redirects entre dominios con esta sesion, asi que un dict nombre->valor basta -- un CookieJar
    completo seria complejidad sin beneficio real aqui."""

    def __init__(self, client: "BurpMCPClient"):
        self.client = client
        self._transport = BurpHttpTransport(client)
        self._cookie_values: Dict[str, str] = {}

    @property
    def cookies(self):
        return _CookieJarAdapter(self._cookie_values)

    def request(self, method: str, url: str, params=None, data=None, headers=None,
               timeout: float = 20.0, allow_redirects: bool = True, **kwargs) -> BurpMCPResponse:
        hdrs = dict(headers or {})
        if self._cookie_values:
            hdrs.setdefault("Cookie", "; ".join(f"{k}={v}" for k, v in self._cookie_values.items()))
        resp = self._transport.request(method, url, params=params, data=data, headers=hdrs,
                                       timeout=timeout, allow_redirects=allow_redirects, **kwargs)
        for raw_cookie in resp.set_cookie_headers:
            name_value = raw_cookie.split(";", 1)[0]
            name, sep, value = name_value.partition("=")
            if sep:
                self._cookie_values[name.strip()] = value.strip()
        return resp

    def get(self, url: str, **kwargs) -> BurpMCPResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> BurpMCPResponse:
        return self.request("POST", url, **kwargs)
