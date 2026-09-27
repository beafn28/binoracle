"""Seguridad de comunicaciones y criptografia.

Detecta transmision sin cifrar (http/ftp/telnet en claro), validacion de certificados
desactivada (aceptar cualquier cert -> MITM), y uso de criptografia debil o rota (MD5, SHA1,
DES, RC4, modo ECB). Grounded en imports (r2 ii) y strings (izz). Curado para bajos FP.
"""
from __future__ import annotations

import re
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding


def _imp(reg):
    t = reg.get("r2_imports"); r = t.run() if t else None
    return (r.data or "").lower() if r and r.ok else ""


def _str(reg):
    t = reg.get("r2_strings"); r = t.run() if t else None
    return (r.data or "") if r and r.ok else ""


def _f(t_es, t_en, sev, ev, r_es, r_en, rec_es, rec_en, lang):
    return Finding(title=t_es if lang == "es" else t_en, severity=sev, verdict="grounded",
                   evidence=ev, location="comunicaciones / criptografia",
                   rationale=r_es if lang == "es" else r_en,
                   recommendation=rec_es if lang == "es" else rec_en,
                   rationale_en=r_en, recommendation_en=rec_en)


# marcadores de crypto debil en imports/strings -> (severidad, ES, EN)
_WEAK = [
    (re.compile(r"\b(md5(_init|_update|_final)?|md4)\b", re.I), "medium",
     "Hash criptografico roto (MD5/MD4): colisiones triviales, no apto para integridad/firmas.",
     "Broken cryptographic hash (MD5/MD4): trivial collisions, unfit for integrity/signatures."),
    (re.compile(r"\bsha1(_init|_update|_final)?\b", re.I), "low",
     "SHA-1 esta deprecado (colisiones): no lo uses para firmas ni integridad nueva.",
     "SHA-1 is deprecated (collisions): do not use it for new signatures/integrity."),
    (re.compile(r"\b(des_(encrypt|set_key|ecb)|des_crypt|\bdes\b|3des|des3)\b", re.I), "medium",
     "Cifrado DES/3DES debil (clave corta): sustituible por AES.",
     "Weak DES/3DES cipher (short key): replace with AES."),
    (re.compile(r"\b(rc4|arc4|arcfour)\b", re.I), "medium",
     "Cifrado de flujo RC4 roto: no ofrece confidencialidad real.",
     "Broken RC4 stream cipher: no real confidentiality."),
    (re.compile(r"_ecb(_|\b)|EVP_[a-z0-9_]*_ecb", re.I), "medium",
     "Modo de cifrado ECB: filtra patrones del texto plano (bloques identicos -> cifrados identicos).",
     "ECB cipher mode: leaks plaintext patterns (identical blocks -> identical ciphertext)."),
    (re.compile(r"\b(blowfish|bf_(ecb|cbc|set_key)|sweet32)\b", re.I), "medium",
     "Blowfish (bloque de 64 bits): vulnerable a colisiones de bloque (Sweet32) en volumenes grandes.",
     "Blowfish (64-bit block): vulnerable to birthday/block collisions (Sweet32) at high volume."),
    (re.compile(r"\b(cast5|cast-128|\brc2\b|\bidea\b|\bseed_)\b", re.I), "low",
     "Cifrado de bloque anticuado (CAST5/RC2/IDEA): usa AES.",
     "Legacy block cipher (CAST5/RC2/IDEA): use AES."),
    (re.compile(r"\bmd2\b", re.I), "medium",
     "Hash MD2 roto y obsoleto.", "Broken and obsolete MD2 hash."),
    (re.compile(r"\$1\$[./0-9A-Za-z]{8}", re.I), "medium",
     "Hash de contrasena md5crypt ($1$): debil, sin coste ajustable.",
     "md5crypt password hash ($1$): weak, no adjustable work factor."),
]

# protocolos TLS/SSL obsoletos o forzados a version insegura
_DEPRECATED_TLS = re.compile(
    r"\b(SSLv2(_method|_client_method|_server_method)?|SSLv3(_method|_client_method|_server_method)?|"
    r"SSLv23_method|TLSv1_method|TLSv1_1_method|TLS1\.0|TLS1\.1|SSL2|SSL3)\b")

# validacion de certificados desactivada (strings/imports)
_NOVERIFY = re.compile(
    r"SSL_VERIFY_NONE|CURLOPT_SSL_VERIFYPEER|CURLOPT_SSL_VERIFYHOST|InsecureSkipVerify|"
    r"verify\s*=\s*false|check_hostname\s*=\s*False|rejectUnauthorized\s*[:=]\s*false", re.I)


def scan_comms(reg: ToolRegistry, binary: str = "", lang: str = "es") -> List[Finding]:
    findings: List[Finding] = []
    imports = _imp(reg)
    strings = _str(reg)
    blob = imports + "\n" + strings

    # 1) transmision sin cifrar: URLs http:// (no https), ftp://, telnet, ws://, ldap://
    # SOLO si el binario tiene capacidad de red REAL (importa una API de red). Un http:// suelto en
    # las strings -sobre todo URLs de la toolchain (gcc/debian/gnu) en binarios estaticos- NO es
    # evidencia de que transmita nada -> se excluye para no dar falsos positivos.
    from ._binfacts import has_network
    _BENIGN_URL = re.compile(r"(debian\.org|gnu\.org|gcc\.gnu|sourceware|kernel\.org|ubuntu\.com|"
                             r"fsf\.org|/bugs/|bugzilla|schemas\.|w3\.org|example\.(com|org))", re.I)
    cleartext = sorted(set(re.findall(r"\b(?:http|ftp|telnet|ws|ldap)://[^\s\"'<>]{3,60}", strings, re.I)))
    cleartext = [u for u in cleartext
                 if not u.lower().startswith(("https://", "wss://", "ldaps://"))
                 and not _BENIGN_URL.search(u)][:6]
    # esquemas que son inherentemente CLIENTE de red (ws/telnet/ftp/ldap): la URL ya es evidencia de
    # comunicacion. Para http:// (que suele ser una URL de documentacion) exigimos ademas red real.
    _client = any(u.lower().startswith(("ws://", "telnet://", "ftp://", "ldap://")) for u in cleartext)
    if cleartext and (_client or has_network(reg)):
        findings.append(_f(
            "Transmision sin cifrar (texto en claro)", "Cleartext transmission", "medium",
            "[radare2: izz]\n" + "\n".join(cleartext),
            "El binario usa endpoints http/ftp/telnet en claro: el trafico (credenciales, datos, "
            "actualizaciones) viaja sin cifrar y es interceptable/modificable (MITM).",
            "The binary uses cleartext http/ftp/telnet endpoints: traffic (credentials, data, "
            "updates) is unencrypted and interceptable/modifiable (MITM).",
            "Usa TLS (https/ftps) en todo endpoint; para actualizaciones, canal cifrado Y firma "
            "verificada del artefacto.",
            "Use TLS (https/ftps) for every endpoint; for updates, an encrypted channel AND a "
            "verified signature of the artifact.", lang))

    # 2) validacion de certificados desactivada -> MITM
    mv = _NOVERIFY.search(blob)
    if mv:
        findings.append(_f(
            "Validacion de certificado TLS desactivada", "TLS certificate validation disabled", "high",
            f"[radare2: ii/izz]\n{mv.group(0)}",
            "Se acepta cualquier certificado (no se valida cadena/hostname): un atacante en la red "
            "presenta su propio certificado y descifra/modifica la transmision 'cifrada' (MITM).",
            "Any certificate is accepted (no chain/hostname validation): a network attacker presents "
            "their own certificate and decrypts/modifies the 'encrypted' transmission (MITM).",
            "Valida SIEMPRE la cadena y el hostname del certificado; nunca uses VERIFY_NONE / "
            "InsecureSkipVerify en produccion; considera pinning.",
            "Always validate the certificate chain and hostname; never use VERIFY_NONE / "
            "InsecureSkipVerify in production; consider pinning.", lang))

    # 2b) protocolos TLS/SSL obsoletos
    dt = _DEPRECATED_TLS.search(blob)
    if dt:
        findings.append(_f(
            "Protocolo TLS/SSL obsoleto", "Obsolete TLS/SSL protocol", "medium",
            f"[radare2: ii/izz]\n{dt.group(0)}",
            "El binario usa/permite un protocolo obsoleto (" + dt.group(0) + "). SSLv2/SSLv3/TLS1.0/1.1 "
            "tienen debilidades conocidas (POODLE, BEAST, downgrade) y estan retirados.",
            "The binary uses/allows an obsolete protocol (" + dt.group(0) + "). SSLv2/SSLv3/TLS1.0/1.1 "
            "have known weaknesses (POODLE, BEAST, downgrade) and are deprecated.",
            "Exige TLS 1.2+ (mejor 1.3) y desactiva las versiones antiguas; usa *_method modernos "
            "(TLS_method con min version fijada).",
            "Require TLS 1.2+ (ideally 1.3) and disable old versions; use modern *_method (TLS_method "
            "with a pinned minimum version).", lang))

    # 3) crypto debil/rota
    seen = set()
    for rx, sev, r_es, r_en in _WEAK:
        m = rx.search(blob)
        if m and (label := rx.pattern[:12]) not in seen:
            seen.add(label)
            findings.append(_f(
                "Criptografia debil o rota", "Weak or broken cryptography", sev,
                f"[radare2: ii/izz]\n{m.group(0)}",
                r_es + " (Sin firma/integridad fuerte, la transmision 'cifrada' no es de fiar.)",
                r_en + " (Without strong signing/integrity, 'encrypted' transmission is untrustworthy.)",
                "Usa primitivas modernas: AES-GCM/ChaCha20-Poly1305 para cifrado con integridad, "
                "SHA-256+ para hash, y firma (Ed25519/RSA-PSS) para autenticidad.",
                "Use modern primitives: AES-GCM/ChaCha20-Poly1305 for authenticated encryption, "
                "SHA-256+ for hashing, and signatures (Ed25519/RSA-PSS) for authenticity.", lang))

    # 4) PRNG inseguro para uso de seguridad (rand/srand/random no son criptograficos). Nombres de
    # import PARSEADOS (imported_names): el regex anterior exigia el prefijo 'sym.imp.' que no
    # siempre aparece en la salida de r2 (algunos binarios listan solo el nombre bare), lo que
    # producia un falso NEGATIVO (rand() real, no detectado) -- confirmado con un binario sintetico.
    from ._binfacts import imported_names
    _prng_names = {"rand", "srand", "random", "srandom", "rand_r", "drand48"}
    prng_hit = imported_names(reg) & _prng_names
    if prng_hit and not re.search(r"getrandom|RAND_bytes|arc4random|/dev/urandom", blob, re.I):
        findings.append(_f(
            "Generador de aleatorios inseguro (PRNG no criptografico)",
            "Insecure randomness (non-cryptographic PRNG)", "medium",
            f"[radare2: ii]\n{', '.join(sorted(prng_hit))}",
            "El binario usa rand()/random() (PRNG predecible). Si se usa para tokens, claves, IVs, "
            "nonces o IDs de sesion, un atacante puede predecirlos.",
            "The binary uses rand()/random() (predictable PRNG). If used for tokens, keys, IVs, "
            "nonces or session IDs, an attacker can predict them.",
            "Para uso de seguridad usa un CSPRNG: getrandom(2), /dev/urandom, RAND_bytes o "
            "arc4random.",
            "For security use a CSPRNG: getrandom(2), /dev/urandom, RAND_bytes or arc4random.", lang))
    return findings
