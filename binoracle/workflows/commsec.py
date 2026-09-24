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
]

# validacion de certificados desactivada (strings/imports)
_NOVERIFY = re.compile(
    r"SSL_VERIFY_NONE|CURLOPT_SSL_VERIFYPEER|CURLOPT_SSL_VERIFYHOST|InsecureSkipVerify|"
    r"verify\s*=\s*false|check_hostname\s*=\s*False|rejectUnauthorized\s*[:=]\s*false", re.I)


def scan_comms(reg: ToolRegistry, binary: str = "", lang: str = "es") -> List[Finding]:
    findings: List[Finding] = []
    imports = _imp(reg)
    strings = _str(reg)
    blob = imports + "\n" + strings

    # 1) transmision sin cifrar: URLs http:// (no https), ftp://, telnet
    cleartext = sorted(set(re.findall(r"\b(?:http|ftp|telnet)://[^\s\"'<>]{3,60}", strings, re.I)))
    cleartext = [u for u in cleartext if not u.lower().startswith("https://")][:6]
    if cleartext:
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
    return findings
