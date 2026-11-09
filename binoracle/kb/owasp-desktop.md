# OWASP Desktop App Security Top 10 en binoracle (que se prueba y con que)

Marco contra el que binoracle reporta cobertura en una auditoria de binario/desktop (metodologia
Fase 9). Cada categoria tiene un scanner REAL: el informe distingue "con hallazgos", "revisado sin
hallazgo" (scanner ejecutado, nada detectado) y, si algun dia no aplicara, "no evaluado". Nunca se
marca revisado lo que no se examina. Complementa [[methodology]] y [[pentest-binarios]].

| ID | Categoria | Que busca binoracle | Scanner / oraculo |
|----|-----------|---------------------|-------------------|
| DA1 | Injection | inyeccion de comando (system/popen con entrada), backdoors de red | backdoors, commsec |
| DA2 | Broken Authentication | auth por comparacion con credencial hardcodeada (strcmp/memcmp), contrasenas sin hashing | authcheck |
| DA3 | Sensitive Data Exposure | secretos/credenciales/claves/tokens embebidos | secrets |
| DA4 | Improper Cryptography | cripto debil (MD5/SHA1/DES/RC4/ECB), PRNG inseguro | commsec |
| DA5 | Improper Authorization | escalada local: SUID/SGID, escribible por todos | fileperms |
| DA6 | Security Misconfiguration | RPATH/RUNPATH inseguro (library hijack), despliegue en /tmp, cert no validado | fileperms, commsec |
| DA7 | Insecure Communication | trafico sin cifrar (http/ftp/telnet), MITM, callback de red en runtime | commsec, dynamic |
| DA8 | Poor Code Quality | overflow, format string, UAF/double-free/heap, ROP -> hasta exploit verificado | vulnhunt, chainanalyzer, autopoc/autorop/autopie/autoheap/autolibc |
| DA9 | Componentes con vulns conocidas | versiones antiguas de componentes embebidos (glibc/GCC/OpenSSL/zlib/...) | versions |
| DA10 | Registro/monitorizacion insuficiente | binario sensible (SUID/red) sin APIs de logging/auditoria | logging_check |

## Reglas de honestidad (para no sacar cosas falsas)
- El RAG es referencia; los hallazgos salen de los oraculos/scanners, no del texto.
- `verified` solo con prueba por EJECUCION o alcanzabilidad (sandbox/angr). `grounded` = evidencia
  estatica no probada. `unverified` = sin respaldo (no se trata como hecho).
- DA9 reporta la version REAL detectada y marca "antigua" bajo umbral; NO afirma un CVE concreto
  (no hay base de CVEs local): el analista lo contrasta con el aviso del componente.
- DA8 es donde binoracle llega mas lejos: construye la cadena de explotacion y la VERIFICA en el
  sandbox (ret2win, ret2libc, ROP, format-string, heap->shell, ROP-PIE, ret2libc+leak), con la
  prueba (offset/base/marcador uid=0) y un script pwntools reproducible.

## Alcance
Estatico + dinamico sobre el binario cargado. No cubre logica de servidor remoto, fuzzing profundo
ni analisis de red en vivo mas alla de la interceptacion LD_PRELOAD del sandbox. Lo que no se
examina se dice; no se rellena con supuestos.
