# Procedencia

Los ficheros de este directorio son wordlists de payloads reales, copiadas tal cual del
proyecto [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
(swisskyrepo y colaboradores, licencia MIT), bajo:

- `xss_alert_identifiable.txt` <- `XSS Injection/Intruders/xss_alert_identifiable.txt`
- `ssti.fuzz` <- `Server Side Template Injection/Intruder/ssti.fuzz`
- `command_exec.txt` <- `Command Injection/Intruder/command_exec.txt`
- `command-execution-unix.txt` <- `Command Injection/Intruder/command-execution-unix.txt`
- `Open-Redirect-payloads.txt` <- `Open Redirect/Intruder/Open-Redirect-payloads.txt`
- `openredirects.txt` <- `Open Redirect/Intruder/openredirects.txt`
- `open_redirect_wordlist.txt` <- `Open Redirect/Intruder/open_redirect_wordlist.txt`
- `Generic_TimeBased.txt` <- `SQL Injection/Intruder/Generic_TimeBased.txt`
- `xml-attacks.txt` <- `XXE Injection/Intruders/xml-attacks.txt`

`payload_kb.py`, en el directorio padre, PARSEA estos ficheros en tiempo de ejecucion y
generaliza cada linea reemplazando su marcador fijo (un `alert(NNNN)` concreto, un `7*7`
concreto, un host `google.com` concreto, etc.) por el canario/secreto/host que cada
verificador genera de forma aleatoria en cada ejecucion -- nunca se manda una linea tal
cual contra un objetivo real sin esa sustitucion. Las lineas que apuntan a infraestructura
de pruebas de terceros (dominios como `crowdshield.com`/`xerosecurity.com`, usados por los
autores de PayloadsAllTheThings para sus propias pruebas OOB) se descartan explicitamente
al parsear -- binoracle nunca debe hacer que un objetivo bajo analisis llame a un servicio
externo que no sea el propio laboratorio efimero.
