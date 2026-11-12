# Material real para la charla — exploits construidos y verificados por binoracle

Todo lo de esta carpeta es real: código y salida generados por el propio binoracle
(`autopwn`/`investigate`), re-ejecutado contra los binarios/objetivos reales el 12 de
noviembre de 2026. Nada aquí es una plantilla rellenada a mano ni una simulación.

## `pocs/` — el código real de cada exploit

Son los drivers de explotación (`_DRIVER`) que `binoracle/workflows/auto*.py` usa
internamente para verificar cada técnica por ejecución real (pwntools, proceso nativo),
extraídos tal cual y confirmados de nuevo ejecutándolos de forma independiente.
Los `.sh` son los PoCs HTTP/CLI reales usados contra los dos CVEs públicos.

## `reports/` — informes completos generados por binoracle

Cada `<nombre>.md`/`.json` es la salida íntegra, sin editar, de `binoracle autopwn
samples/bin/<nombre>` (o `binoracle investigate <CVE>` para los `.html`/`.json` de
CVEs reales): contexto del binario, todas las combinaciones de técnicas probadas (las
que no funcionaron también, con el motivo real), la traza de ejecución, y la
verificación final. Para los CVEs, incluye la hipótesis del LLM, el código fuente real
descargado, la petición HTTP real enviada y la confirmación independiente del efecto.

Solo objetivos autorizados (práctica propia / CTF / laboratorio efímero). Nada de esto
se ejecutó contra un sistema de producción o de un tercero.
