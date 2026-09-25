# Extraccion y triaje de firmware con unblob (cheat sheet)

Flujo moderno y reproducible para desempaquetar una imagen de firmware y llegar al rootfs / a los
binarios antes de reversear. Complementa [[firmware-embedded]] (bare-metal, superficie, emulacion),
[[arm-mips]] y [[ghidra-mcp]]. Regla de oro: trabaja sobre una COPIA en un entorno desechable,
apunta origen/dispositivo/SHA-256, y NUNCA ejecutes lo extraido como parte de la extraccion.

## unblob primero (mejor que binwalk para formatos anidados/raros)
unblob recorre recursivamente, detecta limites de chunk, padding y aleatoriedad (entropia), y
emite un informe JSON. Es la primera opcion; binwalk y extractores por-FS quedan para los huecos.
```bash
unblob --version
unblob --show-external-dependencies      # el paquete pip NO instala todos los extractores
RUN=$(mktemp -d); sha256sum fw.bin > "$RUN/input.sha256"
unblob -p 2 -d 10 -n 1 -e "$RUN/extracted" \
  --report "$RUN/report.json" --log "$RUN/unblob.log" fw.bin > "$RUN/console.txt" 2>&1
```
Claves de interpretacion (grounded, no te fies del exit code):
- un exit 0 o que exista el directorio de salida NO implica extraccion completa. Mira el log,
  el console y los "extraction issues" del report.
- del report interesan: offsets/tamanos de cada componente, rutas de salida, REGIONES DESCONOCIDAS
  (unknown regions) y las estadisticas de aleatoriedad (entropia).
- usa una carpeta NUEVA por intento (no `--force`) para no confundir un fallo con resultados viejos.

## Entropia: donde esta lo cifrado/comprimido
- entropia ~1.0 (alta) y sostenida = cifrado o comprimido (o clave/certificado). Una region grande
  de alta entropia que unblob no supo extraer suele ser el rootfs cifrado o un blob comprimido a mano.
- entropia baja/estructurada = codigo/datos, tablas, texto. Los saltos de entropia marcan fronteras
  entre secciones (bootloader | kernel | rootfs | overlay).
- si una region no se resuelve: comprueba magic bytes al inicio (`xxd | head`), prueba un offset
  manual, o un extractor especifico del FS (abajo). Registra el fallback usado.

## Extractores por sistema de ficheros (para los huecos de unblob)
| FS / formato | Herramienta | Nota |
|--------------|-------------|------|
| SquashFS (estandar y vendor) | `unsquashfs`, **sasquatch** | sasquatch para variantes propietarias (LZMA no estandar) |
| JFFS2 | **jefferson** | flash NOR/NAND antiguas |
| UBIFS / UBI | **ubi_reader** (`ubireader_extract_files`) | flash NAND moderna; primero extrae los volumenes UBI |
| CramFS | `cramfsck` / binwalk | solo lectura, comun en dispositivos pequenos |
| uImage / U-Boot | `dumpimage`, binwalk | cabecera con arch/carga/entry; separa kernel+ramdisk |
| Device Tree | **dtc** (`dtc -I dtb -O dts`) | .dtb -> .dts: mapa de perifericos y direcciones MMIO |

## Triaje estatico del rootfs / binarios
Una vez montado el rootfs, cada binario es un ELF normal (a menudo ARM/MIPS, ver [[arm-mips]]):
- identificar: `file`, `readelf -h` (arch, tipo EXEC/DYN=PIE, endianness), interprete.
- superficie: `strings` (URLs, rutas, comandos, credenciales), `readelf --dyn-syms` (imports),
  `readelf -d` (RPATH/RUNPATH, NEEDED).
- protecciones: `readelf -lW | grep -E 'GNU_RELRO|GNU_STACK'`, y `__stack_chk_fail` / los wrappers
  `*_chk` en `readelf -Ws` (indican FORTIFY). Muchos firmwares no traen canary/NX/PIE.
- objetivos habituales: httpd/servicios propietarios (parsers de peticiones), busybox, binarios de
  actualizacion, y claves/certificados embebidos. Enlaza con [[methodology]] para priorizar.

## Metodologia (5 fases) y automatizacion
1. Extraccion (unblob -> report JSON -> investigar huecos/entropia).
2. Estatico (arch, strings, simbolos, secciones, protecciones -> informe estructurado).
3. Ghidra (base de carga correcta + procesador ARM/MIPS/Cortex-M; scripts de anotacion; ver
   [[ghidra-rpc]] / [[ghidra-mcp]] para conducirlo por API).
4. Emulacion (qemu-system / qiling para binarios del rootfs; firmadyne / FirmAE para routers Linux
   completos; ver [[firmware-embedded]]).
5. Informe (evidencia -> hallazgos con severidad; cada afirmacion respaldada por la salida real).

## Interfaces hardware (obtener el dump o una shell)
- **UART**: consola serie; a menudo shell de U-Boot o root directo (mira TX/RX/GND con un analizador
  logico o multimetro; baudios tipicos 115200).
- **SPI flash**: chip-off + CH341A/flashrom para volcar la NOR sin arrancar el dispositivo.
- **JTAG / SWD**: depuracion on-chip (OpenOCD) para leer/parchear memoria y bypassear arranque.
- **DFU**: modo de actualizacion USB de muchos MCU; puede permitir volcar/flashear sin firma.
