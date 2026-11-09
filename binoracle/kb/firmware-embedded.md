# Firmware / bare-metal / embebido (cheat sheet)

Explotacion y reversing de firmware: routers, IoT, MCUs. A menudo sin SO (bare-metal) o con un
RTOS ligero, sin libc estandar, sin ASLR/NX, y con acceso directo a hardware (MMIO). Objetivo
frecuente: RCE en el dispositivo o extraer secretos.

## Extraccion del firmware
- descarga OTA / dump por SPI flash (chip-off, flashrom, un CH341A) / UART / JTAG.
- binwalk para reconocer y extraer (`binwalk -e fw.bin`): detecta squashfs, cramfs, uImage,
  cabeceras U-Boot, claves, etc. firmware-mod-kit para reempacar.
- si es Linux embebido: montas el rootfs (squashfs-tools) y analizas los binarios (busybox,
  servicios propietarios) como ELF normal (a menudo MIPS/ARM, ver [[arm-mips]]).

## Bare-metal / RTOS (sin SO)
- no hay ELF con secciones estandar; a veces un blob crudo que se mapea a una direccion base.
  Hay que averiguar la base de carga (vector table en Cortex-M: primeras entradas = SP inicial
  + reset handler; da pistas de la base).
- Cortex-M (ARM Thumb): vector table, SVC/PendSV, registros MMIO en direcciones fijas
  (periferico UART/GPIO). Identifica MMIO por accesos a rangos 0x40000000+ tipicos.
- sin NX/ASLR normalmente -> shellcode directo si controlas el flujo; pero las direcciones son
  fijas y el "libc" es codigo propio del firmware (reutiliza sus funciones como gadgets).

## Superficie de ataque
- servicios de red del dispositivo (httpd propietario, UPnP, telnet, TR-069): overflow/command
  injection en el parser de peticiones.
- credenciales/claves hardcoded en el firmware (strings, certificados).
- update sin firma -> flashear firmware modificado.
- interfaces de debug expuestas: UART (shell de U-Boot/root), JTAG.

## Emulacion
- qemu-system-<arch> para arrancar el firmware/kernel embebido.
- qiling para emular binarios del rootfs sin el hardware (hooks de syscalls/MMIO).
- unicorn para emular funciones sueltas (parsers) y fuzzearlas.
- firmadyne / FirmAE para emular firmware de routers Linux completo.

## Herramientas
binwalk, firmware-mod-kit, squashfs-tools, Ghidra (con la base de carga correcta y el
procesador ARM/MIPS/Cortex-M), flashrom, sigrok/logic analyzer, qemu/qiling/unicorn.
