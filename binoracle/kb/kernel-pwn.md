# Kernel pwn Linux (cheat sheet)

Explotacion de un modulo/driver del kernel (LKM) vulnerable. Objetivo tipico: escalar a root
en una VM de CTF. El "shell" se consigue elevando las credenciales del proceso actual.

## Escalada de privilegios (el objetivo)
- `commit_creds(prepare_kernel_cred(0))` -> da al proceso actual las credenciales de init
  (root). prepare_kernel_cred(0) devuelve un cred de kernel; commit_creds lo aplica.
- Tras elevar en un ROP de kernel, hay que volver a userland limpio: `swapgs; iretq`
  (guardando antes rip/cs/rflags/rsp/ss de userland) y luego lanzar una shell.

## ret2usr (sin mitigaciones)
Si SMEP/SMAP estan desactivados: apunta el flujo del kernel a una funcion TUYA en userland
que llame `commit_creds(prepare_kernel_cred(0))`. Sencillo pero raro en retos modernos.

## Mitigaciones y bypass
- SMEP (Supervisor Mode Execution Prevention): marca las paginas de userland como no
  ejecutables desde kernel -> ret2usr no vale. Solucion: ROP en kernel para llamar
  commit_creds(prepare_kernel_cred(0)) con gadgets del propio kernel (o poner CR4 sin el bit
  de SMEP con un gadget `mov cr4`).
- SMAP (Supervisor Mode Access Prevention): el kernel no puede ni leer/escribir punteros de
  userland -> tu fake stack/datos deben estar en kernel-land; ROP puro.
- KPTI (Kernel Page Table Isolation): al volver a userland hay que usar el "KPTI trampoline"
  (swapgs_restore_regs_and_return_to_usermode) o una signal handler, no un iretq directo.
- KASLR: base del kernel aleatoria -> necesitas un leak (dmesg, un infoleak del driver) para
  resolver las direcciones de commit_creds/gadgets.

## modprobe_path (tecnica sin ROP, muy usada)
`modprobe_path` es una variable global del kernel (por defecto "/sbin/modprobe"). Si tienes
escritura arbitraria: sobrescribela con la ruta a un script tuyo, luego ejecuta un binario con
un magic desconocido (o `socket(AF_ALG...)`) para que el kernel invoque modprobe como root ->
corre tu script (p.ej. chmod +s /bin/sh o copiar la flag). Evita todo el ROP/creds.

## Superficie tipica del driver
ioctl/read/write del /dev/xxx con overflow de stack del kernel, UAF de slab (kmalloc), o
copia sin validar tamano (copy_from_user). Primitivas: stack overflow -> ROP; UAF slab ->
secuestrar una struct con function pointer (tty_struct->ops, msg_msg, etc.).

## Herramientas
- extraer/empaquetar el initramfs (cpio) para meter tu exploit.
- pwndbg/gef con qemu (`target remote :1234`), `vmlinux` para simbolos.
- `/proc/kallsyms` (si es legible) da direcciones; `cat /sys/.../kaslr` no.
