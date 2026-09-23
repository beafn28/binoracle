# ARM / AArch64 / MIPS exploitation (cheat sheet)

Explotacion en arquitecturas no-x86. Cambian los registros, la convencion de llamada, los
syscalls y como se controla el flujo (a menudo por registro de enlace, no por la pila).

## AArch64 (ARM 64-bit)
- Args: x0-x7 (1o-8o); retorno en x0. Return address en LR (x30). Puntero de pila SP.
- Llamada: `bl` guarda el retorno en x30; el epilogo hace `ldp x29,x30,[sp],#N ; ret`.
- Control de flujo: para ROP sueles pisar el x30 guardado en la pila (en el `stp x29,x30`).
  Gadgets utiles: `ldp x19,x20,[sp],#0x10 ; ret`, `ldr x0,[...] ; ret`, `blr x?`.
- Syscall: numero en x8, args x0-x5, instruccion `svc #0`. execve = 221 (0xdd).
- No hay `pop rdi`: usas gadgets `ldp`/`ldr` para cargar registros desde la pila.

## ARM 32-bit (ARMv7)
- Args: r0-r3 (1o-4o), resto en la pila; retorno en r0. Return address en LR (r14).
- Modo Thumb (T bit): direcciones impares (addr|1) cambian a Thumb; util para gadgets.
- Syscall: numero en r7, `svc #0`. execve = 11 (EABI). ret2libc/ROP igual que x86 pero con
  gadgets `pop {r0, pc}` etc.

## MIPS
- Args: $a0-$a3; retorno en $v0. Return address en $ra. Syscall numero en $v0, `syscall`.
- Branch delay slot: la instruccion DESPUES de un salto/branch se ejecuta igual. Cuidado al
  construir shellcode/ROP: coloca algo inocuo o util en el delay slot.
- Cache incoherence: tras escribir shellcode puede que necesites flush de cache (o elegir una
  region ya coherente) para que se ejecute.
- syscall execve = 4011 (o/32 ABI).

## General (todas)
- checksec/rabin2 -I para ver arch y mitigaciones. Muchos retos ARM/MIPS son NX pero sin PIE.
- Emulacion/ejecucion: qemu-user (`qemu-aarch64 -L /usr/aarch64-linux-gnu ./bin`) +
  `qemu-... -g 1234` para gdb-multiarch. pwntools: `context.arch='aarch64'|'arm'|'mips'`.
- shellcraft.<arch> genera execve/ORW para la arquitectura.
