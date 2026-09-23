# ARM / AArch64 / MIPS exploitation (cheat sheet)

Explotacion en arquitecturas no-x86. Cambian los registros, la convencion de llamada, los
syscalls y como se controla el flujo (a menudo por registro de enlace, no por la pila).

## AArch64 (ARM 64-bit)
- Args: x0-x7 (1o-8o); retorno en x0. Return address en LR (x30). Puntero de pila SP (alineado
  a 16). Instrucciones de 4 bytes fijos.
- Llamada: `bl` guarda el retorno en x30; el prologo hace `stp x29,x30,[sp,#-N]!` y el epilogo
  `ldp x29,x30,[sp],#N ; ret`. Para ROP pisas el x30 GUARDADO (el `ret` salta a x30).
- Gadgets utiles (cargan desde la pila): `ldp x19,x20,[sp],#0x10 ; ret`,
  `ldr x0,[sp,#..] ; ret`, `mov x0, x19 ; blr x20`. No hay `pop rdi`; usas ldp/ldr.
- Syscall: numero en x8, args x0-x5, instruccion `svc #0`. execve = 221 (0xdd), read=63,
  write=64, open=56, mprotect=226.
```
# ROP execve: x0=&"/bin/sh", x1=0, x2=0, x8=221, svc 0
# cargas x0/x1/x2/x8 con gadgets ldp/ldr desde la fake stack, luego un gadget 'svc'
```
- PAC (arm64e de Apple): firma punteros -> rompe ROP; ver [[macos-macho]].

## ARM 32-bit (ARMv7)
- Args: r0-r3 (1o-4o), resto en la pila; retorno en r0. Return address en LR (r14).
- Modo Thumb (T bit del CPSR): saltar a addr|1 conmuta a Thumb (instrucciones de 2 bytes);
  util porque hay mas gadgets Thumb. `bx`/`blx` conmutan segun el bit 0.
- Gadgets: `pop {r0, pc}`, `pop {r0-r3, pc}`, `pop {r4, lr} ; bx lr`.
- Syscall: numero en r7, `svc #0` (EABI). execve = 11. ret2libc/ROP como en x86 pero con los pop.

## MIPS
- Args: $a0-$a3; retorno en $v0. Return address en $ra (lo pisas para ROP). Syscall numero en
  $v0, `syscall`. execve = 4011 (o32).
- Branch delay slot: la instruccion DESPUES de un salto/branch/jr SE EJECUTA igual. Al construir
  ROP/shellcode coloca algo inocuo (nop) o util en el delay slot, o el gadget hace cosas
  inesperadas.
- Cache incoherence: MIPS tiene I-cache y D-cache separadas; tras escribir shellcode puede que
  no se ejecute hasta un flush. Usa una region ya ejecutable o fuerza el flush.
- little vs big endian: MIPS puede ser mipsel o mips (BE). Ajusta pwntools endian.

## General (todas)
- rabin2 -I / checksec para arch, endian y mitigaciones. Muchos retos ARM/MIPS son NX pero
  SIN PIE (direcciones fijas).
- Emulacion/ejecucion: `qemu-aarch64 -L /usr/aarch64-linux-gnu ./bin` (o -mipsel, -arm) y
  `qemu-... -g 1234` + `gdb-multiarch` (`set architecture ...; target remote :1234`).
- pwntools: `context.arch='aarch64'|'arm'|'mips'`, `context.endian`, `shellcraft.<arch>` genera
  execve/ORW, `asm()`/`disasm()` con el arch fijado. ROPgadget soporta ARM/MIPS.
- gadgets escasos: en RISC hay menos `ret` clasicos; combina ldp/pop de multiples registros y
  aprovecha epilogos completos como gadgets.
