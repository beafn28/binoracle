# Shellcoding (cheat sheet)

Escribir codigo maquina que se inyecta y ejecuta. Solo viable si hay una region ejecutable
(NX off, o tras mprotect/SROP que la haga RWX; ver [[syscalls-seccomp]]).

## execve('/bin/sh') x86-64 (23 bytes, clasico)
Idea: rax=59, rdi="/bin/sh", rsi=0, rdx=0, syscall. Se empuja "/bin/sh\0" a la pila y se
apunta rdi a el. pwntools: `asm(shellcraft.amd64.linux.sh())`.

## Restricciones frecuentes y como sortearlas
- bad chars (0x00, 0x0a, 0x20...): el input los corta (strcpy corta en 0x00, gets en 0x0a).
  Usa un encoder (xor) + decoder stub, o escribe el shellcode evitando esos bytes.
- solo alfanumerico: shellcode alphanumeric (pwntools `encoders`), usa solo instrucciones
  cuyos bytes caen en [0-9A-Za-z]. Necesita un registro apuntando al shellcode.
- espacio muy corto: usa un "egghunter" (busca en memoria una marca de 8 bytes y salta al
  shellcode grande escrito en otra region).
- posicion desconocida: shellcode PIE/position-independent (empuja a la pila, usa rip-relative
  o jmp/call/pop para obtener la direccion actual).

## ORW (seccomp bloquea execve)
open("/flag")+read+write; ver [[syscalls-seccomp]]. `shellcraft.amd64.linux.cat('/flag')`.

## Otras arquitecturas
- x86 (32-bit): `int 0x80`, execve=11, args en ebx/ecx/edx.
- ARM/AArch64, MIPS: distinto encoding y syscalls; pwntools `context.arch` +
  shellcraft.<arch> genera el equivalente.

## Colocacion
- en la pila (NX off): saltar a la direccion del buffer (a veces con un `jmp rsp`/`call rsp`
  o un NOP sled si la direccion es inexacta).
- en .bss/heap tras escribirlo: mprotect RWX (ROP/SROP) y saltar.

## Herramientas
pwntools `asm()`, `shellcraft`, `context.arch/os`; `objdump -d` para verificar; probar en
sandbox aislado antes del target.
