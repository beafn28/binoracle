# Herramientas de pentest de binarios (cheat sheet)

## Estatico / triage
- radare2 / rizin: `aa`, `afl`, `pdf @sym`, `axt`, `/R` (rop), `iI` (info), `ii` (imports).
- checksec: NX, PIE, canary, RELRO, FORTIFY de un vistazo.
- pyelftools / readelf / nm / objdump: simbolos, secciones, GOT/PLT, relocs.
- strings / rabin2 -z: cadenas (flags, /bin/sh, format strings, rutas).
- file / rabin2 -I: arquitectura, tipo, stripped.
- Ghidra / IDA / Binary Ninja: decompilacion (analisis manual profundo).

## ROP / gadgets
- ROPgadget --binary bin --ropchain
- ropper --file bin --search "pop rdi"
- pwntools ROP(elf): construye cadenas programaticamente.
- one_gadget libc.so.6: gadget unico que da shell (con constraints).

## Dinamico / debug
- gdb + pwndbg / gef / peda: breakpoints, heap, telescope, checksec.
- lldb (macOS / cross).
- ltrace / strace: llamadas a libc / syscalls.
- valgrind: errores de memoria (UAF, OOB, leaks).

## Simbolico / fuzzing
- angr: ejecucion simbolica, alcanzabilidad, resolver offsets/inputs.
- pwntools cyclic/cyclic_find: offset a saved RIP.
- AFL++ / libFuzzer / honggfuzz: fuzzing de cobertura.
- KLEE: ejecucion simbolica a nivel LLVM.

## Explotacion / PoC
- pwntools: process/remote, ELF, ROP, fmtstr_payload, shellcraft, cyclic.
- libc-database: identificar libc por offsets de simbolos filtrados.

## Como los usa binoracle
r2 (estatico), angr (offsets/alcanzabilidad, verdict "verified"), pwntools (PoC ejecutable en
sandbox Docker --network none), one_gadget (fallback ret2libc), checksec propio (r2_checksec).
