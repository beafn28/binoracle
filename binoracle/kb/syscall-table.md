# Tabla de syscalls para explotacion (cheat sheet)

Los numeros de syscall que necesitas para shellcode, ORW (open-read-write, tipico con seccomp)
y execve, por arquitectura. El numero va en el registro de syscall y los args en los de
argumentos; luego la instruccion de trap. Complementa [[shellcoding]] y [[syscalls-seccomp]].

## Convencion por arquitectura (registro de nº / trap / args)
| Arch | nº syscall | args | trap |
|------|-----------|------|------|
| x86-64 | rax | rdi, rsi, rdx, r10, r8, r9 | `syscall` |
| x86-32 | eax | ebx, ecx, edx, esi, edi, ebp | `int 0x80` |
| aarch64 (ARM64) | x8 | x0, x1, x2, x3, x4, x5 | `svc #0` |
| arm (32, EABI) | r7 | r0, r1, r2, r3, r4, r5 | `svc #0` |

Nota: los numeros CAMBIAN entre arquitecturas (no asumas que x86-64 == aarch64). x32 ABI suma
0x40000000. Confirma con `ausyscall <arch> <nombre>` o el `unistd.h` del target.

## Syscalls clave (nº por arquitectura)
| syscall | x86-64 | x86-32 | aarch64 | arm(32) |
|---------|-------:|-------:|--------:|--------:|
| read | 0 | 3 | 63 | 3 |
| write | 1 | 4 | 64 | 4 |
| open | 2 | 5 | -(usa openat) | 5 |
| close | 3 | 6 | 57 | 6 |
| mmap | 9 | 90 (old_mmap) | 222 | 192 (mmap2) |
| mprotect | 10 | 125 | 226 | 125 |
| dup2 | 33 | 63 | -(usa dup3=24) | 63 |
| dup3 | 292 | 330 | 24 | 358 |
| socket | 41 | -(socketcall 102) | 198 | 281 |
| connect | 42 | -(socketcall 102) | 203 | 283 |
| execve | 59 | 11 | 221 | 11 |
| exit | 60 | 1 | 93 | 1 |
| openat | 257 | 295 | 56 | 322 |
| execveat | 322 | 358 | 281 | 387 |
| ptrace | 101 | 26 | 117 | 26 |

(x86-32 no tiene open/socket/connect por numero directo util en todos los kernels: `open`=5
existe, pero red va por `socketcall` #102 con un subcodigo. En aarch64 `open`/`dup2` NO existen:
usa `openat(AT_FDCWD=-100, path, flags)` y `dup3(old,new,0)`.)

## Recetas
- **execve("/bin/sh")** x86-64: `rax=59; rdi="/bin/sh"; rsi=0; rdx=0; syscall`.
- **execve("/bin/sh")** aarch64: `x8=221; x0="/bin/sh"; x1=0; x2=0; svc #0`.
- **ORW** (leer flag cuando execve esta bloqueada por seccomp): `openat(AT_FDCWD,"./flag",0)`
  -> `read(fd, buf, n)` -> `write(1, buf, n)`. Numeros: x86-64 257/0/1; aarch64 56/63/64.
- **mprotect a RWX** para saltar a shellcode: `mprotect(page_align(addr), len, 7)` -> x86-64
  rax=10; aarch64 x8=226. El 7 = PROT_READ|WRITE|EXEC.
- **dup2/dup3 de un socket a 0/1/2** para reverse shell: x86-64 dup2=33; aarch64 dup3=24
  (`dup3(sockfd, 0/1/2, 0)`).

## Como sacar el numero exacto (no fiarse de memoria)
- pwntools: `from pwn import *; context.arch='amd64'; print(constants.SYS_execve)` (o
  `shellcraft.amd64.linux.sh()` genera el shellcode con el numero correcto).
- CLI: `ausyscall x86_64 execve` / `ausyscall aarch64 execve` (paquete audit).
- Fuente: la tabla del kernel (`arch/x86/entry/syscalls/syscall_64.tbl`, y el generic
  `include/uapi/asm-generic/unistd.h` para aarch64). Verifica contra la version del target si es
  muy antiguo/nuevo. Ver [[syscalls-seccomp]] para el filtro y [[shellcoding]] para el asm.
