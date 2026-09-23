# Syscalls y seccomp / ORW (cheat sheet)

## Syscalls x86-64 mas usadas en pwn
Convencion: numero en rax; args en rdi, rsi, rdx, r10, r8, r9; instruccion `syscall`.
- read = 0 (fd, buf, count)
- write = 1 (fd, buf, count)
- open = 2 (path, flags, mode)      openat = 257 (dirfd, path, flags, mode)
- mprotect = 10 (addr, len, prot)   prot: R=1 W=2 X=4 -> RWX=7
- execve = 59 (path, argv, envp)
- exit = 60
- rt_sigreturn = 15 (usado en SROP)
Nota: en x86 (32-bit) los numeros son DISTINTOS (execve=11, `int 0x80`), y args en
ebx,ecx,edx,esi,edi.

## mprotect + shellcode (bypass NX sin libc de shell)
Si no puedes ret2libc pero controlas el flujo: ROP/SROP para llamar
mprotect(page_base, len, 7) sobre la pagina de la pila/.bss, luego saltar al shellcode que
escribiste ahi. page_base debe estar alineado a 0x1000.

## seccomp (sandbox de syscalls)
Filtro BPF que permite/deniega syscalls por numero (y a veces por args). Muy comun en CTF
para bloquear execve/execveat y forzar leer la flag por fichero.
- Dump del filtro: `seccomp-tools dump ./chall` (muestra las reglas: qué esta ALLOW/KILL).
- Si execve esta bloqueado -> no hay shell; usa ORW.

## ORW (open + read + write): leer la flag sin shell
Cuando seccomp solo permite open/read/write (y exit):
1. open("/flag", 0)            -> fd
2. read(fd, buf, 0x100)        -> lee la flag a un buffer
3. write(1, buf, 0x100)        -> la imprime por stdout
Se monta como cadena ROP de syscalls o como shellcode ORW. pwntools:
`shellcraft.amd64.linux.cat('/flag')` o `open`+`read`+`write` manuales.

## Bypasses de seccomp (segun el filtro)
- x32 ABI: `syscall` con rax = 0x40000000 + num real. Filtros modernos bloquean rax >=
  0x40000000, pero filtros viejos no.
- Modo 32-bit desde 64-bit: cambiar a CS=0x23 con `retf` y usar `int 0x80` con numeros de
  32-bit (el filtro suele mirar solo el numero de 64-bit). Requiere que el filtro no valide
  la arquitectura.
- openat en vez de open, o execveat en vez de execve, si el filtro solo listo uno.
- Siempre: primero `seccomp-tools dump` para saber QUE esta permitido y disenar en base a eso.
