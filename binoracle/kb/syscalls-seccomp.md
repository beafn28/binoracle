# Syscalls y seccomp / ORW (cheat sheet)

## Syscalls x86-64 mas usadas en pwn
Convencion: numero en rax; args en rdi, rsi, rdx, r10, r8, r9; instruccion `syscall`. El
retorno vuelve en rax.
- read = 0 (fd, buf, count)
- write = 1 (fd, buf, count)
- open = 2 (path, flags, mode)      openat = 257 (dirfd, path, flags, mode)
- mmap = 9    mprotect = 10 (addr, len, prot)   prot: R=1 W=2 X=4 -> RWX=7
- rt_sigreturn = 15 (usado en SROP)
- dup2 = 33 (oldfd, newfd)   socket=41 connect=42 (para reverse shell por ROP)
- execve = 59 (path, argv, envp)     execveat = 322
- exit = 60   exit_group = 231
Nota: en x86 (32-bit) los numeros son DISTINTOS (read=3, write=4, open=5, execve=11) y se usa
`int 0x80` con args en ebx,ecx,edx,esi,edi.

## mprotect + shellcode (bypass NX sin libc de shell)
Si no puedes ret2libc pero controlas el flujo: ROP/SROP para llamar
mprotect(page_base, len, 7) sobre la pagina de la pila/.bss, luego saltar al shellcode.
- page_base DEBE estar alineado a 0x1000 (redondea la direccion hacia abajo: addr & ~0xfff).
- len cubre tu shellcode (0x1000 basta normalmente).
- tras mprotect, un gadget `jmp rsp`/`push rsp; ret` o saltar a la direccion conocida del buffer.

## seccomp (sandbox de syscalls)
Filtro BPF que permite/deniega syscalls por numero (y a veces por args). Muy comun en CTF para
bloquear execve/execveat y forzar leer la flag por fichero.
- Dump del filtro: `seccomp-tools dump ./chall` -> muestra las reglas (ALLOW/KILL/ERRNO) y si
  valida la arquitectura (A = arch). Disena SOLO con lo que este ALLOW.
- Si execve/execveat estan KILL -> no hay shell; usa ORW.

## ORW (open + read + write): leer la flag sin shell
Cuando seccomp solo permite open/read/write (y exit). Como cadena ROP de syscalls:
```
# open("/flag", 0, 0) -> rax = fd (normalmente 3)
pop rdi; "/flag\0"(en .bss)   ; pop rsi; 0 ; pop rdx; 0 ; pop rax; 2 ; syscall
# read(3, bss, 0x40)
pop rdi; 3 ; pop rsi; bss ; pop rdx; 0x40 ; pop rax; 0 ; syscall
# write(1, bss, 0x40)
pop rdi; 1 ; pop rsi; bss ; pop rdx; 0x40 ; pop rax; 1 ; syscall
```
Como shellcode: `shellcraft.amd64.linux.cat('/flag')` (o open+read+write manuales). Escribe
"/flag\0" en .bss con un read previo si no esta en el binario. Si open esta KILL pero openat no,
usa openat(AT_FDCWD=-100, "/flag", 0).

## Bypasses de seccomp (segun el filtro)
- x32 ABI: `syscall` con rax = 0x40000000 + num real. Filtros modernos bloquean rax >=
  0x40000000, pero filtros viejos no lo validan.
- Modo 32-bit desde 64-bit: cambiar a CS=0x23 con `retf` (push 0x23; push addr32; retf) y usar
  `int 0x80` con numeros de 32-bit. Funciona si el filtro solo mira el numero de 64-bit y no la
  arquitectura (no A check).
- openat/execveat en vez de open/execve si el filtro solo listo uno.
- si permiten mmap/mprotect: mapea RWX y mete shellcode ORW.
- Siempre: `seccomp-tools dump` primero y disena en base a lo permitido.
