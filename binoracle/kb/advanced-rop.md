# ROP avanzado: SROP, ret2csu, stack pivot, ret2dlresolve (cheat sheet)

Tecnicas para cuando faltan gadgets, falta espacio en la pila o no hay leak de libc.

## SROP (Sigreturn-Oriented Programming)
Abusa de rt_sigreturn: el kernel restaura TODOS los registros desde un "signal frame" en la
pila. Controlas rax, rdi, rsi, rdx, rip, rsp, eflags... de una vez.
- syscall rt_sigreturn en x86-64 = numero 15.
- Pasos: pon rax=15, rsp apuntando a tu sigframe falso, ejecuta `syscall`. El kernel
  "restaura" el contexto que tu forjaste.
- Necesitas un gadget `syscall; ret` y controlar rax (p.ej. `pop rax; ret`, o una llamada a
  read que devuelve el numero de bytes leidos en rax -> lee exactamente 15 bytes).
- Uso tipico: execve('/bin/sh') directo, o mprotect(stack, RWX) y saltar a shellcode.
```
from pwn import *
context.arch = 'amd64'
frame = SigreturnFrame()
frame.rax = constants.SYS_execve   # 59
frame.rdi = binsh                  # direccion de "/bin/sh"
frame.rsi = 0; frame.rdx = 0
frame.rip = syscall_gadget         # un 'syscall' cualquiera
payload = b'A'*off + p64(pop_rax) + p64(15) + p64(syscall_gadget) + bytes(frame)
```
- Limite: sin leak de pila cuesta poner rsp a un valor util. Escribe "/bin/sh" en .bss por
  read antes, o usa una direccion conocida.

## ret2csu
Gadgets universales en `__libc_csu_init` (presentes en casi todo ELF x86-64 no muy moderno)
para controlar rdi/rsi/rdx sin `pop rdi/rsi/rdx`.
- Gadget 1 (pop): `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`.
- Gadget 2 (mov+call): `mov rdx, r14; mov rsi, r13; mov edi, r12d; call [r15 + rbx*8]`.
- Mapa: r12->edi (arg1, solo 32 bits!), r13->rsi (arg2), r14->rdx (arg3); r15 apunta a memoria
  con la direccion de la funcion objetivo; rbx=0 para que la llamada sea [r15].
- Tras Gadget 2, rbx se incrementa y hay `cmp rbx, rbp` + salto: pon rbp=rbx+1 (rbx=0, rbp=1)
  para salir del bucle. Tras el call, el epilogo hace `add rsp, 8` + pops: rellena con 7 valores
  dummy (0) tras Gadget 2 para que caiga en tu siguiente gadget.
- Limite: edi solo carga 32 bits (mov edi, r12d). Para punteros de 64 bits en rdi no sirve
  directo; encadena con `pop rdi` real despues, o usa r15 para la funcion + otra via para rdi.

## Stack pivoting
Cuando el overflow deja poco espacio tras saved RIP. Rediriges rsp a un buffer controlado
(.bss, heap) donde montaste la cadena ROP completa.
- `leave; ret` (8 bytes, el mas eficiente): leave = `mov rsp, rbp; pop rbp`. Sobrescribe el
  saved RBP con (target-8) y RIP con `leave; ret` -> rbp toma target-8, pop rbp lo consume,
  y el ret siguiente salta a [target]. Coloca la cadena en target.
- `pop rsp; ret`: directo pero raro.
- `xchg reg, rsp` combinado con `pop reg; ret` (~16 bytes).
- add/sub rsp, N: micro-pivot para saltar hueco.
- El destino debe contener ya la fake stack (cadena ROP) lista. Suele escribirse con un
  read(0, bss, N) previo por ROP.

## ret2dlresolve
Resuelve y llama una funcion (p.ej. system) SIN leak, abusando del lazy binding del linker.
- Requiere GOT escribible y lazy binding: funciona con Partial RELRO / No RELRO; Full RELRO
  (bind now) lo bloquea.
- Forjas Elf64_Rela + Elf64_Sym falsas en memoria escribible que apuntan al simbolo "system"
  (nombre en .dynstr controlado), y llamas a la PLT[0] (_dl_runtime_resolve) con un reloc_index
  grande que caiga en tu estructura.
```
from pwn import *
elf = context.binary = ELF('./chall')      # no PIE, Partial RELRO
dl = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop = ROP(elf)
rop.read(0, dl.data_addr)         # escribe las structs falsas en .bss
rop.ret2dlresolve(dl)             # dispara la resolucion + llamada
payload = b'A'*off + rop.chain() + b'\n' + dl.payload
```
- Ideal en estatico-parcial sin libc conocida y sin infoleak. Ver internals en [[got-plt]].
