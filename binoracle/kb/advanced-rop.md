# ROP avanzado: SROP, ret2csu, stack pivot, ret2dlresolve (cheat sheet)

Tecnicas para cuando faltan gadgets, falta espacio en la pila o no hay leak de libc.

## SROP (Sigreturn-Oriented Programming)
Abusa de rt_sigreturn: el kernel restaura TODOS los registros desde un "signal frame" en la
pila. Controlas rax, rdi, rsi, rdx, rip, rsp, eflags... de una vez.
- syscall rt_sigreturn en x86-64 = numero 15.
- Pasos: pon rax=15, rsp apuntando a tu sigframe falso, ejecuta `syscall`. El kernel
  "restaura" el contexto que tu forjaste.
- Necesitas un gadget `syscall; ret` y controlar rax (p.ej. `pop rax; ret`, o una llamada a
  read que devuelve el numero de bytes en rax).
- Uso tipico: execve('/bin/sh') directo, o mprotect(stack, RWX) y saltar a shellcode en la
  pila (bypass NX).
- pwntools: `SigreturnFrame()` monta el frame; rellena frame.rax/rdi/rsi/rdx/rip/rsp.
- Limite: sin leak de pila cuesta poner rsp a un valor util.

## ret2csu
Gadgets universales en `__libc_csu_init` (presentes en casi todo ELF x86-64 no muy moderno)
para controlar rdi/rsi/rdx sin `pop rdi/rsi/rdx`.
- Gadget 1 (pop): `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`.
- Gadget 2 (mov+call): `mov rdx, r14; mov rsi, r13; mov edi, r12d; call [r15 + rbx*8]`.
- Mapa: r12d->edi (arg1), r13->rsi (arg2), r14->rdx (arg3); r15 apunta a memoria con la
  direccion de la funcion objetivo; rbx=0 para que la llamada sea [r15].
- Tras Gadget 2, rbx se incrementa y hay un chequeo `cmp rbx, rbp` -> pon rbp=rbx+1 (p.ej.
  rbx=0, rbp=1) para no repetir el bucle.
- Nota: en binarios muy nuevos (sin __libc_csu_init, PIE con otro init) puede no existir;
  buscar gadgets equivalentes.

## Stack pivoting
Cuando el overflow deja poco espacio tras saved RIP. Rediriges rsp a un buffer controlado
(.bss, heap) donde montaste la cadena ROP completa.
- `leave; ret` (8 bytes, el mas eficiente): leave = `mov rsp, rbp; pop rbp`. Sobrescribe el
  saved RBP con (target-8) y RIP con `leave; ret` -> rsp salta a target.
- `pop rsp; ret`: directo pero raro.
- `xchg reg, rsp` combinado con `pop reg; ret` (~16 bytes).
- El destino debe contener ya la fake stack (cadena ROP) lista para ejecutarse.

## ret2dlresolve
Resuelve y llama una funcion (p.ej. system) SIN leak, abusando del lazy binding del linker.
- Requiere GOT escribible: funciona con Partial RELRO / No RELRO; Full RELRO lo bloquea.
- Forjas estructuras Elf64_Rela + Elf64_Sym falsas en memoria escribible que apuntan al
  simbolo deseado, y llamas a `_dl_runtime_resolve` con el indice controlado.
- pwntools: `Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])`; escribes el
  payload con read/gets en .bss y disparas con `rop.ret2dlresolve(dlresolve)`.
- Ideal en estatico-parcial sin libc conocida y sin infoleak.
