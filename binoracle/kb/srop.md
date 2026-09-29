# SROP - Sigreturn Oriented Programming (cheat sheet)

Tecnica de control de flujo que usa el mecanismo de `sigreturn` del kernel (la syscall que
restaura el contexto de un proceso tras manejar una senal) para fabricar de un golpe un `struct
sigcontext`/`ucontext` completo -- es decir, controlar TODOS los registros de la CPU con una
unica escritura en la pila, sin necesitar una cadena larga de gadgets ROP.

## Por que funciona
Cuando el kernel entrega una senal, guarda el estado de los registros en la pila (el "sigframe")
y, al terminar el handler, el programa llama a `sigreturn`, que lee ese sigframe y restaura TODOS
los registros exactamente como estan en la estructura -- incluido `rip`. Si puedes:
1. Controlar el stack pointer en el momento de invocar `sigreturn` (via un overflow que te deja
   apilar tu propio sigframe falso), y
2. Invocar la syscall `sigreturn` (numero 15 en x86-64) con ese sigframe en la pila,

el kernel restaura CADA registro (rax, rdi, rsi, rdx, rsp, rip...) al valor que TU escribiste en
la estructura falsa. Esto es control total en una sola operacion: mucho mas potente que un
ret2libc/ROP normal, que solo controla la pila un gadget a la vez.

## Requisitos tipicos
- Poder invocar `sigreturn` (via `syscall` directo con rax=15, o via un gadget `syscall; ret`
  presente en el binario -- frecuente en binarios estaticos o con vdso mapeado).
- Un overflow o control de pila suficientemente grande para escribir el sigframe completo (~250
  bytes en x86-64: todos los registros de proposito general + flags + segmentos).
- Conocer el layout EXACTO del `struct sigcontext` de la arquitectura objetivo (offset de cada
  registro dentro del frame) -- pwntools trae `SigreturnFrame()` ya construido para esto.

## Flujo tipico de exploit
1. Overflow que sobrescribe la direccion de retorno con la del gadget `syscall; ret` (o
   `int 0x80; ret` en x86).
2. Justo despues, apilas el sigframe fabricado (rax=15 para que el PRIMER `syscall` que se
   ejecute, antes de llegar aqui, sea el que invoca sigreturn -- el orden exacto depende de si
   usas el gadget directamente o pasas antes por una syscall de setup).
3. El kernel restaura los registros del sigframe: puedes poner rax/rdi/rsi/rdx a los valores de
   una syscall `execve("/bin/sh", NULL, NULL)` y rip apuntando de nuevo a un gadget syscall ->
   shell con una sola cadena.

## Cuando se usa
Especialmente util cuando el binario es ESTATICO (sin libc dinamica que dar leaks, pero con
muchas syscalls disponibles), o cuando el numero de gadgets ROP utiles es muy limitado y necesitas
controlar registros arbitrarios que no hay gadgets sencillos para poner (rax con valores grandes,
por ejemplo).

## Ver tambien
[[advanced-rop]] (ROP chains generales), [[ret2csu]] y [[stack-pivot]] (otras tecnicas para
casos con pocos gadgets disponibles).
