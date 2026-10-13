# Playbook de exploits verificados (auto-generado por el entrenador)

Catalogo de tecnicas de explotacion que binoracle ha **desarrollado y VERIFICADO por ejecucion** (shell real en sandbox) sobre el corpus autorizado. Generado por `binoracle train --export-playbook`; se regenera al reentrenar. Solo tecnicas confirmadas -- nada inferido. Cada seccion indica bajo que mitigaciones se confirmo, para elegir la tecnica por las defensas del objetivo (metodologia: hecho sobre inferencia).

- fecha: 2026-10-13T13:48:17
- verificados: 15/21  |  tecnicas distintas: 13

## format-string via canary leak (%s) -> rewrite -> overflow -> win()
- clase: **format-string**  |  estrategia verificada: **canary leak (%s) -> rewrite -> overflow -> win()**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Canary+Partial-RELRO
- offset a la direccion de retorno / primitiva: 284
- verificado por ejecucion en sandbox (shell real)
- tecnica: Bypass de stack canary con fuga: se sobrescribe el LSB nulo del canary para que un %s imprima sus 7 bytes altos (canary=0x00|fuga), luego un 2o overflow reescribe el MISMO canary (pasa la comprobacion) y retorna a win(). Derrota el canary SIN desactivarlo; necesita una primitiva de fuga adyacente al canary.
- ejemplo de corpus: `canfmt`

## format-string via format-string printf@GOT=system
- clase: **format-string**  |  estrategia verificada: **format-string printf@GOT=system**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 264
- verificado por ejecucion en sandbox (shell real)
- tecnica: Format-string con GOT escribible (No/Partial RELRO): %n reescribe printf@GOT -> system, y el siguiente printf(entrada) ejecuta system(entrada).
- ejemplo de corpus: `fmtstring`

## format-string via ret2win
- clase: **format-string**  |  estrategia verificada: **ret2win**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 136
- verificado por ejecucion en sandbox (shell real)
- tecnica: Desbordamiento de pila -> se sobrescribe la direccion de retorno con la de la funcion regalo win()/system('/bin/sh'). Aplica con NX (no hace falta shellcode) y sin canary; si no hay PIE la direccion es fija.
- ejemplo de corpus: `fmt_got`

## stack-overflow via canary leak (%s) -> rewrite -> overflow -> win()
- clase: **stack-overflow**  |  estrategia verificada: **canary leak (%s) -> rewrite -> overflow -> win()**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Canary+Partial-RELRO
- offset a la direccion de retorno / primitiva: 88
- verificado por ejecucion en sandbox (shell real)
- tecnica: Bypass de stack canary con fuga: se sobrescribe el LSB nulo del canary para que un %s imprima sus 7 bytes altos (canary=0x00|fuga), luego un 2o overflow reescribe el MISMO canary (pasa la comprobacion) y retorna a win(). Derrota el canary SIN desactivarlo; necesita una primitiva de fuga adyacente al canary.
- ejemplo de corpus: `canleak`

## stack-overflow via ret2dlresolve (shell sin leak de libc)
- clase: **stack-overflow**  |  estrategia verificada: **ret2dlresolve (shell sin leak de libc)**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 72
- verificado por ejecucion en sandbox (shell real)
- tecnica: ret2dlresolve: en un dinamico no-PIE con Partial RELRO, sin win()/system() ni fuga posible, se forjan las estructuras del enlazador (Elf64_Rela/Sym/Str) y se llama al stub PLT-0 para que resuelva y ejecute system('/bin/sh') SIN leak de libc.
- ejemplo de corpus: `dlresolve`

## stack-overflow via ret2libc+leak (2 etapas)
- clase: **stack-overflow**  |  estrategia verificada: **ret2libc+leak (2 etapas)**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 88
- verificado por ejecucion en sandbox (shell real)
- tecnica: Fuga de una direccion de libc (p.ej. puts@GOT via puts@PLT), se calcula la base de libc y se retorna a system('/bin/sh'). Derrota NX; necesita una fuga.
- ejemplo de corpus: `ret2libc`

## stack-overflow via ret2win
- clase: **stack-overflow**  |  estrategia verificada: **ret2win**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 72
- verificado por ejecucion en sandbox (shell real)
- tecnica: Desbordamiento de pila -> se sobrescribe la direccion de retorno con la de la funcion regalo win()/system('/bin/sh'). Aplica con NX (no hace falta shellcode) y sin canary; si no hay PIE la direccion es fija.
- ejemplo de corpus: `ret2win`

## stack-overflow via ret2win-pie
- clase: **stack-overflow**  |  estrategia verificada: **ret2win-pie**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+PIE+Full-RELRO
- offset a la direccion de retorno / primitiva: 72
- verificado por ejecucion en sandbox (shell real)
- tecnica: Desbordamiento de pila -> se sobrescribe la direccion de retorno con la de la funcion regalo win()/system('/bin/sh'). Aplica con NX (no hace falta shellcode) y sin canary; si no hay PIE la direccion es fija.
- ejemplo de corpus: `ret2win_pie`

## stack-overflow via rop-pie
- clase: **stack-overflow**  |  estrategia verificada: **rop-pie**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+PIE+Canary+Full-RELRO
- offset a la direccion de retorno / primitiva: 6344
- verificado por ejecucion en sandbox (shell real)
- tecnica: ROP sobre PIE: con ASLR off (o tras fugar la base) se reubica el ELF y se encadena ret2libc system('/bin/sh') o execve por syscall con gadgets absolutos.
- ejemplo de corpus: `ropme_pie`

## stack-overflow via write-what-where GOT=win
- clase: **stack-overflow**  |  estrategia verificada: **write-what-where GOT=win**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 24
- verificado por ejecucion en sandbox (shell real)
- tecnica: Write-what-where (indice sin comprobar sobre un array global): offset estatico array->GOT en no-PIE, se reescribe una entrada GOT llamada despues (puts/printf) a win().
- ejemplo de corpus: `oobwrite`

## uaf via UAF (reutilizacion de chunk) funcptr=win
- clase: **uaf**  |  estrategia verificada: **UAF (reutilizacion de chunk) funcptr=win**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 88
- verificado por ejecucion en sandbox (shell real)
- tecnica: Use-after-free por reutilizacion de chunk: un malloc posterior del mismo tamano recicla la struct liberada cuyo primer campo es un puntero a funcion -> win().
- ejemplo de corpus: `uaf`

## uaf via tcache dup GOT=system
- clase: **uaf**  |  estrategia verificada: **tcache dup GOT=system**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 32
- verificado por ejecucion en sandbox (shell real)
- tecnica: UAF/tcache poisoning (glibc >=2.32, safe-linking): se fuga la clave con un bin vacio, se envenena fd=key^free@GOT, y free@GOT=win; se repara la ranura GOT vecina que el key-clear pone a cero.
- ejemplo de corpus: `notes_heap`

## uaf via tcache-poison free@GOT=win
- clase: **uaf**  |  estrategia verificada: **tcache-poison free@GOT=win**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 28
- verificado por ejecucion en sandbox (shell real)
- tecnica: UAF/tcache poisoning (glibc >=2.32, safe-linking): se fuga la clave con un bin vacio, se envenena fd=key^free@GOT, y free@GOT=win; se repara la ranura GOT vecina que el key-clear pone a cero.
- ejemplo de corpus: `heapexp`
