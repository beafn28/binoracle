# Playbook de exploits verificados (auto-generado por el entrenador)

Catalogo de tecnicas de explotacion que binoracle ha **desarrollado y VERIFICADO por ejecucion** (shell real en sandbox) sobre el corpus autorizado. Generado por `binoracle train --export-playbook`; se regenera al reentrenar. Solo tecnicas confirmadas -- nada inferido. Cada seccion indica bajo que mitigaciones se confirmo, para elegir la tecnica por las defensas del objetivo (metodologia: hecho sobre inferencia).

- fecha: 2026-10-13T07:27:57
- verificados: 10/11  |  tecnicas distintas: 8

## format-string via format-string printf@GOT=system
- clase: **format-string**  |  estrategia verificada: **format-string printf@GOT=system**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 264
- verificado por ejecucion en sandbox (shell real)
- ejemplo de corpus: `fmtstring`

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

## stack-overflow via write-what-where GOT=win
- clase: **stack-overflow**  |  estrategia verificada: **write-what-where GOT=win**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 24
- verificado por ejecucion en sandbox (shell real)
- ejemplo de corpus: `oobwrite`

## uaf via UAF (reutilizacion de chunk) funcptr=win
- clase: **uaf**  |  estrategia verificada: **UAF (reutilizacion de chunk) funcptr=win**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 88
- verificado por ejecucion en sandbox (shell real)
- ejemplo de corpus: `uaf`

## uaf via tcache dup GOT=system
- clase: **uaf**  |  estrategia verificada: **tcache dup GOT=system**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 32
- verificado por ejecucion en sandbox (shell real)
- ejemplo de corpus: `notes_heap`

## uaf via tcache-poison free@GOT=win
- clase: **uaf**  |  estrategia verificada: **tcache-poison free@GOT=win**
- arquitectura: x86 64-bit  |  mitigaciones presentes: NX+Partial-RELRO
- offset a la direccion de retorno / primitiva: 28
- verificado por ejecucion en sandbox (shell real)
- tecnica: UAF/tcache poisoning (glibc >=2.32, safe-linking): se fuga la clave con un bin vacio, se envenena fd=key^free@GOT, y free@GOT=win; se repara la ranura GOT vecina que el key-clear pone a cero.
- ejemplo de corpus: `heapexp`
