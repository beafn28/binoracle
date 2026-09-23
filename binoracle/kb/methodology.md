# Metodologia de auditoria de un binario (cheat sheet)

Flujo de trabajo para pasar de un binario desconocido a un exploit verificado (o al hallazgo
mas fuerte respaldado por evidencia). Es la logica que sigue el modo `Auditar` de binoracle.

## 1. Triage (el terreno)
Arquitectura, bits, endian, tipo (ELF/PE/Mach-O), estatico/dinamico, stripped, mitigaciones
(NX/PIE/canary/RELRO/FORTIFY). `rabin2 -I`, checksec. Define que tecnicas son viables.

## 2. Superficie de ataque
- entradas: argv, stdin, ficheros, red, variables de entorno.
- imports peligrosos: gets, strcpy/strcat, sprintf, scanf("%s"), read con tamano grande,
  system/exec, printf(user), malloc/free (heap).
- cadenas interesantes: "/bin/sh", "flag", format strings, rutas, mensajes de menu.

## 3. Sinks y flujo de datos
Para cada sink peligroso: quien lo llama (xrefs) y con QUE datos. Traza el input del usuario
hasta el sink. Un `gets(buf)` local = overflow directo; un `printf(buf)` = format string.

## 4. Hipotesis de primitiva
overflow de stack? format-string? heap (UAF/double-free/overflow)? integer/off-by-one?
type confusion? -> elige la primitiva mas probable segun la superficie observada.

## 5. Verificacion (grounded, no adivinar)
- offset: cyclic + cyclic_find o angr (nunca lo asumas).
- alcanzabilidad: angr prueba que el sink/win es alcanzable desde entry con input controlado.
- Verdict "verified" SOLO con prueba de angr o ejecucion real en sandbox.

## 6. Eleccion de la ruta segun mitigaciones
- no-PIE + funcion win + overflow      -> ret2win ([[ret2win]])
- NX + estatico                        -> ret2syscall execve ([[rop]])
- NX + dinamico + leak posible         -> ret2libc / one_gadget ([[ret2libc]])
- Full RELRO (sin GOT)                 -> FSOP / exit handlers ([[io-file]], [[exit-handlers]])
- printf(user)                         -> format-string GOT overwrite ([[format-string]])
- Partial RELRO + sin leak             -> ret2dlresolve ([[got-plt]])
- poco espacio en pila                 -> stack pivot ([[advanced-rop]])
- pocos gadgets / control de registros -> ret2csu / SROP ([[advanced-rop]])
- bug de heap                          -> tcache poisoning / house-of-* segun glibc ([[heap]])
- seccomp bloquea execve               -> ORW ([[syscalls-seccomp]])

## 7. Construir y probar el PoC
Monta la cadena, ejecuta en sandbox aislado (--network none), captura shell/flag como
evidencia (id -> uid=0, o la flag). Un PoC serio termina en evidencia real, no en "deberia".

## 8. Reporte
Primitiva, cadena/payload, evidencia (salida real), severidad por IMPACTO real verificado, y la
mitigacion recomendada. Enlaza la evidencia al oraculo que la produjo.

## Regla de oro (binoracle)
Grounded over generated: cada afirmacion respaldada por un oraculo (r2/angr/debugger/ejecucion).
Cero falsos positivos por construccion: solo se promueve a "verified" lo que se prueba.
