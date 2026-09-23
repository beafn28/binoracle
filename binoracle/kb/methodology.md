# Metodologia de auditoria de un binario (cheat sheet)

1. Triage: arquitectura, tipo, stripped, mitigaciones (checksec). Define el terreno.
2. Superficie: imports peligrosos (gets, strcpy, sprintf, system, printf(user)), entradas
   (argv, stdin, ficheros, red), cadenas interesantes.
3. Sinks: para cada sink peligroso, quien lo llama y con que datos (xrefs).
4. Hipotesis de primitiva: overflow de stack? format-string? heap UAF/double-free? leak?
5. Verificacion (grounded): offset por cyclic/angr; alcanzabilidad por angr; nunca afirmar
   sin prueba. Verdict "verified" solo con prueba de angr o ejecucion real.
6. Explotacion segun mitigaciones:
   - no-PIE + win  -> ret2win
   - NX + estatico -> ret2syscall (execve)
   - NX + dinamico + leak -> ret2libc (o one_gadget)
   - printf(user)  -> format-string (GOT overwrite)
   - heap bug      -> tcache poisoning / house-of-* segun glibc
7. PoC reproducible en sandbox aislado; capturar shell/flag como evidencia.
8. Reporte: primitiva, cadena, evidencia, severidad por impacto real, mitigacion recomendada.

Regla de oro binoracle: grounded over generated. Cada afirmacion respaldada por un oraculo.
