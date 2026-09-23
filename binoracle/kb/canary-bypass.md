# Bypass de stack canary (cheat sheet)

El canary es un valor aleatorio colocado entre los buffers locales y el saved RBP/RIP. Al
retornar, `__stack_chk_fail` aborta si cambio. En glibc el byte bajo del canary es 0x00 (para
frenar leaks por strcpy/print).

## Formas de saltarselo
1. Fugar el canary y reponerlo:
   - format-string: `%N$p` sobre el offset donde vive el canary en la pila.
   - OOB read / print de un buffer sin terminar que llegue hasta el canary.
   - Una vez leido, tu payload = padding + canary + saved_rbp + RIP_control.

2. Overwrite que no pasa por el canary:
   - escritura arbitraria (format-string %n, index OOB) directamente sobre saved RIP o sobre
     una GOT/puntero llamado antes del epilogo.
   - sobrescribir una variable de control (no el RIP) para desviar la logica.

3. Brute-force byte a byte (fork server):
   - si el proceso hace fork por conexion, el canary NO cambia entre hijos. Prueba byte a byte
     (256 intentos por byte, el hijo que no aborta acerto). 7 bytes utiles (el 1o es 0x00) ->
     ~7*128 intentos de media.

4. Evitar el canary por completo:
   - si el overflow esta en una funcion SIN canary (no todas lo tienen), o si puedes saltar a
     una via alternativa.
   - SROP/ret2dlresolve tras un pivot que no dependa del epilogo protegido.

## Notas
- El canary es por-thread (en TLS, `fs:0x28`). Si controlas un leak de TLS puedes leerlo.
- Comprueba con checksec si realmente hay canary antes de asumirlo.
- Tras fugarlo, cuidado con reusarlo entre ejecuciones si NO hay fork (cambia por proceso).
