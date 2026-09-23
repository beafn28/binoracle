# Bypass de stack canary (cheat sheet)

El stack canary (stack protector / __stack_chk) es un valor aleatorio colocado entre los
buffers locales y el saved RBP/RIP. En el prologo se copia desde el TLS (`mov rax, fs:0x28`);
en el epilogo se compara y, si cambio, llama `__stack_chk_fail` -> abort. El byte bajo es 0x00
(para frenar leaks por strcpy/printf que cortan en NUL).

## Layout de la pila protegida
```
[ buffer local ] [ ... ] [ CANARY (8B, acaba en 00) ] [ saved RBP ] [ saved RIP ]
```
Un overflow lineal pisa el canary antes de llegar a RIP -> tienes que reponerlo con su valor
correcto, o no pasar por el.

## 1. Fugar el canary y reponerlo (lo mas comun)
- format-string: `%N$p` sobre el offset de la pila donde esta el canary (lo reconoces: valor
  aleatorio que TERMINA en 00 y esta cerca del saved rbp/rip).
- OOB read / printf de un buffer sin terminar en NUL que llegue hasta el canary (un `%s` que
  lee de mas). Truco: sobrescribe el byte 0x00 bajo del canary con un no-nulo para que el print
  siga hasta filtrar los 7 bytes altos.
- read que no pone NUL: si te dejan leer justo hasta el canary y luego imprimen, lo filtras.
Luego: `payload = b"A"*off_al_canary + p64(canary) + p64(saved_rbp) + <ROP/RIP>`.
```
canary = u64(io.recv(8))          # tras el leak
payload = b'A'*40 + p64(canary) + p64(0) + p64(pop_rdi) + ...
```

## 2. Escritura que NO pasa por el canary
- arb write (format-string %n, indice OOB con signo) directamente sobre saved RIP, una GOT, o
  __stack_chk_fail@GOT (redirigir el propio fallo a system/one_gadget).
- sobrescribir una VARIABLE de control (no el RIP) para desviar la logica sin tocar el canary.

## 3. Brute-force byte a byte (fork server)
Si el proceso hace fork por conexion (o forkea hijos), el canary NO cambia entre hijos (heredan
el TLS del padre). Fuerza byte a byte: prueba el siguiente byte con 256 valores; el hijo que NO
aborta acerto ese byte. 7 bytes utiles (el 1o es 00) -> ~7*128 intentos de media. Mismo truco
para PIE/retaddr si hay fork.

## 4. Evitar el canary por completo
- si el overflow esta en una funcion SIN canary (no todas la tienen: gcc solo protege las que
  tienen arrays/allocas segun heuristica). Busca la funcion vulnerable sin `fs:0x28`.
- overflow no lineal (indice controlado) que escribe DIRECTO en saved RIP sin tocar el canary.
- __stack_chk_fail redirigido: si vas a abortar igual, apunta su GOT a un one_gadget.

## Notas
- El canary es por-thread, en el TLS (`fs:0x28`). Un leak del TLS o de la TCB lo revela.
- Comprueba con checksec/rabin2 si REALMENTE hay canary antes de asumirlo.
- Sin fork, el canary cambia por proceso: fuga y usa en la MISMA conexion; no lo reuses entre
  ejecuciones.
- El canary no protege overwrites de datos ANTES del saved RIP que no sean el retaddr (punteros
  locales, variables) -> a veces ni necesitas el canary.
