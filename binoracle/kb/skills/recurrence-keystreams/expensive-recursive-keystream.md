# Técnica: función recursiva "cara" usada como generador de keystream

## Patrón a reconocer

Un reto de reversing a veces computa cada byte de la flag como:

    flag[i] = XOR(recursive_fn(f(i)), ciphertext[i])

donde `recursive_fn` es una función SIN memoización que se llama a sí misma 1 o 2 veces por
nivel (tipo Fibonacci: `R(n) = a*R(n-1) + b*R(n-2)`), y `f(i)` crece con `i` (p.ej. `i*i`).

**Señal de alarma en el disassembly**: dos o más `call` recursivas a la MISMA función dentro
de su propio cuerpo, sin ningún array/tabla de cache visible. Esto es tiempo EXPONENCIAL
(como Fibonacci naive) -- para argumentos grandes (decenas o cientos), ejecutar la función
de verdad (o emularla instrucción a instrucción, incluyendo con angr) tardaría más que la
vida del universo. El propio chiste de este tipo de reto suele ser "optimiza tu código":
el jugador no debe ejecutar la recursión, debe reconocer la relación y resolverla con
programación dinámica.

## Cómo resolverlo (orden de preferencia)

1. **`angr_call_function`** (herramienta de binoracle): llama a la función con el argumento
   real directamente. Si el argumento es pequeño, esto basta y es instantáneo.
2. Si `angr_call_function` NO termina a tiempo (degrada con "did NOT complete within
   budget"), es la señal de que el argumento real es demasiado caro -- NO reintentar con el
   mismo argumento.
3. **`angr_extrapolate_recurrence`**: muestrea la función en argumentos pequeños (0..~10),
   ajusta la relación de recurrencia lineal de menor orden que explica EXACTAMENTE esas
   muestras, y extrapola al argumento grande con aritmética exacta en tiempo O(n). Esto
   resuelve el patrón completo sin que el modelo tenga que derivar ni verificar la fórmula a
   mano.
4. Una vez se tiene el valor de la función para cada `i`, se hace XOR contra el byte
   correspondiente del ciphertext (normalmente visible como literal cifrado en `.rodata` o
   `.data`, cerca de la llamada a la función recursiva) para reconstruir cada carácter de la
   flag.

## Caso real confirmado (CTF "recur")

- `R(0)=3, R(1)=5, R(n)=2*R(n-1)+3*R(n-2)` para `n = i*i`, `i=0..27`.
- `angr_extrapolate_recurrence` reprodujo exactamente esta fórmula a partir de muestras y
  extrapoló `R(729)` con aritmética exacta.
- Flag real: `utflag{0pt1m1z3_ur_c0d3_l0l}` (confirmada por longitud exacta de 28 caracteres,
  terminación en `}`, y verificación cruzada contra la ejecución simbólica real de `angr`
  en los valores pequeños).
