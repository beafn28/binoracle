# Técnica: código auto-modificable vía introspección de dirección de retorno (patrón getRetAddress)

## Patrón a reconocer

Un binario con técnicas anti-debug/anti-análisis parchea SU PROPIO código en tiempo de
ejecución, usando una función que lee su propia dirección de retorno de la pila
(`dword[esp+4]` en x86, o equivalente) para calcular DÓNDE escribir el parche, en vez de usar
una dirección fija. Un ejemplo típico: `getRetAddress()` se llama varias veces desde distintos
puntos de `main()`, y cada llamada usa un OFFSET distinto desde su propia dirección de retorno
(p.ej. `getRetAddress()+391`) para localizar y sobrescribir bytes de otra función (parches tipo
NOP-slide reemplazados por instrucciones reales, claves XOR corregidas, etc.).

## Por qué importa

El código ESTÁTICO en el binario (lo que ve `pdf`/un desensamblador normal) muestra la versión
SIN PARCHEAR -- NOPs, una constante incorrecta, una comparación que parece fallar. Si no se
reconoce el patrón de auto-parcheo, es fácil concluir erróneamente "esto no se puede verificar
sin ejecutar el binario" cuando en realidad el parche real SÍ es derivable estáticamente.

## Cómo aplicarlo

1. Busca una función que lea su propia dirección de retorno (acceso directo a la pila en el
   prólogo, antes de cualquier `push`/`sub esp`) -- es la firma de `getRetAddress()`.
2. Si esa función se llama VARIAS veces desde `main()` (u otra función), cada llamada devuelve
   una dirección DISTINTA según desde qué punto se invoque. Identifica TODOS los call-sites, no
   asumas que el primero (o el más obvio) es el correcto para un parche concreto.
3. Para cada call-site, calcula `direccion_de_retorno + offset` (el offset usado en el código
   que sigue a la llamada) y comprueba si esa dirección cae EXACTAMENTE sobre una región
   sospechosa (un hueco de NOPs, una constante que no tiene sentido, bytes que no decodifican
   bien). La dirección correcta suele caer con precisión quirúrgica sobre ese hueco -- una
   coincidencia tan exacta no es casualidad.
4. Decodifica los bytes que el parche escribe ahí como instrucciones reales (no como NOPs) y
   continúa el análisis con el código YA PARCHEADO, no con la versión estática original.
5. Si el resultado final (un mensaje descifrado, una comparación) da texto COHERENTE y
   completo, es una señal fuerte de que el parche se identificó correctamente -- más fuerte que
   cualquier trazado manual instrucción a instrucción.

## Caso real confirmado (CTF "Anti-Debugging")

Un crackme con 2 parches distintos vía el mismo mecanismo `getRetAddress()+391`: uno corrige
una comparación (`sub al,0xa` → `sub al,0x05` en la validación de contraseña) y otro rellena un
hueco de 4 NOPs en el bucle que descifra el mensaje final con 2 instrucciones reales
(`mov al,0x6e; xor al,[edx]`). Identificar CUÁL de las 4 llamadas a `getRetAddress()` en
`main()` correspondía a cada parche (probando las 4 sistemáticamente) resolvió el reto
completo, incluyendo el mensaje final, sin necesitar depurador ni Wine.
