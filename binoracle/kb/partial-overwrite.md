# Partial Overwrite (cheat sheet)

Tecnica para saltar una direccion cuando solo controlas ALGUNOS bytes bajos de ella (tipico
formato-string de un solo `%hn`/`%hhn`, o un overflow que solo llega a pisar parte de un
puntero guardado en la pila) en binarios con PIE/ASLR, sin necesitar un leak completo.

## Por que funciona
ASLR aleatoriza la pagina base, pero dentro de un binario PIE/una libreria, los bytes MAS BAJOS de
una direccion (normalmente los ultimos 1.5-3 bytes, hasta el limite de una pagina o de la region
mapeada) siguen siendo relativos al offset dentro del binario/libreria y no cambian entre
ejecuciones si conoces el binario/libc exactos. Solo los bytes ALTOS (la base de la region) estan
aleatorizados.

## Aplicacion tipica: pisar solo el byte bajo de una direccion de retorno
Si tienes una direccion de retorno guardada en la pila que apunta DENTRO del mismo binario (por
ejemplo, la vuelta de `main` a `__libc_start_main`, o el retorno de una funcion a otra del propio
programa), y tu overflow solo puede escribir 1-2 bytes antes de topar con un canary o el limite
del buffer, puedes sobrescribir SOLO el byte(s) menos significativo(s) de esa direccion para
redirigir el retorno a OTRA funcion cercana del mismo binario (p.ej. de `vuln()` de vuelta a
`vuln()` otra vez, o a `win()` si su direccion comparte los mismos bytes altos).

## Con formato de cadena (%hn/%hhn)
`%hn` escribe 2 bytes, `%hhn` escribe 1 byte, en la direccion que apunta el argumento
correspondiente -- perfecto para sobrescribir solo la parte baja de una GOT entry o de una
direccion de retorno sin necesitar controlar (ni conocer) los bytes altos aleatorizados.

## Riesgo de fuerza bruta
Cuando el partial overwrite no alcanza para llegar EXACTAMENTE al objetivo (por ejemplo, porque
el byte que controlas determina 1 de 256 posibles destinos), a veces se combina con reintentos:
en servicios que hacen `fork()` por conexion, los hijos heredan la MISMA aleatorizacion que el
padre, asi que puedes reintentar la conexion repetidamente probando byte a byte sin que la base
cambie entre intentos -- ver [[canary-bypass]] para el mismo principio aplicado al canary.

## Limitaciones
- Solo sirve para saltar DENTRO del mismo rango de pagina/mapping (el offset controlado no puede
  cruzar el limite donde cambiarian los bytes altos).
- No sirve para saltar a una region completamente distinta (por ejemplo de PIE a libc) sin
  conocer tambien los bytes altos de esa otra region.

## Ver tambien
[[canary-bypass]] (brute-force con fork), [[advanced-rop]], [[stack-pivot]].
