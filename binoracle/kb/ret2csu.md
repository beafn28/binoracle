# ret2csu (cheat sheet)

Tecnica de ROP para x86-64 que reutiliza el codigo generado por el compilador dentro de
`__libc_csu_init` (la rutina que inicializa los arrays de constructores globales, presente en
CASI todo binario estatico o dinamicamente enlazado compilado con gcc/glibc) como un gadget
"universal" para controlar registros cuando el binario apenas tiene gadgets propios utiles.

## Por que existe
`__libc_csu_init` contiene, de forma casi identica en la mayoria de binarios x86-64 con glibc, un
bloque que hace `pop`s de varios registros de proposito general seguido de una llamada indirecta,
y otro bloque que mueve esos registros a los de la convencion de llamada (rdi/rsi/rdx) antes de
saltar. Como esta funcion la mete el LINKER (no el codigo del programador), esta presente incluso
en binarios muy pequenos y "vacios" de gadgets utiles -- por eso es el recurso favorito cuando
`ROPgadget`/`ropper` no encuentran nada mejor.

## Los dos bloques clave
1. **Bloque de pops**: permite hacer pop de varios registros (tipicamente los que luego se
   mueven a rdi/rsi/rdx) de golpe, seguido de una llamada `call [reg + offset]` -- si controlas
   el registro que actua como puntero de la tabla de funciones, controlas A DONDE salta.
2. **Bloque de setup de argumentos**: antes del `call`, copia esos registros pop-eados a los
   registros de argumento de la convencion de llamada de System V (rdi, rsi, rdx) -- esto es lo
   que te permite, con solo este gadget, poner los 3 primeros argumentos de una llamada a
   funcion arbitraria (por ejemplo `write(1, buf, len)` para un leak, o preparar argumentos antes
   de saltar a `execve`).

## Limitacion tipica
El salto final es una llamada INDIRECTA a traves de un puntero que tu tambien controlas (dentro
de una tabla que fabricas o apuntas a una GOT entry) -- tras la llamada, la ejecucion vuelve al
gadget en un punto fijo, no directamente a donde quieras, asi que normalmente se usa para UNA
llamada (o para encadenar con otro ret2csu) mas que para una cadena larga arbitraria.

## Cuando usarla
- Binarios estaticos o muy pequenos, sin apenas gadgets propios.
- Cuando necesitas controlar rdi/rsi/rdx para una llamada de 3 argumentos y no hay gadgets
  `pop rdi; ret` / `pop rsi; pop rdx; ret` limpios disponibles por separado.
- Como paso intermedio para conseguir un leak (llamar a `write`/`puts` con argumentos
  controlados) antes de un ret2libc completo.

## Ver tambien
[[advanced-rop]] (ROP general), [[srop]] (alternativa cuando necesitas TODOS los registros, no
solo 3), [[got-plt]] (para entender que hay en la GOT que se pueda usar como puntero de salto).
