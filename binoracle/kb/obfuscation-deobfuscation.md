# Ofuscacion y desofuscacion (cheat sheet)

Tecnicas que un binario usa para dificultar el analisis (no para explotar nada por si solas) y
como quitarlas de en medio para llegar al codigo real. Complementa [[anti-debug]] (deteccion de
depurador) y [[reversing-workflow]] (triage inicial: empaquetado/packers).

## Control-flow flattening
El grafo de control normal (if/for anidados con forma de arbol) se aplana a un UNICO bucle con
un `switch` gigante sobre una variable de estado:
```
state = 0;
while (1) {
    switch (state) {
        case 0: ... ; state = 3; break;
        case 1: ... ; state = 7; break;   // el "siguiente bloque" no es el que sigue en memoria
        ...
    }
}
```
En el disasm se ve como un jump table enorme (ver [[compiler-patterns]]) con bloques que no
tienen relacion de cercania logica entre si (el bloque que sigue a `case 0` puede ser `case 7`,
no `case 1`). Desofuscar: identifica la variable de estado, vuelca la tabla case->siguiente
estado, y reconstruye el grafo original a mano o con un script (angr/Miasm pueden emular
bloque a bloque y recuperar la secuencia real de estados para un input dado).

## Opaque predicates (condiciones falsas)
Un `if` cuyo resultado es SIEMPRE el mismo en tiempo de ejecucion pero no es obvio
estaticamente, para inflar el grafo con ramas muertas:
```
if ((x*x) % 4 != 2)   // nunca es 2 para ningun entero x -> rama "else" es codigo muerto,
    real_code();        // pero el desofuscador tiene que probarlo (SMT/angr) para descartarla
else
    junk_code();
```
Deteccion: si angr/un solver SMT concluye que una condicion es tautologia (siempre
true/false independientemente de la entrada simbolica), es opaque y esa rama se puede podar.

## Ofuscacion por maquina virtual (VM-based, la mas dura)
El compilador traduce el codigo sensible a BYTECODE PROPIO que un interprete (la "VM", escrita
en el propio binario) ejecuta en runtime. No hay codigo x86 nativo que reversear directamente:
hay que entender el interprete primero.
- Identificalo: un bucle `fetch-decode-dispatch`: lee un byte de un array de "bytecode", usa
  un jump table (o cadena de `cmp`) para elegir un handler, ejecuta, avanza el "program
  counter" virtual, repite. Muchas variables locales actuan como "registros virtuales".
- El interprete SI esta en claro (es codigo x86 normal); lo que esta oculto es la LOGICA,
  codificada como bytecode en `.rodata`/`.data`.
- Estrategia: (1) mapea cada opcode a su handler (tabla de dispatch), (2) para cada handler,
  entiende que efecto tiene sobre las "registros"/pila virtuales, (3) o bien traduce el
  bytecode a pseudocodigo a mano, o bien traza la ejecucion (Unicorn/angr/DBI como Frida/
  Pin/DynamoRIO) y observa el efecto EN RUNTIME sin desmontar la VM entera.
- Nota: tracing dinamico suele ser mas rapido que reversear el interprete a mano si solo
  necesitas el comportamiento para un input concreto (p.ej. validar una flag).

## Cifrado/ofuscacion de strings
Los strings sensibles (URLs de C2, mensajes de error reveladores, flags) se cifran en
`.rodata` y se descifran en una funcion `deobfuscate_str(ptr, len)` llamada justo antes de
usarlos (con XOR de un byte/clave fija, RC4, o un algoritmo custom):
- Busca funciones pequenas llamadas MUCHAS veces desde sitios distintos, con un bucle simple
  sobre un buffer y una operacion aritmetica/XOR -- candidata clara.
- binoracle marca esto como `secrets`/strings sospechosas solo si el VALOR ya esta en claro;
  si esta cifrado, r2_strings no lo vera como texto legible (aparecera como bytes random) y
  hace falta ejecutar/emular la rutina de descifrado (o replicarla en Python) para recuperarlo.

## Junk code / instrucciones basura
Secuencias que no cambian el estado observable (`push reg; pop reg`, `xor reg,reg` seguido de
un valor que se sobrescribe, saltos a la siguiente instruccion) insertadas para alargar el
disasm y confundir heuristicas de deteccion de patrones. No afectan el analisis SEMANTICO
(ejecucion simbolica/dinamica las atraviesa sin problema); solo estorban la lectura manual.
Ghidra/IDA con optimizacion de "instrucciones sin efecto" activada las colapsa automaticamente.

## Empaquetado (packers) -- desofuscar antes de reversear
Un binario empaquetado (UPX y similares, o un packer custom) tiene el codigo real comprimido/
cifrado y un STUB que lo descomprime en memoria antes de saltar a el:
- UPX: `upx -d binario` lo desempaqueta directamente si no esta modificado.
- Packer custom: pon un breakpoint en la ULTIMA instruccion del stub (normalmente un `jmp`/
  `call` a una direccion calculada dinamicamente = el OEP, Original Entry Point) y vuelca la
  memoria en ese momento (`gdb`: `dump memory`: o usa un plugin de unpacking de Ghidra/x64dbg
  con "Scylla" para reconstruir el PE tras el dump).
- Senal de que hay packer: muy pocos imports visibles en `ii` (el resto se resuelven en
  runtime), una sola seccion grande con alta entropia, y un entrypoint que no llama a
  `__libc_start_main`/`main` de forma reconocible.
