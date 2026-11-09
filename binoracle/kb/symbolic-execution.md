# Ejecucion simbolica para CTF: angr y Z3 (cheat sheet)

En vez de razonar el binario a mano, la ejecucion simbolica trata las entradas como variables
SIMBOLICAS (no valores concretos) y explora los caminos de ejecucion posibles, generando al final
las CONDICIONES matematicas que un solver (Z3) resuelve para dar una entrada concreta que
alcance el estado objetivo. Muy util contra checks de contrasena/serial complejos, crackmes con
muchas ramas, o VMs/ofuscacion donde razonar manualmente es lento.

## Cuando usarlo (y cuando NO)
- SI: crackmes/checks de entrada con logica compleja pero determinista (comparaciones, XORs,
  tablas), sobre todo si el arbol de decision es grande pero cada rama es barata de simular.
  Tambien para RESOLVER una condicion aritmetica sin tener que despejarla a mano (Z3 solo, sin
  simular todo el binario).
- NO / mal candidato: binarios con syscalls pesadas, mucha interaccion con el sistema real
  (red, ficheros), bucles con MUCHAS iteraciones dependientes de la entrada (explosion de
  estados), o codigo con mucha aritmetica de punto flotante (angr lo soporta mal).

## angr: flujo tipico
1. `proj = angr.Project(binario, auto_load_libs=False)` -- carga el binario en el motor.
2. Define el ESTADO INICIAL: `proj.factory.entry_state(args=[...], stdin=angr.SimFile(...))`, o
   `blank_state` si quieres empezar en una direccion concreta con memoria simbolica poblada a
   mano.
3. Marca como simbolico lo que el atacante controla (bytes de stdin, argv) con
   `claripy.BVS('nombre', bits)`.
4. Explora con `proj.factory.simulation_manager(state).explore(find=DIR_OBJETIVO,
   avoid=(DIR_MALA_1, DIR_MALA_2, ...))` -- `find` es la direccion que quieres alcanzar (p.ej. el
   mensaje "Correct!"), `avoid` las que quieres podar (p.ej. "Wrong!") para no explotar el
   espacio de estados.
5. Si angr encuentra un estado que llega a `find`, `found[0].posix.dumps(0)` (o
   `.solver.eval(entrada_simbolica, cast_to=bytes)`) te da la entrada CONCRETA que lo logra.

## Acelerar la exploracion
- `avoid` agresivo: poda cualquier rama que sepas que es un callejon sin salida (mensajes de
  error, funciones de salida temprana).
- Hooks: reemplaza funciones costosas/irrelevantes (I/O real, funciones de librerias externas
  sin logica interesante) con un stub simbolico simple via `proj.hook(direccion, tu_funcion)`
  para que angr no intente simular su interior.
- `LAZY_SOLVES`/tecnicas de exploracion alternativas (`explore` con `num_find`, DFS vs BFS) cuando
  el espacio de estados crece demasiado.

## Z3 solo (sin simular todo el binario)
Cuando ya entiendes la logica (por ejemplo tras decompilar) pero es tediosa de invertir a mano
(un sistema de ecuaciones, una funcion hash custom reversible), se puede MODELAR esa logica
directamente en Z3 (`z3.BitVec`, operaciones bit a bit, `solver.add(...)`) sin pasar por angr en
absoluto -- mas rapido cuando la logica cabe en unas pocas restricciones explicitas.

## Ver tambien
[[compiler-patterns]] (reconocer la logica antes de modelarla), [[ctf-techniques]] (vision
general de tecnicas por categoria de reto).
