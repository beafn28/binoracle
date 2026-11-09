# House of Lore (cheat sheet)

Tecnica de heap para conseguir un `malloc()` arbitrario (fake chunk) abusando de los small bins
en vez de fastbin/tcache. Complementa las house-of-* ya resumidas en [[heap]] (Force/Spirit/
Einherjar/Botcake): esta se centra en small bins, que tienen su propia comprobacion de
consistencia distinta a fastbin.

## Idea central
Los small bins son listas doblemente enlazadas (fd/bk). Al insertar un chunk falso en la cabeza
del bin (mediante un UAF que sobrescriba el `bk` del chunk real que esta en la cabeza, apuntando
a tu chunk falso), la SIGUIENTE peticion malloc() de ese tamano recorre la lista y puede devolver
tu chunk falso si pasa la comprobacion `victim->bk->fd == victim` (que tu mismo preparas en la
estructura falsa para que cuadre).

## Pasos tipicos
1. Fuerza a que haya un chunk real en el small bin del tamano objetivo (libera uno de ese
   tamano y evita que otra asignacion lo reutilice antes).
2. Via UAF, sobrescribe el `bk` de ese chunk real para que apunte a tu chunk falso (en una
   region que controles: pila, heap, .bss).
3. En el chunk falso, fabrica un `fd` que apunte de vuelta al chunk real (o cumpla la
   comprobacion de consistencia de la version de glibc que estes atacando).
4. La siguiente malloc() de ese tamano devuelve el chunk REAL (paso intermedio); la de despues
   devuelve tu chunk FALSO -> control total del contenido devuelto.

## Comprobaciones que hay que superar
glibc valida (segun version) que `bck->fd == victim` al sacar un chunk del small bin; por eso el
chunk falso necesita un `fd` coherente. Fallar esta comprobacion aborta con corrupcion de lista
enlazada, igual que en [[unlink-exploitation]].

## Cuando usarla
Es mas dificil de montar que tcache poisoning (necesita UAF, no solo un simple double-free) y
casi siempre queda eclipsada por tcache en glibc >= 2.26 para tamanos pequenos -- su nicho real
es cuando el tamano objetivo excede el rango de tcache pero sigue siendo "small" (hasta ~0x400
tipicamente), o en binarios que fuerzan el vaciado del tcache.

## Ver tambien
[[heap]] (tabla general), [[largebin-attack]] (equivalente para chunks aun mas grandes).
