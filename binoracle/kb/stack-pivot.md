# Stack Pivoting (cheat sheet)

Tecnica para mover el stack pointer (`rsp`/`esp`) a una region de memoria que controlas cuando el
overflow disponible es DEMASIADO PEQUENO para caber una cadena ROP completa en la pila real, pero
si tienes otra zona mas grande (heap, .bss, una seccion de datos) con contenido controlado.

## Cuando hace falta
- El buffer vulnerable en la pila es pequeno (unos pocos bytes hasta la direccion de retorno) y
  no cabe una ROP chain larga despues del overflow.
- Existe OTRO sitio (heap, .bss, un buffer global) donde SI puedes escribir una cadena ROP larga
  ANTES de disparar el overflow corto.

## Mecanica basica
1. Escribe tu cadena ROP completa en la region controlada (heap/.bss/etc), por el canal que sea
   (otra opcion del menu, otra entrada, etc.).
2. Dispara el overflow corto para sobrescribir SOLO la direccion de retorno (o, si el overflow da
   para un poco mas, tambien `rbp`) con un gadget `leave; ret` o `pop rsp; ret` (o
   `pop rbp; ret` seguido de `leave; ret`) que apunte `rsp` a la region controlada.
3. Tras el `ret` del pivot, la ejecucion sigue leyendo instrucciones de la NUEVA pila (tu region
   controlada), donde esta la cadena ROP real.

## Gadgets de pivot mas comunes
- `pop rsp; ret` (o `pop esp; ret` en x86): el mas directo -- el valor que pusiste donde estaba
  la direccion de retorno se convierte en el nuevo rsp.
- `leave; ret`: equivalente a `mov rsp, rbp; pop rbp; ret` -- si controlas `rbp` (por ejemplo con
  un `pop rbp; ret` previo), el pivot apunta rsp a donde apuntaba rbp.
- `xchg rax, rsp; ret` (o variantes con otros registros): util si tienes control de un registro
  pero no de rbp directamente.

## Precauciones
- La region destino necesita ser EJECUTABLE-INDEPENDIENTE en el sentido de que el pivot no
  ejecuta codigo AHI (solo la usa como pila para leer los siguientes "retornos"), asi que sirve
  aunque la region no sea NX-exempt: lo que importa es que sea LEGIBLE y que su contenido sean
  direcciones/gadgets validos, no que sea ejecutable.
- Si el binario tiene PIE/ASLR, necesitas primero un leak para calcular la direccion real de la
  region controlada antes de poder apuntar el pivot ahi con precision.

## Ver tambien
[[advanced-rop]] (construir la cadena que se ejecuta despues del pivot), [[srop]] (alternativa
cuando el pivot no es viable pero si puedes invocar sigreturn), [[ret2csu]].
