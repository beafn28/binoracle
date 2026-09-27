# Patrones de codigo generado por el compilador (cheat sheet)

Reconocer en el disasm lo que el COMPILADOR genera (no el programador escribio esto a mano)
ahorra horas: switch/loops/structs/llamadas indirectas tienen firmas reconocibles en x86,
x64 y ARM. Complementa [[reversing-workflow]] (metodologia) y [[arm-mips]]/[[arm64-exploitation]].

## Prologo/epilogo de funcion (identificar limites)
```
; x86/x64 clasico (sin -fomit-frame-pointer)
push rbp / mov rbp, rsp / sub rsp, N   ; prologo: reserva N bytes de locales
...
leave                                   ; = mov rsp,rbp; pop rbp
ret

; x86/x64 moderno (-O2, sin frame pointer): solo `sub rsp, N` al entrar, `add rsp, N; ret`
; al salir. RBP es un registro normal, mas dificil trazar el frame -> usa r2 `afvd`/Ghidra.

; ARM: push {r4-r7, lr} / ... / pop {r4-r7, pc}   (o `bx lr` si lr no se toco)
; ARM64: stp x29, x30, [sp, #-N]! (guarda fp+lr) / ... / ldp x29, x30, [sp], #N / ret
```

## Switch/case -> jump table
Un `switch` con casos densos compila a tabla de saltos, NO a una cadena de `cmp/je`:
```
cmp eax, 7          ; num de casos - 1 (rango check)
ja default_case
lea rdx, [rip+jump_table]
movsxd rax, dword [rdx+rax*4]   ; entrada de la tabla: offset de 32 bits (PIE-safe)
add rax, rdx
jmp rax
```
Con pocos casos o dispersos, el compilador prefiere `cmp/je` en cascada (mas facil de leer).
En Ghidra/r2, la tabla de saltos se ve como datos en `.rodata`; `afl`/`axt` sobre la direccion
de la tabla lista los casos. Un switch sobre un `char`/enum pequeno suele SER un jump table.

## Bucles: reconocer for/while/do-while
- `for`/`while` (test al PRINCIPIO): un `jmp` inicial salta a la condicion, el cuerpo esta
  antes; patron `jmp cond; body: ...; cond: cmp...; jl body`.
- `do-while` (test al FINAL, mas eficiente, el compilador prefiere convertir a esto cuando
  puede probar >=1 iteracion): `body: ...; cmp...; jl body` sin salto inicial.
- Loop unrolling (`-O2`/`-O3`): el cuerpo se repite 2-8x con el contador ajustado; si ves el
  mismo bloque de instrucciones repetido con offsets `+0`, `+8`, `+16`..., es un bucle
  desenrollado, no codigo distinto.

## Acceso a arrays/structs
- `array[i]`: `mov reg, [base + idx*escala]` (escala = sizeof elemento: 1/2/4/8). La escala
  te dice el TAMANO del elemento sin ver la declaracion.
- `struct.campo`: `mov reg, [base + offset_constante]`. Offsets constantes repetidos sobre el
  mismo puntero base = layout de un struct; reconstruyelo en Ghidra (`Structure Editor`) para
  que el resto del disasm se lea con nombres de campo en vez de offsets.
- Array de structs: `[base + idx*sizeof_struct + offset_campo]` -- combina ambos patrones.

## Llamadas indirectas (vtables, function pointers, callbacks)
```
mov rax, [rdi]        ; carga el vptr (primer campo de un objeto C++ con metodos virtuales)
call [rax+8]           ; llama a la 2a entrada de la vtable -> metodo virtual #1
```
Ver [[uaf-typeconfusion]] para el ataque (vptr hijack) y `av`/`r2_vtables` de binoracle para
detectarlas automaticamente. Un `call [reg]`/`call [reg+offset]` sin resolver estaticamente el
destino (no hay `call sym.foo` fijo) es SIEMPRE control de flujo indirecto: revisa quien
escribe ese puntero antes de la llamada.

## Calling conventions (para leer args sin mirar la firma)
- x86 cdecl: args en pila (derecha a izquierda), el llamante limpia la pila.
- x86 stdcall (WINAPI): args en pila, el LLAMADO limpia (`ret N`).
- x64 System V (Linux/macOS): RDI, RSI, RDX, RCX, R8, R9; resto en pila; RAX = retorno.
- x64 Microsoft (Windows): RCX, RDX, R8, R9; shadow space de 32 bytes reservado por el
  llamante (ver [[windows-exploit]]).
- ARM (AAPCS): R0-R3; resto en pila; R0 = retorno.
- ARM64 (AAPCS64): X0-X7; resto en pila; X0 = retorno; X30 = link register (direccion de
  vuelta, NO esta en la pila salvo que la funcion haga push explicito -- por eso ARM64 no
  tiene un "saved return address" clasico que hacer overflow directo, hay que sobrescribir
  donde se GUARDO x30 en la pila).

## Tail calls (confunden el analisis de flujo)
`jmp sym.otra_funcion` (en vez de `call`) al final de una funcion es una tail call: la funcion
actual no vuelve, salta directo a la siguiente reutilizando el frame. r2/Ghidra a veces NO
marcan esto como una llamada real, asi que un grep de `call sym.peligrosa` puede perderse un
camino que llega ahi por `jmp`.
