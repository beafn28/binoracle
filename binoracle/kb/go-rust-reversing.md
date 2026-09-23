# Reversing de binarios Go y Rust (cheat sheet)

Go y Rust producen binarios nativos ELF/PE/Mach-O, pero con runtime y convenciones propias que
confunden a los desensambladores. Suelen ser estaticos y grandes. Aqui, lo que cambia respecto
a C y como orientarse.

## Go
- Binarios estaticos y grandes; incluyen su runtime (goroutines, GC, scheduler).
- Simbolos: aunque este "stripped", Go guarda metadatos (pclntab) con nombres de funcion y
  ficheros. Herramientas: `go tool`, GoReSym, redress, el plugin de Ghidra para Go
  (golang_loader_assist / gostringungarbler) recuperan nombres, strings y tipos.
- Calling convention: Go < 1.17 pasa TODOS los args y retornos por la PILA (no en registros);
  Go >= 1.17 usa registros (ABIInternal: rax, rbx, rcx, rdi, rsi...). Ojo al analizar.
- strings: NO terminan en NUL; son (puntero, longitud). Un "string" en Go se ve como dos campos.
  Por eso ves texto pegado en .rodata sin separadores.
- goroutines: `go func()` -> runtime.newproc; la stack crece dinamicamente (stack splitting).
- panics/errores en vez de codigos de retorno C.
- superficie de pwn: overflows en cgo (parte C), o bugs de logica; el runtime de Go tiene
  bounds checking en slices (dificil de overflow puro Go).

## Rust
- Binarios nativos con name mangling propio (`_ZN...` legacy o `_R...` v0). rustfilt / c++filt
  (para v0 usa rustc-demangle) desofuscan los nombres.
- panics con mensajes que suelen filtrar el fichero/linea del source (utiles para orientarse).
- monomorfizacion de genericos -> muchas copias de la misma funcion con tipos distintos.
- seguridad de memoria por defecto (borrow checker): los bugs suelen estar en `unsafe {}`,
  en FFI (llamadas a C), o en logica. Busca bloques unsafe y llamadas externas.
- calling convention: la C ABI en `extern "C"`, pero la Rust ABI interna no es estable.

## Como orientarse (ambos)
- identifica el lenguaje: strings del runtime ("go1.2x", "runtime.", rutas /rustc/<hash>/,
  panic messages), Detect It Easy, `rabin2 -I`.
- recupera simbolos con la tool adecuada ANTES de analizar (cambia radicalmente la legibilidad).
- concentra el analisis en cgo/FFI/unsafe y en el parser de la entrada del usuario.
- para pwn real, la parte C (cgo) o un `unsafe` mal hecho es tu vector; el codigo puro Go/Rust
  raramente tiene los overflows clasicos de C.

## Herramientas
Ghidra/IDA con plugins de Go/Rust, GoReSym, redress, rustfilt, Detect It Easy, gdb (con el
runtime cargado), delve (dlv) para debug de Go.
