# Reversing para CTF: workflow y patrones (cheat sheet)

Metodologia para ENTENDER un binario compilado/ofuscado/empaquetado/virtualizado antes de
explotarlo o resolverlo (flag checkers, crackmes, VMs custom, packers, anti-debug). Cuando ya
entiendes la vuln y solo queda explotar, ve a las hojas de pwn ([[methodology]]). Adaptado del
skill ctf-reverse (MIT).

## Quick wins (prueba SIEMPRE primero)
```
strings binary | grep -Ei 'flag\{|ctf\{|pico|secret|password'
rabin2 -z binary | grep -i flag           # strings de secciones de datos
ltrace ./binary                            # llamadas a libc (strcmp/memcmp revelan el target)
strace -f -s 500 ./binary                  # syscalls
xxd binary | grep -i flag
./binary AAAA ; echo test | ./binary       # comportamiento con input de prueba
```
Muchos retos faciles filtran la flag en claro o por ltrace sin reversear nada.

## Triage inicial
```
file binary            # tipo, arquitectura, estatico/dinamico, stripped
rabin2 -I binary       # arch, bits, lang (go/rust), mitigaciones, packer
checksec --file=binary # mitigaciones
```
Detecta el LENGUAJE/formato: C, Go/Rust ([[go-rust-reversing]]), .NET, Python bytecode, WASM,
Android ([[android-native]]), UPX/packer ([[anti-debug]]), VM custom.

## Orden de ataque (de menos a mas esfuerzo)
1. strings / ltrace / strace (flag en claro o en una comparacion).
2. Frida: hookear strcmp/memcmp para capturar el valor esperado SIN reversear.
3. angr: ejecucion simbolica para resolver flag-checkers automaticamente (find=exito, avoid=fallo).
4. Qiling/unicorn: emular binarios de otra arquitectura o saltar anti-debug pesado sin artefactos.
5. Mapear el control de flujo (r2 `agf`, Ghidra) antes de modificar la ejecucion.
6. Automatizar (r2pipe, Frida, angr, Python) cualquier proceso manual repetitivo.

## Memory dumping (deja que el programa calcule la flag)
Idea clave: en vez de reversear la transformacion, deja que el binario compute la respuesta y
VUELCALA. Break en la comparacion final (`b *main+OFFSET`), mete un input del largo correcto, y
`x/s $rsi` (o el registro que compara) para leer la flag ya calculada.

## Direccion de la comparacion (critico)
- `transform(flag) == target`  -> hay que INVERTIR la transformacion.
- `transform(target) == flag`  -> la flag ES el dato transformado: aplica transform al target.
Identifica cual de los dos operandos viene del usuario.

## Deteccion de decoy flags
Varios targets falsos antes del check real, con mensajes de exito distintos. Pon el breakpoint
en la comparacion FINAL, no en las primeras.

## GDB con PIE
```
gdb ./binary
start            # fuerza la resolucion de la base PIE
b *main+0xca     # breakpoint relativo a main
run
```

## Patrones de cifrado comunes en flag checkers
- XOR de 1 byte: prueba los 256 valores.
- XOR con plaintext conocido (`flag{`, `CTF{`).
- XOR con el indice de posicion (`^ i`) combinado con clave repetida.
- RC4 con clave hardcoded; permutacion custom + XOR; S-box/keystream.
- resuelvelo con z3 si es un sistema de constraints (cada byte una ecuacion).

## Anti-analisis (que buscar)
ptrace(TRACEME), /proc/self/status TracerPid, timing RDTSC, VM custom (interprete de opcodes),
self-modifying code, SIGILL/SIGSEGV/SIGFPE como handlers de control de flujo, nanomites,
opaque predicates, junk bytes, MBA (mixed boolean-arithmetic). Bypass en [[anti-debug]].

## Herramientas por tarea
- estatico: Ghidra (r2ghidra en radare2), IDA, Binary Ninja, radare2/rizin+cutter, dogbolt.org
  (comparar decompiladores).
- dinamico: gdb+pwndbg/gef, Frida (hooks), lldb, x64dbg (Windows).
- simbolico/emulacion: angr, Qiling, unicorn, Triton (DSE), z3.
- formatos: uncompyle6/pycdc (Python), wasm-decompile (WASM), jadx/apktool (Android), dnSpy (.NET).

## Cuando cambiar de enfoque
Si ya entiendes el binario y toca heap/ROP/kernel -> hojas de pwn. Si el nucleo es cripto/mates
-> resuelvelo como cripto. Si es una VM de juguete/pyjail -> tratalo como puzzle, no como binario.
