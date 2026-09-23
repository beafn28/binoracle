# macOS / iOS: Mach-O y PAC (cheat sheet)

Explotacion en el mundo Apple. El formato es Mach-O (no ELF), el linker es dyld, y en Apple
Silicon (arm64e) hay Pointer Authentication (PAC) que firma punteros de codigo.

## Mach-O basico
- Cabecera + load commands (LC_SEGMENT_64, LC_MAIN, LC_LOAD_DYLIB, LC_CODE_SIGNATURE...).
- Enlace: bind opcodes clasicos o LC_DYLD_CHAINED_FIXUPS (cadenas de fixups modernas) resuelven
  los imports. No hay GOT/PLT al estilo ELF; hay __got y stubs, pero el flujo lo maneja dyld.
- checksec equivalente: PIE (casi siempre), stack canary, ARC, code signing, hardened runtime.
- Herramientas: `otool -l/-tV`, `nm`, `codesign -dv`, `dyld_info`, Hopper/Ghidra/IDA.

## Diferencias al explotar (vs Linux)
- ret2libc apunta a libSystem (dyld_shared_cache: las libs del sistema estan pre-linkadas en
  una cache unica; sus direcciones vienen de ahi, no de un .so suelto).
- syscalls BSD: numeros con clase alta (0x2000000 + n en x86-64; en arm64 svc con x16). execve
  existe pero el sandbox de la app puede bloquearlo.
- code signing: no puedes ejecutar codigo no firmado en iOS -> el objetivo suele ser ROP/JOP
  puro o abusar de JIT (navegador) en vez de shellcode.

## PAC (arm64e, ARMv8.3)
Firma criptografica en los bits altos de los punteros (return addr, function pointers,
vtables). Instrucciones PACIA/AUTIA (y B/DA/DB variants) firman/verifican con claves por
proceso; un AUT fallido corrompe el puntero -> crash al usarlo.
- Rompe el ROP clasico: no puedes saltar a una direccion arbitraria sin un puntero firmado
  valido.
- Bypass conocidos: fuga y REUSO de punteros ya firmados (buffer overread para "cosechar"
  punteros validos y reutilizarlos), oraculos de firma (p.ej. abusar de dyld chained fixups
  para que dyld escriba punteros PAC-validos), o bugs que evitan el AUT.
- Tambien hay BTI (ARMv8.5): los saltos indirectos deben caer en un `bti` -> limita los
  gadgets (JOP) validos.

## Syscalls (detalle)
- x86-64: numero = 0x2000000 | n (clase Unix=2); `syscall`. execve = 0x2000003b.
- arm64: numero en x16, `svc #0x80`. execve = 59 en la clase Unix (mismo esquema BSD).
- Mach traps (numeros negativos) para IPC/puertos; distintos de los syscalls BSD.

## Objetivos de escritura (sin hooks estilo glibc)
- __DATA_CONST (a veces __got): punteros de import; con arb write y sin RO estricto, GOT-like
  overwrite. dyld chained fixups complican el layout.
- vtables de C++/Obj-C (isa pointer del objeto -> clase -> metodos): type confusion Obj-C.
- Obj-C: el dispatch pasa por objc_msgSend(self, selector); controlar isa/selector redirige.

## Flujo tipico CTF/research
Reversing con Hopper/IDA/Ghidra, entender el sandbox (sandbox-exec / entitlements / seatbelt),
en arm64e asumir PAC (buscar leak+reuse de punteros firmados o un bug de logica que evite el
AUT), y para userland x86-64/arm64 sin PAC aplicar ROP/ret2libc contra el dyld_shared_cache.
Herramientas extra: `dyld_shared_cache_util` para extraer libs de la cache, LLDB para debug.
