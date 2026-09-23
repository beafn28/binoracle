# Anti-debug, anti-reversing y packers (cheat sheet)

Tecnicas que un binario usa para detectar/estorbar el analisis, y como sortearlas al hacer
reversing. (Lado defensivo/analista, para retos y malware autorizado.)

## Deteccion de debugger (Linux)
- ptrace(PTRACE_TRACEME): un proceso solo puede ser traceado una vez; si el binario se
  auto-tracea, un debugger que intente attach falla. Bypass: LD_PRELOAD de un ptrace() que
  devuelva 0, o parchear la llamada, o `catch syscall ptrace` en gdb y falsear el retorno.
- /proc/self/status -> campo TracerPid != 0 indica que hay un debugger. Bypass: parchear la
  comprobacion o montar un /proc falso.
- comprobar argv[0], variables de entorno de gdb (LINES/COLUMNS), o ficheros /proc/*/exe.

## Deteccion de debugger (Windows)
- IsDebuggerPresent / CheckRemoteDebuggerPresent / PEB->BeingDebugged (offset 0x2 del PEB).
- NtGlobalFlag (heap flags), NtQueryInformationProcess(ProcessDebugPort).
- Bypass: parchear el flag del PEB, plugins como ScyllaHide / TitanHide.

## Deteccion por breakpoints / integridad
- INT3 (0xCC): buscar bytes 0xCC en el propio codigo delata software breakpoints. Bypass: usa
  hardware breakpoints (DR0-DR3) que no modifican el codigo.
- checksums del propio .text: el binario se auto-hashea para detectar parches. Bypass: parchea
  y recalcula el checksum, o hookea la funcion de verificacion.

## Timing / evasion
- RDTSC / clock: mide ciclos entre dos puntos; un debugger lo ralentiza. Bypass: parchear
  RDTSC para devolver deltas pequenos, o no pausar entre esos puntos.
- deteccion de VM/sandbox (CPUID hypervisor bit, MAC de VMware, numero de CPUs) para no
  ejecutar la logica real.

## Ofuscacion de flujo
- opaque predicates, control-flow flattening, junk/dead code, saltos a mitad de instruccion
  (misaligned) para confundir al desensamblador. Herramientas: usar el modo grafico de IDA/
  Ghidra, o desofuscadores (angr/miasm para simplificar).

## Packers
- UPX (facil): `upx -d packed.bin` desempaqueta. Si el header esta manipulado, dumpea en
  runtime tras el unpack (OEP) con x64dbg + Scylla / gdb.
- Themida / VMProtect / Enigma (VM-based): virtualizan el codigo; muy dificil, se analiza el
  interprete de la VM o se hace unpack dinamico volcando memoria en el OEP.
- Estrategia general de unpack: ejecutar hasta el "tail jump" al OEP, volcar la memoria,
  reconstruir la IAT.

## Bypass practico (ejemplos)
gdb - neutralizar ptrace(PTRACE_TRACEME) para que siempre "tenga exito":
```
catch syscall ptrace
commands
  set $rax = 0
  continue
end
```
LD_PRELOAD - suplantar ptrace desde una .so:
```
long ptrace(int r, int p, void*a, void*d){ return 0; }   // gcc -shared -fPIC -o p.so p.c
# LD_PRELOAD=./p.so ./chall
```
frida - anular una comprobacion (p.ej. IsDebuggerPresent / una funcion de check):
```
Interceptor.attach(Module.getExportByName(null,'ptrace'), { onLeave(r){ r.replace(0); }});
```
parche estatico - NOP a la llamada de anti-debug o invertir el salto condicional (jz<->jnz)
con radare2: `r2 -w chall` ; `s sym.check` ; `wa nop` o `wx 9090...`.

## Herramientas
gdb+gef/pwndbg, x64dbg+ScyllaHide/TitanHide, IDA/Ghidra, frida (hook dinamico), ltrace/strace,
qiling/unicorn (emulacion), angr/miasm (desofuscacion simbolica), Detect It Easy (identificar
packer/protector).
