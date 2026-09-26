# Tecnicas de CTF (pwn/reversing) destiladas (cheat sheet)

Patrones recurrentes en writeups de CTF de binarios, para reconocerlos rapido y saber la via de
ataque. Sintesis (no copia). Complementa [[reversing-workflow]], [[methodology]], [[anti-debug]],
[[rop]], [[syscalls-seccomp]] y [[reference_ctf_quantum_patterns]].

## Resolucion de checkers de flag por SMT/simbolico (z3 / angr)
Cuando el binario valida la flag con una funcion de comprobacion (comparaciones, aritmetica, XOR,
sistemas de ecuaciones sobre los bytes de entrada):
- Modela la comprobacion como restricciones y resuelvela con z3 (Solver, BitVec de 8 bits por byte)
  o deja que angr encuentre la entrada que llega al estado "correcto" (ver el oraculo de
  alcanzabilidad de binoracle: input concreto que dispara el sink/objetivo).
- Claves: identificar la funcion de check (xrefs a "Correct"/"Wrong"/puts de exito), extraer las
  constantes/tablas, y expresar el objetivo (memcmp == 0, o la rama de exito).
- angr: `explore(find=addr_exito, avoid=addr_fallo)` con stdin/argv simbolico acotado; para bucles
  largos, hooka la funcion o usa `unicorn` para acelerar.

## Nanomites / anti-debug por ptrace (padre traza hijo)
Ofuscacion clasica: el proceso se relanza como HIJO y un PADRE lo depura (ptrace PTRACE_TRACEME en
el hijo / PTRACE_ATTACH en el padre). Una variable de entorno (p.ej. `YAY`) distingue los dos roles.
- El codigo real esta CIFRADO o sustituido por trampas (INT3/0xCC = "nanomites"): en cada trap el
  padre lee el contexto (PTRACE_GETREGS), descifra/parcha la instruccion real y continua. Sin el
  padre, el binario no funciona (o va por un camino falso).
- Reversing: no basta con el disasm estatico; hay que ver que hace el PADRE en el handler de
  SIGTRAP (la tabla de instrucciones reales suele estar en una seccion de datos). Vale emular
  (unicorn/qiling) o instrumentar. Deteccion de anti-debug: PTRACE_TRACEME devuelve -1 si ya hay un
  tracer, /proc/self/status TracerPid, timing con rdtsc. Ver [[anti-debug]].

## Codigo auto-descifrado / auto-modificable
El binario descifra en runtime la seccion .text (o una funcion) antes de ejecutarla (packer casero,
XOR con clave derivada). Estatico no basta:
- Pon un breakpoint tras el bucle de descifrado y vuelca la memoria ya descifrada (gdb dump / core),
  o emula hasta ese punto. Reconoce el patron: bucle que escribe sobre paginas +W+X y luego salta.
- En Windows: mismo patron con VirtualProtect/VirtualAlloc; en ELF, mprotect a RWX.

## Pwn: primitivas frecuentes en estos retos
- SROP (sigreturn-oriented programming): con un `syscall; ret` y control de RAX=15, montas un
  sigcontext falso en la pila para fijar TODOS los registros a la vez (util con pocos gadgets). Ver
  [[syscall-table]] y [[advanced-rop]].
- Bypass de seccomp: dumpea el filtro (seccomp-tools) y busca una syscall permitida que de RCE u
  fuga (openat+sendfile en vez de execve; o open/read/write del flag). Ver [[syscalls-seccomp]].
- Fuga via `environ`: en libc, `environ` guarda un puntero a la pila; con un leak de libc, leer
  `environ` da una direccion de pila (para ROP en pila o localizar el buffer). Ver [[ret2libc]].
- Shellcode restringido: si el filtro limita bytes (solo imprimibles/alfanumericos), usa un encoder
  o un stub que construya el shellcode real; ver [[shellcoding]].

## Reglas de uso en binoracle (grounded)
Estas tecnicas son CONOCIMIENTO para orientar el analisis; los hallazgos siguen saliendo de los
oraculos. Un checker resuelto por angr se marca `verified` solo si la alcanzabilidad/entrada esta
PROBADA por el solver; el resto queda como hipotesis a confirmar.
