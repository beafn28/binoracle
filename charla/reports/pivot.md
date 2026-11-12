## Auto-explotacion de `samples/bin/pivot`

> EXPLOIT VERIFICADO: se ejecuto un exploit (pivot) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary ON**
- funcion gift `win()`: **si**
- sinks peligrosos: read
- **por que la tecnica elegida**: overflow demasiado corto para una cadena completa (solo alcanza saved rbp/rip) -> `leave; ret` migra RSP a un buffer .bss ya escalonado con la cadena real

- hallazgos verificados: 0

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2csu | posible | ret2csu: no verificado (native) (sin gadgets csu / puntero de funcion / timing) |
| pivot | FUNCIONA | VERIFIED mode=leave off=16 slides=1 leave_ret=0x4018b5 win=0x401835 buf=0x4adb40 |
| heap-shell | no | no aplicable: no se detecto un menu new/free/edit/show en el binario |
| uaf-funcptr | posible | no verificado (native): menu no reconocido, tamano de chunk distinto, o UAF no explotable asi |
| canary-bypass | posible | no verificado (native): sin fuga del canary utilizable o sin win |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=true
[recon] sinks: read
[recon] gadget 'pop rdi': si
[verify] hallazgos verificados por angr: 0
[combo] ret2win: canary activo -> el overflow lineal se omite, se usa el bypass por fuga (combo canary)
[combo] ret2csu: gadgets universales de __libc_csu_init (sandbox)...
[combo] ret2csu -> no verificado
[combo] stack pivot: overflow corto -> migracion RSP a buffer .bss (sandbox)...
[combo] stack pivot -> SHELL VERIFICADA
[combo] heap-shell: tcache poison -> free@GOT=win (sandbox)...
[combo] heap-shell -> no verificado
[combo] uaf-funcptr: UAF reuso de chunk -> funcptr=win (sandbox)...
[combo] uaf-funcptr -> no verificado
[combo] canary: fuga del canary + overflow a win (sandbox)...
[combo] canary -> no verificado
[fin] combinaciones probadas: ret2csu, pivot, heap-shell, uaf-funcptr, canary-bypass
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).