## Auto-explotacion de `samples/bin/fmt_got`

> EXPLOIT VERIFICADO: se ejecuto un exploit (ret2win, format-string) en sandbox y se consiguio el objetivo.

### Contexto del binario (defensas detectadas)

- arquitectura: **x86 64-bit**
- mitigaciones: **NX ON · PIE off · canary off**
- funcion gift `win()`: **si**
- sinks peligrosos: system, read, printf
- **por que la tecnica elegida**: win() presente sin canary -> retorno directo a win() (direccion fija)

- hallazgos verificados: 2

### Combinaciones probadas

| tecnica | resultado | detalle |
|---|---|---|
| ret2win | FUNCIONA | offset=136 win=0x401176 |
| format-string | FUNCIONA | VERIFIED offset=6 system=0x155555258750 printf_got=0x404010 |

### Traza
```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: system, read, printf
[recon] gadget 'pop rdi': no
[verify] hallazgos verificados por angr: 2
[combo] ret2win: construyendo y verificando en sandbox...
[combo] ret2win -> FUNCIONA (verificado)
[combo] format-string: intentando GOT overwrite -> shell (sandbox)...
[combo] format-string -> SHELL VERIFICADA
[fin] combinaciones probadas: ret2win, format-string
```

Todo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).