# Tutorial guiado: de cero a exploit verificado sobre el corpus de `samples/`

ROADMAP.md, "Cross-cutting quality" -- "A docs site with a guided tutorial over the `samples/`
corpus". Esta es esa guía: un recorrido progresivo, binario por binario, usando el corpus de
práctica intencionalmente vulnerable en `samples/src/` (AUTORIZADO, solo para práctica local/CTF).
Cada bloque de salida de abajo es **real** -- copiado de una ejecución real de binoracle contra
el binario compilado correspondiente, no inventado. Si tu salida difiere ligeramente (direcciones,
offsets de libc), es normal: depende de tu compilador/libc exactos.

Antes de empezar, compila el corpus:

```bash
samples/build.sh
```

Esto compila cada `.c` de `samples/src/` a `samples/bin/` (usa Docker `gcc:13` si está, o el gcc
del host en Linux). Son ~40 binarios, cada uno aislando una técnica distinta. Ver `docs/USAGE.md`
para instalar binoracle si aún no lo hiciste.

---

## 1. El primer paso: `triage` (hechos fundamentados, sin ejecutar nada)

Antes de explotar nada, mira qué sabe binoracle del binario con solo leerlo -- ELF, mitigaciones,
símbolos. Esto no ejecuta el binario, es análisis estático puro (radare2 + pyelftools).

```bash
binoracle triage samples/bin/ret2win
```

Salida real (recortada):

```
## Triage (grounded facts)

### File / ELF header
source: `elf_meta(pyelftools): header`

class: 64-bit
machine: x64
type: ET_EXEC
entrypoint: 0x401090
stripped: False

### Exploit mitigations (checksec)
source: `elf_meta(pyelftools): checksec`

PIE:          False
NX:           True
RELRO:        Partial
Stack canary: False
Stripped:     False
```

Cada hecho lleva su `source:` -- la herramienta exacta que lo produjo. Esa es la regla de oro de
binoracle: nunca un hallazgo sin una herramienta real detrás.

---

## 2. El clásico: `ret2win` (sin canary, sin PIE)

`samples/src/ret2win.c` es el ejemplo más simple: un `gets()` sin límite sobre un buffer, y una
función `win()` que llama a `system("/bin/sh")`. Sin canary (visto arriba: `Stack canary: False`),
así que un overflow lineal puede sobreescribir la dirección de retorno directamente con `win()`.

```bash
binoracle autopwn samples/bin/ret2win
```

Salida real:

```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: system, gets, printf
[verify] hallazgos verificados por angr: 3
[combo] ret2win: construyendo y verificando en sandbox...
[combo] ret2win -> FUNCIONA (verificado)

> EXPLOIT VERIFICADO: se ejecuto un exploit (ret2win) en sandbox y se consiguio el objetivo.

| tecnica  | resultado | detalle                    |
|----------|-----------|-----------------------------|
| ret2win  | FUNCIONA  | offset=72 win=0x401176      |
```

"Verificado" no significa "angr dice que es alcanzable" -- significa que binoracle **construyó
el payload de verdad** (72 bytes de relleno + la dirección de `win()`), lo **ejecutó contra el
binario real** en el sandbox (`make pwn-image`, o nativamente con `unshare`/`setarch -R`), y
**confirmó la señal de éxito** (aquí, que `win()` realmente corrió). El offset (72) y la
dirección (`0x401176`) salieron de ese binario real, no de una tabla.

---

## 3. Cuando SÍ hay canary: fuga + bypass (`canleak`)

`samples/src/canleak.c` tiene un canary de pila activo, pero también una fuga genuina: un primer
`read()` pisa el byte menos significativo (siempre `\x00`) del canary, y el `printf("hi %s\n",
buf)` que sigue imprime los 7 bytes restantes del canary al seguir leyendo más allá de ese byte
nulo. Con el canary completo recuperado, un segundo `read()` ya puede sobreescribirlo con su
valor real y seguir hasta `win()`.

```bash
binoracle autopwn samples/bin/canleak
```

Salida real (recortada a lo relevante):

```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=true
[combo] ret2win: canary activo -> el overflow lineal se omite, se usa el bypass por fuga (combo canary)
...
[combo] canary: fuga del canary + overflow a win (sandbox)...
[combo] canary -> SHELL VERIFICADA

> EXPLOIT VERIFICADO: se ejecuto un exploit (canary-bypass) en sandbox y se consiguio el objetivo.

- **por que la tecnica elegida**: canary ACTIVO + win() + buffer impreso -> fuga del canary,
  reescritura y overflow a win()
```

Fíjate que binoracle **no intentó** el `ret2win` lineal aquí -- lo detectó como bloqueado por el
canary (`canary=true` en el recon) y pasó directamente a la técnica correcta. Esa es la lógica de
árbol de decisión de `workflows/autopwn.py`: elige la técnica según las mitigaciones REALES del
binario, no prueba todo a ciegas.

Prueba también `samples/bin/canary` (el mismo binario SIN la fuga): verás que `autopwn` lo
intenta pero no lo consigue verificar -- un "no" honesto en vez de fingir un éxito, porque sin
una fuga real, el canary de 8 bytes no es adivinable.

---

## 4. Sin función `win()`: format-string hasta una shell

`samples/src/fmtstring.c` no tiene ninguna función "regalo" -- solo un `printf(buf)` directo
sobre la entrada del usuario, en un bucle. Eso es una vulnerabilidad de format-string clásica:
`%n` puede ESCRIBIR en memoria arbitraria.

```bash
binoracle autopwn samples/bin/fmtstring
```

Salida real:

```
[recon] arch=x86 64-bit  NX=true  PIE=false  canary=false
[recon] sinks: printf
[combo] ret2win: no hay funcion gift -> se omite
...
[combo] format-string: intentando GOT overwrite -> shell (sandbox)...
[combo] format-string -> SHELL VERIFICADA

| tecnica        | resultado | detalle                                                         |
|-----------------|-----------|-------------------------------------------------------------------|
| format-string   | FUNCIONA  | VERIFIED offset=6 system=0x155555258750 printf_got=0x404000       |
```

La técnica: localiza la entrada de `printf` en la GOT (Partial RELRO -- visible en el `triage` del
paso 1 si lo corrieras contra este binario -- deja la GOT escribible), calcula el offset de pila
donde el formato puede alcanzar su propio argumento (`offset=6`, encontrado por fuerza bruta
real contra el binario), y usa `%n` para sobreescribir `printf@GOT` con la dirección de `system`.
La próxima vez que el programa llama a "printf" en su propio código... en realidad llama a
`system`, con la entrada del usuario (`"/bin/sh"`) como argumento.

---

## 5. Heap: cuando la respuesta honesta es "no" (y por qué eso es lo correcto)

```bash
binoracle heap samples/bin/notes_heap
```

Salida real:

```
## Heap dinamico (confirmacion por ejecucion)

- corrupcion confirmada: **no**
- no se disparo corrupcion con las entradas de prueba
```

Esto NO es un fallo de binoracle -- es el comportamiento correcto. `notes_heap.c` es un reto
"notas" clásico, dirigido por menú (crear/editar/liberar/mostrar), con una vulnerabilidad real de
use-after-free. Pero el probador genérico de `binoracle heap` manda una entrada de prueba FIJA, y
esa entrada no reproduce la secuencia de menú exacta que dispara el UAF de este binario en
particular. Antes que fingir una corrupción que no observó de verdad (lo que violaría la regla de
oro del proyecto: nunca un hallazgo sin una herramienta real detrás), binoracle lo dice tal cual:
**no se disparó corrupción con estas entradas** -- ni más ni menos.

Las técnicas de heap completas (house-of-spirit, house-of-force, tcache-dup, fastbin-dup,
unsafe-unlink, y más) sí están implementadas y verificadas de extremo a extremo contra fixtures
dedicados por técnica -- mira `samples/src/hos.c`, `hof.c`, `fastbindup.c`, `unsafeunlink.c`, etc.,
y corre `binoracle autopwn` contra sus binarios compilados (`samples/bin/hos`, `samples/bin/hof`...)
para ver cada una verificada igual que los pasos 2-4 de arriba.

---

## Siguientes pasos

- `docs/USAGE.md` -- instalación completa, servidor MCP, UI web.
- `docs/ENGINE.md` -- cómo funciona el motor por debajo (oráculos, sandbox, grounding).
- `ROADMAP.md` -- qué hay construido y qué sigue, con la auditoría honesta de cada item.
- `binoracle --help` / `binoracle <comando> --help` -- cada comando de este tutorial (y muchos
  más: `regress`, `funcid`, `ci-gate`, `runs`, `rawshellcode`, `rust`...) tiene su propio `--help`.
