# Kernel Linux: mitigaciones y sus bypasses (cheat sheet)

Como en userland, lo primero al mirar un LPE de kernel es saber QUE mitigaciones hay activas
(config del kernel, `/proc/config.gz`, version) para elegir la ruta. Aqui va el mapa
mitigacion -> que para -> como se saltea, mas los objetos y objetivos tipicos. Taxonomia
sintetizada de la coleccion autoritativa xairy/linux-kernel-exploitation. Complementa
[[kernel-pwn]], [[race-conditions]] y [[heap-grooming]].

## Mitigaciones y como se saltan
| Mitigacion | Que impide | Bypass tipico |
|------------|-----------|---------------|
| **SMEP** | ejecutar paginas de USER en modo kernel (no ret2usr directo) | ROP/JOP en kernel: pivota la pila a memoria controlada y encadena gadgets; o **ret2dir** (physmap alias de tu pagina user) / **ret2bpf** / **ret2page** |
| **SMAP** | que el kernel LEA/escriba punteros de user | todo por ROP (no toques memoria user directa); coloca datos via objetos de kernel (msg_msg, pipe_buffer) en vez de leerlos de user |
| **KPTI** | Meltdown; separa page tables user/kernel | volver a user necesita el **trampolin KPTI** (swapgs_restore_regs_and_return_to_usermode) o **signal return / iretq** bien montado; no rompe el LPE, solo el retorno |
| **KASLR** | direcciones fijas de kernel | leak: **EntryBleed** (prefetch contra la entry text con KPTI), **prefetch side-channel**, info-leak de un objeto, o un puntero de kernel filtrado (dmesg, /proc) |
| **FG-KASLR** | randomiza por-funcion | necesitas leak de la funcion concreta (no basta la base); apoya en leaks de punteros a esa funcion |
| **kCFI / FineIBT** | llamadas indirectas fuera de type-set | usa gadgets con la MISMA firma de tipo, o data-only / **page-oriented programming**; JOP restringido |
| **CET (IBT/SHSTK)** | ROP/JOP (shadow stack + endbr) | data-only attacks; corromper estructuras en vez de RIP; buscar caminos sin retorno controlado |
| **STACKLEAK** | reusar restos de pila de kernel | limita infoleaks de pila; usa otras fuentes de leak (heap, objetos) |
| **heap hardening** (SLUB freelist hardening, FREELIST_RANDOM, RANDOM_KMALLOC_CACHES) | envenenar la freelist / layout predecible | **cross-cache attack** (reclama via otro slab), spray masivo, elastic objects; groom con userfaultfd/FUSE |
| **MTE / PAN** (ARM) | UAF/OOB (tags) / acceso user desde kernel | rebase de tags si hay leak; PAN se salta con ROP como SMAP |

## Objetos "elasticos" para reclamar (spray)
Tras un UAF/OOB de un objeto de slab, reclamas el hueco con un objeto que controles del MISMO
tamano (kmalloc-N). Los clasicos:
- **msg_msg** (`msgsnd`): tamano flexible, contenido controlado; el rey del spray de datos.
- **pipe_buffer**: tiene un puntero a `ops` (funciones) -> secuestro de flujo; base de Dirty Pipe.
- **sk_buff** (paquetes de red), **setxattr** (+userfaultfd para congelar el tiempo de vida).
- **timerfd_ctx / tty_struct / seq_operations**: traen punteros a funcion -> RIP control.
Ver [[heap-grooming]] (seccion kernel) y [[race-conditions]] (userfaultfd/FUSE para ganar la carrera).

## Objetivos finales (que pisar para rootear)
- **commit_creds(prepare_kernel_cred(0))**: la cadena clasica -> creds de root al proceso actual.
- **core_pattern**: escribe `|/tmp/x` -> se ejecuta como root al primer core dump.
- **modprobe_path**: apunta a tu script -> se ejecuta como root al cargar un modulo/binario magic.
- **cred struct** del proceso: pon uid/gid = 0 directamente (data-only, esquiva CFI).

## Tecnicas modernas con nombre (data-only y n-day)
- **Dirty Pipe** (CVE-2022-0847): flag `PIPE_BUF_FLAG_CAN_MERGE` sin resetear -> escribir en
  ficheros de solo-lectura (incl. /etc/passwd, binarios SUID). Sin corromper punteros.
- **DirtyCred**: intercambia una `struct cred`/`file` no privilegiada por una privilegiada
  (swap de objetos del mismo cache) -> esquiva CFI/CET porque no toca RIP.
- **Dirty Pagetable**: corrompe una page table entry -> R/W sobre memoria fisica arbitraria.
- **cross-cache**: liberas todo un slab para que la pagina vuelva al buddy y la reclama otro
  cache -> UAF entre caches distintos (rompe el aislamiento de kmalloc-N).
- **page-oriented programming**: cadena de "gadgets" a nivel de pagina; util frente a CFI.
- **io_uring / eBPF JIT spray / FUSE**: superficies y primitivas de spray/ejecucion adicionales.

## Flujo tipico de un LPE moderno
1. Bug -> primitiva (UAF/OOB/double-free/race). Identifica el cache (kmalloc-N) del objeto.
2. **Leak** para romper KASLR (EntryBleed/prefetch o infoleak del propio bug).
3. **Groom + spray**: reclama el objeto con uno elastico (msg_msg/pipe_buffer); usa
   userfaultfd/FUSE para el timing si es race ([[race-conditions]]).
4. Segun mitigaciones: con CFI/CET ve a **data-only** (DirtyCred, cred struct, page table);
   sin ellas, ROP en kernel (pivot + commit_creds), respetando el retorno KPTI.
5. Verifica en una VM (qemu + gdb `-s`) antes de darlo por bueno; el kernel-pwn se depura en VM.

Fuente de la taxonomia: xairy/linux-kernel-exploitation (github.com/xairy/linux-kernel-exploitation),
coleccion de referencia de seguridad y explotacion de kernel. Aqui sintetizada como mapa de
decision; para PoCs por CVE, ver esa coleccion y [[kernel-pwn]].
