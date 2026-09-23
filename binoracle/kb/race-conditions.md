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

## Deteccion
- estatico: mismo puntero de usuario leido dos veces; check y uso separados por una operacion
  que cede CPU (lock, copy, syscall).
- dinamico: fuzzing con hilos; sanitizers (KCSAN para data races en kernel).
