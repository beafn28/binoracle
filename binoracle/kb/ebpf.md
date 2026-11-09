# eBPF exploitation (cheat sheet)

eBPF permite cargar programas en el kernel Linux (redes, tracing, seccomp) que un VERIFICADOR
valida antes de ejecutar (JIT). Los bugs suelen estar en el verificador (deja pasar algo que no
deberia) -> primitiva de R/W en kernel sin necesidad de un driver vulnerable.

## Como funciona
- Un programa eBPF (bytecode) se carga con bpf(BPF_PROG_LOAD). El verifier analiza TODOS los
  caminos: rangos de registros, accesos a memoria, bounds de los maps, que no haya bucles no
  acotados, que se salga con un valor valido.
- Si pasa, se JIT-compila a codigo nativo del kernel y se ejecuta con privilegios de kernel.
- maps: estructuras compartidas (arrays, hash) entre el programa eBPF y userland; el vector de
  comunicacion y a menudo el objetivo de la primitiva.

## Clases de bug (verifier)
- errores de tracking de rangos (min/max value de un registro): el verifier cree que un valor
  esta acotado cuando no lo esta -> acceso OOB a un map o a la pila del programa -> R/W kernel.
- confusion de tipos de puntero (scalar vs pointer): operar aritmetica que el verifier permite
  por error -> puntero controlado.
- ALU sign/bounds (CVE-2020-8835, CVE-2021-3490, etc.): el patron clasico es enganar al tracking
  de bounds tras operaciones (and/or/shift) para lograr un OOB de 1 o mas bytes que se amplia a
  arbitrary R/W via un map array.

## De OOB a root
1. bug del verifier -> OOB R/W relativo sobre un map/objeto de kernel.
2. leak de kernel (una direccion) para derrotar KASLR.
3. arbitrary R/W -> sobrescribir cred del proceso (commit_creds), o modprobe_path, o task_struct
   -> root. Igual que [[kernel-pwn]] una vez tienes la primitiva.

## Requisitos / mitigaciones
- CAP_BPF / CAP_SYS_ADMIN o `kernel.unprivileged_bpf_disabled=0` para cargar sin root
  (muchas distros lo desactivan -> reduce mucho la superficie).
- constant blinding del JIT, hardening del verifier, y bpf lockdown.
- retos CTF de eBPF suelen dar un kernel con unprivileged_bpf habilitado.

## Herramientas
- libbpf / bpftool para cargar/inspeccionar; `bpftool prog`, `bpftool map`.
- el codigo del verifier (kernel/bpf/verifier.c) es la referencia.
- gdb+qemu sobre vmlinux para depurar el kernel ([[kernel-pwn]]).
