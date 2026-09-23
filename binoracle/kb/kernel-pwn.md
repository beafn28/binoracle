# Kernel pwn Linux (cheat sheet)

Explotacion de un modulo/driver del kernel (LKM) vulnerable. Objetivo tipico: escalar a root
en una VM de CTF. El "shell" se consigue elevando las credenciales del proceso actual y
volviendo a userland.

## Escalada de privilegios (el objetivo)
- `commit_creds(prepare_kernel_cred(0))` -> da al proceso actual las credenciales de init
  (root). prepare_kernel_cred(0) devuelve un cred de kernel; commit_creds lo aplica.
  (En kernels muy nuevos prepare_kernel_cred(0) puede requerir &init_cred; usa init_cred
  directo si 0 no funciona.)
- Guarda el estado de userland ANTES de entrar al kernel (para volver):
```
unsigned long user_cs, user_ss, user_rsp, user_rflags;
void save_state(){ asm("mov %%cs,%0; mov %%ss,%1; mov %%rsp,%2; pushf; pop %3"
  : "=r"(user_cs),"=r"(user_ss),"=r"(user_rsp),"=r"(user_rflags)); }
void shell(){ system("/bin/sh"); }   // se llama tras volver a ring3
```

## ret2usr (sin SMEP/SMAP)
Apunta el flujo del kernel a una funcion TUYA en userland que llame
commit_creds(prepare_kernel_cred(0)) y luego haga el retorno. Sencillo pero raro hoy.

## ROP en kernel (con SMEP)
Cadena tipica en la kstack (tras un overflow del driver):
```
pop rdi ; ret        ; 0            -> rdi=0
prepare_kernel_cred                 -> rax = cred
pop rdi ; ret        ; (mov rdi,rax gadget) -> rdi = cred
commit_creds
swapgs_restore_regs_and_return_to_usermode (+offset)  -> KPTI trampoline
0 ; 0                -> rax, rdi dummy que espera el trampoline
&shell ; user_cs ; user_rflags ; user_rsp ; user_ss   -> iretq frame
```
El trampoline (swapgs_restore_regs_and_return_to_usermode) hace el swapgs+iretq correcto con
KPTI. Salta unas instrucciones dentro (offset ~ +22/+27) para caer justo en el `mov rdi, rsp`
/ pops previos al iretq.

## Mitigaciones y bypass
- SMEP: paginas de userland no ejecutables desde kernel -> ret2usr no vale; usa ROP en kernel
  (o `mov cr4, X` para apagar el bit 20 de CR4, fragil).
- SMAP: el kernel no lee/escribe punteros de userland -> tu fake stack/datos en kernel-land.
- KPTI: al volver usa el trampoline swapgs_restore_regs_and_return_to_usermode, no iretq directo.
- KASLR: base del kernel aleatoria -> necesitas un leak (dmesg, /proc, un infoleak del driver)
  para resolver commit_creds/gadgets. kbase = leak - offset_conocido.

## modprobe_path (tecnica sin ROP, muy usada)
`modprobe_path` es una global (por defecto "/sbin/modprobe"). Con escritura arbitraria:
```
1. escribe "/tmp/x\0" en modprobe_path (kbase + off_modprobe)
2. crea /tmp/x (script: #!/bin/sh, chmod +s /bin/sh o cat /flag > /tmp/o) y /tmp/dummy con
   magic invalido (\xff\xff\xff\xff), ambos +x
3. ejecuta /tmp/dummy -> el kernel no reconoce el formato -> llama modprobe (=/tmp/x) como root
```
Evita todo el ROP/creds. Requiere solo un arb-write (o un UAF que lo consiga).

## Superficie tipica del driver
ioctl/read/write de /dev/xxx con: overflow de stack del kernel, UAF de slab (kmalloc-N),
copia sin validar tamano (copy_from_user), o double-fetch. Primitivas:
- stack overflow -> ROP en kstack.
- UAF slab -> reclamar con un objeto con function pointer y secuestrarlo: tty_struct->ops,
  msg_msg, pipe_buffer->ops, timerfd_ctx, seq_operations. Spray con las tecnicas de
  [[race-conditions]] y [[heap-grooming]].

## Herramientas y entorno
- extraer/empaquetar el initramfs (cpio + gzip) para meter tu exploit compilado estatico.
- qemu con `-s` -> gdb `target remote :1234`; carga vmlinux para simbolos, o resuelve por kbase.
- pwndbg/gef; `cat /proc/kallsyms` (si kptr_restrict lo permite) da direcciones.
- comprueba mitigaciones en el script run.sh de qemu (-cpu con smep/smap, nokaslr, kpti).
