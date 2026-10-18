/* SROP practice target, aarch64 (ARM64). Sigreturn-Oriented Programming on ARM64: a stack overflow
   overwrites the saved frame record (x29/x30) so the function epilogue `ret`s into a
   `mov x8, #139; svc #0` gadget (rt_sigreturn = 139), which restores a forged sigcontext from the
   stack; that forged frame sets x8=221 (execve), x0=&"/bin/sh", x1=x2=0 and pc=`svc #0`, so the
   kernel runs execve("/bin/sh", 0, 0). Static + no-PIE so the gadget/string addresses are fixed.

   NOTE: this builds and runs only on an aarch64 runtime (aarch64-linux-gnu-gcc + an ARM64 kernel or
   qemu-user). AUTHORIZED / CTF practice only. */
#include <unistd.h>

char binsh[] = "/bin/sh";

/* gadgets: `srop_tramp` triggers rt_sigreturn; `svc_gadget` is the execve syscall whose x8/x0/x1/x2
   come from the restored sigframe. Kept via references so the linker does not strip them. */
__asm__(
    ".text\n"
    ".global srop_tramp\n"
    ".type srop_tramp,%function\n"
    "srop_tramp:\n"
    "    mov x8, #139\n"       /* __NR_rt_sigreturn */
    "    svc #0\n"
    ".global svc_gadget\n"
    ".type svc_gadget,%function\n"
    "svc_gadget:\n"
    "    svc #0\n"
);
extern void srop_tramp(void);
extern void svc_gadget(void);
void *const _keep[] = { (void *)srop_tramp, (void *)svc_gadget, (void *)binsh };

void vuln(void){
    char buf[64];
    read(0, buf, 1024);        /* linear stack overflow -> overwrites the saved x29/x30 frame record */
}

int main(void){
    write(1, (const char *)_keep, 0);   /* reference so the gadgets/string are kept */
    write(1, "go\n", 3);
    vuln();
    return 0;
}
