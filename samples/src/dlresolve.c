/* ret2dlresolve target: a dynamic, no-PIE, Partial-RELRO binary with a stack overflow and NO
   gift -- no win(), no system() ever called, and no leak primitive. The intended solution is to
   forge the dynamic linker's resolver structures (Elf64_Rela + Elf64_Sym + symbol string) so a
   call into the PLT stub resolves and invokes system("/bin/sh") WITHOUT any libc leak. Needs
   Partial RELRO (Full RELRO / BIND_NOW kills it). AUTHORIZED / CTF practice only.

   Modern gcc no longer emits __libc_csu_init, so we provide the handful of ROP gadgets the
   technique needs (pop rdi / pop rsi / pop rdx) via a small asm block -- exactly the gadget set a
   typical CTF dlresolve challenge exposes. */
#include <stdio.h>
#include <unistd.h>

__asm__(
    ".text\n"
    ".globl rop_gadgets\n"
    ".type rop_gadgets,@function\n"
    "rop_gadgets:\n"
    "    pop %rdi\n    ret\n"
    "    pop %rsi\n    ret\n"
    "    pop %rdx\n    ret\n"
);
extern void rop_gadgets(void);
void *const _keep_gadgets = (void *)rop_gadgets;   /* keep the gadgets from being GC'd/stripped */

void vuln(){
    char buf[64];
    read(0, buf, 1024);           /* linear stack overflow, no bound -> controls return address */
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    write(1, (const char *)&_keep_gadgets, 0);     /* reference so the linker keeps the gadgets */
    write(1, "go\n", 3);
    vuln();
    return 0;
}
