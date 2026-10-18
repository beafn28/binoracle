/* ret2dlresolve target, 32-bit (x86 / i386): a dynamic, no-PIE, Partial-RELRO binary with a stack
   overflow and NO gift -- no win(), no system() ever called, and no leak primitive. The intended
   solution forges the dynamic linker's resolver structures (Elf32_Rel + Elf32_Sym + symbol string)
   so a call into the PLT stub resolves and invokes system("/bin/sh") WITHOUT any libc leak. Needs
   Partial RELRO (Full RELRO / BIND_NOW kills it). AUTHORIZED / CTF practice only.

   32-bit calls are cdecl (args on the stack), so we expose the gadget set a typical i386 dlresolve
   challenge has: single pops plus a 3-dword cleanup (`add esp, 0xc; ret`) so pwntools can call
   read(0, data) and clean up the cdecl frame before the resolver stub. */
#include <stdio.h>
#include <unistd.h>

__asm__(
    ".text\n"
    ".globl rop_gadgets32\n"
    ".type rop_gadgets32,@function\n"
    "rop_gadgets32:\n"
    "    pop %ebx\n    ret\n"
    "    pop %ecx\n    ret\n"
    "    pop %edx\n    ret\n"
    "    pop %ebx\n    pop %ecx\n    pop %edx\n    ret\n"   /* 3-arg cdecl cleanup */
    "    add $0xc, %esp\n    ret\n"                          /* alternate cdecl cleanup */
    "    leave\n    ret\n"
);
extern void rop_gadgets32(void);
void *const _keep_gadgets32 = (void *)rop_gadgets32;   /* keep the gadgets from being GC'd/stripped */

void vuln(){
    char buf[64];
    read(0, buf, 1024);           /* linear stack overflow, no bound -> controls return address */
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    write(1, (const char *)&_keep_gadgets32, 0);   /* reference so the linker keeps the gadgets */
    write(1, "go\n", 3);
    vuln();
    return 0;
}
