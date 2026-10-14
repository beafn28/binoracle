/* ret2csu -> execve chain (x86-64): gadget-poor binary that has `pop rdi`, `pop rax`, a `syscall`
   gadget and a "/bin/sh" string, but NO `pop rsi` / `pop rdx`. The two universal __libc_csu_init
   gadgets are chained to set rsi=0 and rdx=0 (from r14/r15) -- the registers with no pop -- with
   gadget2's forced `call [r12+rbx*8]` aimed at a benign `ret`; then pop rdi=&binsh, pop rax=59 and
   `syscall` perform execve("/bin/sh",0,0). Intentionally vulnerable, AUTHORIZED practice only. */
#include <unistd.h>

char binsh[] = "/bin/sh";
__attribute__((naked, used)) void ret_gadget(void){ __asm__ volatile("ret"); }  /* benign naked `ret` target */
void *retptr = ret_gadget;                            /* pointer in .data for the indirect call */

__attribute__((naked, used)) void gadget_block(void){     /* the two universal csu gadgets */
    __asm__ volatile(
        "pop %rbx\n pop %rbp\n pop %r12\n pop %r13\n pop %r14\n pop %r15\n ret\n"
        "mov %r15, %rdx\n mov %r14, %rsi\n mov %r13d, %edi\n call *(%r12,%rbx,8)\n ret\n");
}
__attribute__((naked, used)) void more_gadgets(void){     /* pop rax / syscall / pop rdi */
    __asm__ volatile("pop %rax\n ret\n" "syscall\n ret\n" "pop %rdi\n ret\n");
}

void vuln(void){ char buf[64]; read(0, buf, 512); }
int main(void){ write(1, "csuexec\n", 8); vuln(); return 0; }
