/* House-of-spirit practice target (x86-64, real glibc tcache). The program plants one attacker
   value (a fake chunk size), frees an attacker-chosen pointer, then malloc() hands that pointer
   back. By crafting a fake chunk whose data overlaps a function pointer and freeing it into the
   tcache, the next malloc returns a pointer AT the function pointer, so a write hijacks it -> shell.
   NX on, no PIE (fixed addresses). Unlike house-of-force, this is NOT mitigated on modern glibc
   (the tcache free fast-path returns before the fastbin next-size checks). AUTHORIZED practice. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void){ system("/bin/sh"); }
void (*handler)(void) __attribute__((aligned(16))) = NULL;   /* hijack target (16-aligned) */

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    unsigned long addr, val, freep;
    write(1, "addr: ", 6); read(0, &addr, 8);     /* where to plant the fake chunk size */
    write(1, "val: ",  5); read(0, &val, 8);       /* the fake size (e.g. 0x41) */
    *(unsigned long *)addr = val;                  /* plant it */
    write(1, "free: ", 6); read(0, &freep, 8);     /* pointer to free (the fake chunk's data) */
    free((void *)freep);                           /* house-of-spirit: fake chunk enters tcache */
    void *p = malloc(0x30);                        /* tcache[0x40] -> returns the fake chunk */
    write(1, "data: ", 6); read(0, p, 8);          /* arbitrary write at the fake chunk */
    if (handler) handler();                        /* hijacked -> win -> shell */
    write(1, "done\n", 5);
    return 0;
}
