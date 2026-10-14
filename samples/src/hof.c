/* House-of-force practice target (x86-64). Real glibc house-of-force is MITIGATED since glibc 2.29
   (the top-chunk size is sanity-checked), so this ships an in-binary allocator that faithfully
   reproduces the pre-2.29 top-chunk carve: malloc() serves from the top chunk only if the request
   fits in top->size, advances top by the request, and stores the remainder as the new top->size.
   The heap overflow lets you overwrite top->size with a huge value (the house-of-force primitive),
   so an attacker-chosen huge request moves `top` to an arbitrary address; the next allocation then
   returns a pointer there, giving an arbitrary write used to hijack a function pointer -> shell.
   NX on, no PIE (fixed addresses). Intentionally vulnerable, AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HEAPSZ 0x2000
typedef struct { size_t prev; size_t size; } hdr;

char heap[HEAPSZ] __attribute__((aligned(16)));   /* fixed arena (no-PIE) */
char *topp = heap;                                 /* current top-chunk header */

void win(void){ system("/bin/sh"); }
void benign(void){ write(1, "benign\n", 7); }
void (*handler)(void) = benign;                    /* hijack target (fixed address) */

/* pre-2.29 top-chunk carve: NO independent bound beyond top->size (which HoF inflates) */
void *hof_malloc(size_t n){
    hdr *t = (hdr*)topp;
    size_t need = ((n + 15) & ~((size_t)15)) + 16;
    if (need > t->size) { write(2, "nomem\n", 6); _exit(1); }   /* the check HoF bypasses */
    void *mem = (char*)t + 16;
    char *newtop = (char*)t + need;
    ((hdr*)newtop)->size = t->size - need;
    topp = newtop;
    return mem;
}

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    ((hdr*)topp)->size = HEAPSZ;             /* whole arena is the initial top chunk */
    char *a = hof_malloc(24);                /* chunk A */
    write(1, "of: ", 4);
    read(0, a, 0x100);                       /* overflow A -> overwrite top->size (HoF primitive) */
    size_t n;
    write(1, "sz: ", 4);
    read(0, &n, 8);                          /* attacker-chosen huge request -> move top to target */
    hof_malloc(n);
    char *b = hof_malloc(8);                 /* returns a pointer AT the target */
    write(1, "w: ", 3);
    read(0, b, 8);                           /* arbitrary write -> handler = win */
    handler();                               /* hijacked -> shell */
    write(1, "done\n", 5);
    return 0;
}
