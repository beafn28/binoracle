/* Unsafe-unlink practice target (x86-64). The classic unlink() attack: when a free merges with an
   adjacent free chunk, glibc unlinks the victim with `FD->bk = BK; BK->fd = FD`. glibc 2.3.4+ guards
   it with `FD->bk == P && BK->fd == P`; the classic bypass forges P->fd = &ptr-0x18 and
   P->bk = &ptr-0x10 where `ptr` is a global pointing at the chunk, which SATISFIES the check and
   makes the two writes set `ptr = &ptr-0x18`. From there, editing through `ptr` overwrites `ptr`
   itself to aim at a function pointer, then overwrites that -> hijack -> shell. A faithful glibc
   unlink also needs real consolidation plumbing; this ships an in-binary allocator that reproduces
   the unlink write + the 2.3.4+ consistency check. NX on, no PIE. AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct chunk { size_t prev_size; size_t size; struct chunk *fd; struct chunk *bk; } chunk;

char   heap[0x4000] __attribute__((aligned(16)));
char  *bump = heap;
void  *chunkptr;                                   /* the classic `ptr`: points at the victim chunk */

void win(void){ system("/bin/sh"); }
void (*handler)(void) __attribute__((aligned(16))) = 0;   /* hijack target */

static void *c_alloc(size_t n){
    chunk *c = (chunk*)bump; c->size = ((n + 15) & ~((size_t)15)) + 16;
    char *m = bump + 0x10; bump += 0x100; return m;
}

/* unlink with the glibc 2.3.4+ consistency check -- the classic bypass satisfies it. */
static void c_unlink(chunk *p){
    chunk *FD = p->fd, *BK = p->bk;
    if (FD->bk != p || BK->fd != p){ write(1, "corrupt\n", 8); _exit(1); }
    FD->bk = BK;                                   /* *(FD+0x18) = BK */
    BK->fd = FD;                                   /* *(BK+0x10) = FD */
}

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    char *a = c_alloc(0x80);                        /* victim; its chunk header is at heap+0x00 */
    chunkptr = (void*)((char*)a - 0x10);            /* ptr -> chunk (as glibc's user bookkeeping) */
    write(1, "unl: ", 5); read(0, a, 0x10);         /* overflow: set P->fd (a+0) and P->bk (a+8) */
    c_unlink((chunk*)((char*)a - 0x10));            /* unlink -> ptr = &chunkptr - 0x18 */
    write(1, "e1: ", 4); read(0, (char*)chunkptr + 0x18, 8);   /* chunkptr = &handler */
    write(1, "e2: ", 4); read(0, (char*)chunkptr, 8);          /* handler = win */
    if (handler) handler();                         /* hijacked -> shell */
    write(1, "done\n", 5);
    return 0;
}
