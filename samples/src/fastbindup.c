/* Fastbin-dup practice target (x86-64, classic pre-safe-linking). The classic fastbin double-free:
   old glibc only rejected a free when the chunk equals the CURRENT fastbin top, so freeing A, B, A
   slips the second free of A past the check and leaves A linked to itself. Allocating then lets you
   poison A->fd toward a fake chunk, and a later allocation returns that attacker-chosen address ->
   overwrite a function pointer -> shell. The fastbin serve also checks `chunksize(victim)==nb`, so
   the fake chunk needs a valid size qword (the classic "0x7f near a hook" trick); here the target
   object carries one. Reproduces the pre-2.32 fastbin (no safe-linking). NX on, no PIE.
   AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct chunk { size_t prev_size; size_t size; struct chunk *fd; } chunk;

#define SZ 0x30                                  /* fastbin chunk size (0x20 request + header) */
char   heap[0x4000] __attribute__((aligned(16)));
char  *bump = heap;
chunk *fasttop = 0;                               /* single fastbin head (LIFO) */

void win(void){ system("/bin/sh"); }
/* fake chunk the dup aims at: `size` must equal SZ to pass the serve check; `fn` is the user slot. */
struct fakeobj { size_t prev_size; size_t size; void (*fn)(void); } hslot __attribute__((aligned(16)));

static void *f_alloc(void){
    if (fasttop){
        chunk *v = fasttop;
        if ((v->size & ~0xf) != SZ){ write(1, "badsize\n", 8); _exit(1); }   /* chunksize==nb */
        fasttop = v->fd;
        return (char*)v + 0x10;
    }
    chunk *c = (chunk*)bump; c->size = SZ; char *m = bump + 0x10; bump += 0x100; return m;
}

static void f_free(void *p){
    chunk *c = (chunk*)((char*)p - 0x10);
    if (fasttop == c){ write(1, "double free (fasttop)\n", 22); _exit(1); }   /* classic weak check */
    c->fd = fasttop; fasttop = c;
}

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    hslot.size = SZ;                              /* fake chunk carries a valid size for the serve check */
    char *a = f_alloc();                          /* chunk A (header at heap+0x00) */
    char *b = f_alloc();                          /* chunk B */
    f_free(a); f_free(b); f_free(a);              /* classic dup: A,B,A (A != top at the 2nd free of A) */
    f_alloc();                                    /* pops A */
    write(1, "fd: ", 4); read(0, a, 8);           /* poison A->fd = &hslot (fake chunk header) */
    f_alloc();                                    /* pops B */
    f_alloc();                                    /* pops A again */
    char *t = f_alloc();                          /* pops the poisoned chunk -> returns &hslot.fn */
    write(1, "win: ", 5); read(0, t, 8);          /* hslot.fn = win */
    if (hslot.fn) hslot.fn();                      /* hijacked -> shell */
    write(1, "done\n", 5);
    return 0;
}
