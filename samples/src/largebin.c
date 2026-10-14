/* Largebin-attack practice target (x86-64). The largebin attack's signature is the insertion
   write: when a large chunk is inserted into a largebin whose resident chunk has a corrupted
   bk_nextsize, glibc executes `victim->bk_nextsize->fd_nextsize = victim`, i.e. it writes the
   address of the freshly inserted chunk to an attacker-chosen location (bk_nextsize + 0x20). That
   turns a free into an arbitrary POINTER write; from the chunk it now points at (whose contents the
   attacker controls) you pivot to a shell. A faithful glibc largebin attack on modern libc (>=2.30)
   must also pass the added `bck->bk_nextsize->fd_nextsize == old_fwd` sanity check and is usually
   chained into _IO_list_all / a later malloc target; this ships an in-binary allocator that
   reproduces the characteristic insertion write so the primitive runs end to end and is observable.
   NX on, no PIE. AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* chunk header mirroring glibc's largebin layout: the nextsize fields live at +0x20 / +0x28. */
typedef struct {
    size_t prev_size;      /* +0x00 */
    size_t size;           /* +0x08 */
    void  *fd;             /* +0x10 */
    void  *bk;             /* +0x18 */
    void  *fd_nextsize;    /* +0x20 */
    void  *bk_nextsize;    /* +0x28 */
} hdr;

char heap[0x4000] __attribute__((aligned(16)));
char *bump = heap;
hdr  *lb = 0;                                  /* single-entry largebin head */

void win(void){ system("/bin/sh"); }
void *slot __attribute__((aligned(16))) = 0;   /* overwritten to point at a controlled chunk */

/* bump allocator with a fixed 0x400 stride so chunk addresses are deterministic */
void *lb_alloc(size_t n){
    hdr *c = (hdr*)bump;
    c->size = ((n + 15) & ~((size_t)15)) + 16;
    char *mem = bump + 0x10;
    bump += 0x400;
    return mem;
}

/* insert a large chunk; reproduces glibc's `victim->bk_nextsize->fd_nextsize = victim` write */
void lb_insert(void *p){
    hdr *v = (hdr*)((char*)p - 0x10);
    if (!lb){ lb = v; v->fd_nextsize = v; v->bk_nextsize = v; return; }
    v->bk_nextsize = lb->bk_nextsize;                     /* inherits head's (corrupted) bk_nextsize */
    *(void**)((char*)v->bk_nextsize + 0x20) = v;          /* THE WRITE: *(bk_nextsize+0x20) = &victim */
}

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    char *a = lb_alloc(0x400);                 /* A -> largebin head (chunk at heap+0x000) */
    lb_insert(a);
    char *b = lb_alloc(0x380);                 /* B -> smaller large chunk (chunk at heap+0x400) */
    write(1, "lb: ", 4); read(0, a, 0x100);    /* overflow A: set lb->bk_nextsize = &slot - 0x20 */
    lb_insert(b);                              /* insertion write -> slot = &B_header */
    write(1, "w: ", 3); read(0, b, 8);         /* plant win into B's user data */
    if (slot){                                 /* slot -> B_header; B user data (+0x10) holds win */
        void (*f)(void) = *(void(**)(void))((char*)slot + 0x10);
        f();                                   /* hijacked -> shell */
    }
    write(1, "done\n", 5);
    return 0;
}
