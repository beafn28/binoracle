/* Tcache-stashing-unlink practice target (x86-64). When _int_malloc serves a request from a
   SMALLBIN and the matching tcache bin still has room, glibc "stashes" the remaining smallbin
   chunks into the tcache. The stash loop unlinks each chunk and runs `bck->fd = bin` and
   `tcache_put(tc_victim)`. By corrupting the `bk` of a smallbin chunk to a FAKE chunk, that fake
   chunk is stashed into the tcache, so a later allocation of that size returns an attacker-chosen
   address -> overwrite a function pointer -> shell. Modern glibc (>=2.31) hardened the loop with
   `if (bck->fd != tc_victim) malloc_printerr("smallbin double linked list corrupted")`, which is
   why a naive stash crashes; this reproduction enforces that very check and SATISFIES it (the
   invariants a real attacker arranges through the heap layout are set up here, and the stash is
   triggered via calloc, which bypasses the tcache like glibc's). The attacker-controlled action is
   the single `bk` overflow. NX on, no PIE; the sandbox runs with ASLR off so addresses are
   deterministic. AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct chunk { size_t prev_size; size_t size; struct chunk *fd; struct chunk *bk; } chunk;

#define SZ 0x90
#define TC_MAX 7

char  heap[0x10000] __attribute__((aligned(16)));
char *bump = heap;
chunk bin;                              /* smallbin sentinel: bin.fd=first, bin.bk=last */
int   bin_init = 0;
void *tcache[32];
int   tcount = 0;

void win(void){ system("/bin/sh"); }

/* The fake chunk overlaps this object; its "fd" field (chunk+0x10) is the callable slot, so a
   malloc that returns the fake chunk hands back &hobj.fn. `bk` (chunk+0x18) is hobj.bk. */
struct fakeobj { char hdr[0x10]; void (*fn)(void); void *bk; } hobj __attribute__((aligned(16)));
char  zbuf[0x40] __attribute__((aligned(16)));      /* a "previous" chunk so the loop terminates cleanly */

static void *s_alloc(void){
    chunk *c = (chunk*)bump; c->size = SZ | 1; char *m = bump + 0x10; bump += 0x100; return m;
}
static void sb_push(void *p){           /* insert at the front (fd side); last(bin)=bin.bk */
    chunk *c = (chunk*)((char*)p - 0x10);
    if (!bin_init){ bin.fd = bin.bk = &bin; bin_init = 1; }
    c->fd = bin.fd; c->bk = &bin; bin.fd->bk = c; bin.fd = c;
}

/* malloc-from-smallbin + stash, reproducing glibc's loop and its >=2.31 consistency check.
   `use_tcache`: a real malloc() checks the tcache first; calloc() does NOT -> pass 0 to force the
   smallbin path (and thus the stash) even while the tcache has entries. */
static void *serve(int use_tcache){
    if (use_tcache && tcount){ return tcache[--tcount]; }
    chunk *victim = bin.bk;                           /* last(bin) */
    if (victim == &bin){ return s_alloc(); }          /* empty -> fresh */
    chunk *bck = victim->bk;
    bin.bk = bck; bck->fd = &bin;                     /* unlink the served chunk */
    while (tcount < TC_MAX && bin.bk != &bin){        /* STASH remaining into tcache */
        chunk *tc_victim = bin.bk;
        chunk *b2 = tc_victim->bk;
        if (b2->fd != tc_victim){                     /* glibc >=2.31 hardening */
            write(1, "corrupt\n", 8); _exit(1);
        }
        bin.bk = b2; b2->fd = &bin;                   /* unlink write: bck->fd = bin */
        tcache[tcount++] = (char*)tc_victim + 0x10;   /* tcache_put */
    }
    return (char*)victim + 0x10;
}

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    /* Pre-fill the tcache to TC_MAX-2 so the stash has room for exactly two puts (Ctc, then fake). */
    for (int i = 0; i < TC_MAX - 2; i++) tcache[tcount++] = s_alloc();

    void *cserve = s_alloc();                          /* served (discarded) */
    void *ctc    = s_alloc();                          /* becomes the first tc_victim */
    sb_push(cserve); sb_push(ctc);                     /* smallbin: last=cserve, then ctc */

    /* The fake chunk lives at &hobj. Arrange the invariants a real heap-grooming attacker would:
       the stash's consistency check needs fake->fd == tc_victim(ctc), and the loop needs a valid
       "previous" chunk (zbuf) so fake can be stashed before the count fills. */
    chunk *fake = (chunk*)&hobj;
    chunk *ctc_hdr = (chunk*)((char*)ctc - 0x10);
    chunk *zc = (chunk*)zbuf;
    fake->fd = ctc_hdr;                                /* == tc_victim -> passes the >=2.31 check */
    fake->bk = zc;                                     /* previous chunk for the final iteration */
    zc->fd   = fake;                                   /* zc->fd == fake -> passes its check too */

    /* ATTACKER: overflow ctc's user data to corrupt ctc->bk = &fake (fd at user+0, bk at user+8). */
    write(1, "stash: ", 7);
    read(0, ctc, 0x10);                                /* 8 bytes fd (don't care) + 8 bytes bk=&hobj */

    serve(0);                                          /* calloc path: serve smallbin + STASH fake */
    void *p = serve(1);                                /* malloc: pops fake -> returns &hobj.fn */

    write(1, "win: ", 5);
    read(0, p, 8);                                     /* plant win into hobj.fn */
    if (hobj.fn) hobj.fn();                            /* hijacked -> shell */
    write(1, "done\n", 5);
    return 0;
}
