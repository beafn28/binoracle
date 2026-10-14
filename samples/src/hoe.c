/* House-of-einherjar practice target (x86-64). Einherjar's essence is BACKWARD CONSOLIDATION: when
   a chunk is freed with its PREV_INUSE bit clear, the allocator reads its prev_size and merges with
   the "previous" chunk at (chunk - prev_size); forging prev_size (and clearing PREV_INUSE via an
   overflow) makes that previous chunk a FAKE chunk at an attacker-chosen address, so the freed
   chunk lands there and the next malloc returns it -> arbitrary write -> hijack -> shell. Faithful
   glibc einherjar also needs tcache-bypass and size checks; this ships an in-binary allocator that
   reproduces the consolidation condition. NX on, no PIE. AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PREV_INUSE 1
typedef struct { size_t prev_size; size_t size; } hdr;

char heap[0x2000] __attribute__((aligned(16)));
char *bump = heap;
char *freelist = 0;                         /* one-slot free list */

void win(void){ system("/bin/sh"); }
void (*handler)(void) __attribute__((aligned(16))) = 0;   /* hijack target */

void *e_malloc(size_t n){
    if (freelist){ char *r = freelist; freelist = 0; return r + 0x10; }   /* serve the freed chunk */
    hdr *c = (hdr*)bump;
    size_t need = ((n + 15) & ~((size_t)15)) + 16;
    c->size = need | PREV_INUSE;
    char *mem = bump + 0x10;
    bump += need;
    return mem;
}

void e_free(void *p){
    hdr *c = (hdr*)((char*)p - 0x10);
    char *chunk = (char*)c;
    if (!(c->size & PREV_INUSE))             /* backward consolidation (einherjar) */
        chunk = (char*)c - c->prev_size;     /* prev_size forged -> fake chunk at arbitrary address */
    freelist = chunk;
}

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    char *a = e_malloc(0x18);                /* A */
    e_malloc(0x18);                          /* B (header right after A) */
    char *b = heap + 0x40;                   /* B's data (header at heap+0x30) */
    write(1, "of: ", 4); read(0, a, 0x100);  /* overflow A -> set B.prev_size, clear B PREV_INUSE */
    e_free(b);                               /* consolidate backward -> freelist = fake chunk */
    char *c = e_malloc(0x18);                /* returns fake+0x10 = &handler */
    write(1, "w: ", 3); read(0, c, 8);       /* handler = win */
    if (handler) handler();                  /* hijacked -> shell */
    write(1, "done\n", 5);
    return 0;
}
