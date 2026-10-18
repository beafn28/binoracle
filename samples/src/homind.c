/* House-of-Mind practice target (x86-64). HoM abuses glibc's per-heap ARENA SELECTION: free() finds
   the arena via `heap_for_ptr(p)` -- it masks the chunk pointer down to the containing heap and reads
   the `heap_info.ar_ptr` there -- then inserts the chunk into that arena's fastbins. By corrupting
   `ar_ptr` to a fake arena, the fastbin insertion `arena->fastbinsY[idx] = chunk` writes the chunk
   address to an attacker-chosen location -> hijack. A faithful glibc HoM also needs the NON_MAIN_ARENA
   bit and a huge heap boundary; this ships an in-binary allocator that reproduces the
   heap_for_ptr -> ar_ptr -> fastbin-insertion write. NX on, no PIE. AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

typedef struct chunk { size_t prev_size; size_t size; } chunk;
struct arena   { void *fastbinsY[32]; };
struct heapinfo { void *ar_ptr; };                 /* heap_for_ptr(p) lands here */

#define HEAPSZ   0x4000
#define HEAPMASK (~(uintptr_t)(HEAPSZ - 1))
char   heap[HEAPSZ] __attribute__((aligned(HEAPSZ)));
char  *bump = heap + 0x40;                          /* leave room for heap_info at heap+0 */

void win(void){ system("/bin/sh"); }
/* fake arena target: the fastbin-index write lands in `target`; we call through it. */
struct { char hdr[0x10]; void *target; } hom_slot __attribute__((aligned(16)));

static void *m_alloc(size_t n){
    chunk *c = (chunk*)bump; c->size = ((n + 15) & ~((size_t)15)) + 16;
    char *m = bump + 0x10; bump += 0x100; return m;
}

/* free(): select the arena from the heap's heap_info.ar_ptr, then insert into its fastbins. */
static void m_free(void *p){
    struct heapinfo *hi = (struct heapinfo*)((uintptr_t)p & HEAPMASK);   /* heap_for_ptr */
    struct arena *av = (struct arena*)hi->ar_ptr;                        /* forgeable arena */
    size_t sz = ((chunk*)((char*)p - 0x10))->size & ~((size_t)15);
    size_t idx = (sz - 0x20) >> 4;
    av->fastbinsY[idx] = (char*)p - 0x10;            /* THE WRITE: arena->fastbinsY[idx] = &chunk */
}

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    char *a = m_alloc(0x18);                          /* a_chunk at heap+0x40 (size 0x30 -> idx 1) */
    write(1, "ar: ", 4);  read(0, heap, 8);           /* corrupt heap_info.ar_ptr = fake arena */
    write(1, "win: ", 5); read(0, a, 8);              /* plant win into a's user data */
    m_free(a);                                        /* av->fastbinsY[1] = &a_chunk == &hom_slot.target */
    if (hom_slot.target){                              /* target == &a_chunk; a_chunk+0x10 == a */
        void (*f)(void) = *(void(**)(void))((char*)hom_slot.target + 0x10);
        f();                                           /* f == a[0] == win -> shell */
    }
    write(1, "done\n", 5);
    return 0;
}
