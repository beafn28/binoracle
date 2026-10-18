/* House-of-corrosion practice target (x86-64). HoC's core primitive is a controlled RELATIVE WRITE
   through the fastbins: by corrupting `global_max_fast` to a huge value, a free() of a large chunk is
   treated as a fastbin free, and the allocator indexes `fastbinsY[(size-0x20)>>4]` with NO bound --
   so an attacker-chosen `size` makes that index alias an arbitrary slot, and the insertion writes the
   freed chunk's address there. In real glibc this is chained into libc (global_max_fast lives in
   main_arena, the write lands on _IO_list_all / stdout / __free_hook-era targets); this ships an
   in-binary allocator that reproduces the unbounded-fastbin-index write so the primitive runs end to
   end and is observable. NX on, no PIE. AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct { size_t prev_size; size_t size; void *fd; } chunk;

char   heap[0x4000] __attribute__((aligned(16)));
char  *bump = heap;
void  *fastbinsY[0x4000];                 /* the fastbin array (like main_arena.fastbinsY) */
size_t global_max_fast = 0x80;            /* normal: only chunks <= 0x80 are fastbin-eligible */

void win(void){ system("/bin/sh"); }
/* HoC relative-write target: the fastbin index write lands in `target` (a pointer to the freed
   chunk); we then call the function pointer stored in that chunk's user data. */
struct { char hdr[0x10]; void *target; } hook_slot __attribute__((aligned(16)));

static void *c_alloc(size_t n){
    chunk *c = (chunk*)bump; c->size = ((n + 15) & ~((size_t)15)) + 16;
    char *m = bump + 0x10; bump += 0x100; return m;
}

/* fastbin free: when size <= global_max_fast, insert into fastbinsY[(size-0x20)>>4] -- UNBOUNDED,
   exactly the corrosion condition. The insertion writes &chunk into fastbinsY[idx]. */
static void c_free(void *p){
    chunk *c = (chunk*)((char*)p - 0x10);
    size_t size = c->size & ~((size_t)15);
    if (size <= global_max_fast){
        size_t idx = (size - 0x20) >> 4;      /* no upper-bound check -> arbitrary index */
        c->fd = fastbinsY[idx];
        fastbinsY[idx] = c;                   /* THE WRITE: fastbinsY[idx] = &chunk */
    }
}

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    char *a = c_alloc(0x18);                   /* victim; a's chunk header is at heap+0x00 */
    write(1, "gmf: ", 5); read(0, &global_max_fast, 8);   /* corrupt global_max_fast -> huge */
    write(1, "sz: ", 4);  read(0, a - 8, 8);               /* set a's chunk->size = S (chunk+8) */
    c_free(a);                                 /* fastbinsY[(S-0x20)>>4] = &a_chunk; S picks &hook_slot.target */
    write(1, "win: ", 5); read(0, a, 8);       /* plant win into a's user data (a == &a_chunk+0x10) */
    if (hook_slot.target){                      /* target == &a_chunk via the write; a_chunk+0x10 == a */
        void (*f)(void) = *(void(**)(void))((char*)hook_slot.target + 0x10);
        f();                                    /* f == a[0] == win -> shell */
    }
    write(1, "done\n", 5);
    return 0;
}
