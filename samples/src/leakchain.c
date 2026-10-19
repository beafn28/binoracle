/* Automatic infoleak chaining target: an out-of-bounds READ leaks a real, already-resolved
   libc pointer sitting next to a global array (so the leaked value is genuinely unknown until
   runtime -- it depends on the libc build, not something hardcoded), from which libc's base is
   computed; the SAME out-of-bounds primitive (write-what-where) then overwrites a function
   pointer with system()'s computed address, and calling it spawns a shell. One bug class
   (OOB read/write on `table`), two uses, chained into a single exploit informed by the leak --
   not two separate findings. No-PIE, dynamically linked (so libc is real and its own ASLR can
   stay ON: the leak is read fresh from THIS run, not assumed from a previous one). AUTHORIZED
   practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

long table[16];
void (*printf_leak)(void) = (void (*)(void))printf;   /* already-resolved libc pointer */
void (*callback)(const char *) = NULL;                 /* hijack target */
char shellarg[] = "/bin/sh";                            /* known static arg (no leak needed) */

int main() {
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IONBF, 0);
    long idx, val;
    int c;
    while (1) {
        printf("1) read idx  2) write idx,val  3) call callback  4) quit\n> ");
        if (scanf("%d", &c) != 1) return 0;
        if (c == 1) {
            printf("idx: ");
            if (scanf("%ld", &idx) != 1) return 0;
            printf("val: %#lx\n", table[idx]);          /* OOB read: write-what-where leak */
        } else if (c == 2) {
            printf("idx: ");
            if (scanf("%ld", &idx) != 1) return 0;
            printf("val: ");
            if (scanf("%ld", &val) != 1) return 0;
            table[idx] = val;                            /* OOB write: write-what-where */
        } else if (c == 3) {
            if (callback) callback(shellarg);
        } else {
            break;
        }
    }
    return 0;
}
