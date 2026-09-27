/* Out-of-bounds write (write-what-where): an unchecked index into a global array lets the attacker
   write a chosen value at a chosen offset (e.g. over a GOT entry or a saved return).
   NX on, no PIE. AUTHORIZED practice only. */
#include <stdio.h>
#include <unistd.h>

long table[16];
void win(){ system("/bin/sh"); }

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    long idx, val;
    printf("idx: "); fflush(stdout);
    if (scanf("%ld", &idx) != 1) return 0;      /* no bounds check on idx */
    printf("val: "); fflush(stdout);
    if (scanf("%ld", &val) != 1) return 0;
    table[idx] = val;                           /* arbitrary write-what-where */
    puts("ok");
    return 0;
}
