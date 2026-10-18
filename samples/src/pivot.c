/* Stack-pivot practice target (x86-64): the overflow in vuln() is SHORT -- only enough to set the
   saved RBP and the saved return address -- so a full ROP chain does not fit on the stack. But a
   large payload is first staged into a fixed .bss buffer (notes[]). The intended path is a stack
   migration: overwrite saved RBP = &notes and saved RIP = a `leave; ret` gadget, so execution
   pivots RSP into notes[] and runs the ROP chain staged there. NX on, no PIE (fixed addresses).
   win() spawns a shell. Intentionally vulnerable, for AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char notes[512];                 /* fixed .bss staging buffer for the migrated chain */

void win(){ system("/bin/sh"); }

void vuln(){
    char buf[16];
    write(1, "stage: ", 7);
    read(0, notes, 512);         /* stage the ROP chain at a known fixed address */
    write(1, "of: ", 4);
    read(0, buf, 40);            /* SHORT overflow: buf[16] + saved rbp(8) + ret(8) + slack */
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    vuln();
    return 0;
}
