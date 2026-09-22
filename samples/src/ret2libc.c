/* ret2libc target: overflow, NX on, canary off, no win function. */
#include <stdio.h>
#include <string.h>
void vuln(){
    char buf[80];
    printf("data: "); fflush(stdout);
    read(0, buf, 256);      /* overflow, no bounds */
}
int main(){ vuln(); puts("done"); return 0; }
