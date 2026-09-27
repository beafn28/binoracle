/* ret2win: unbounded gets overflow + a gift function. No canary, no PIE. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void win(){ printf("[+] win reached\n"); system("/bin/sh"); }
int main(){
    char buf[64];
    printf("name? "); fflush(stdout);
    gets(buf);
    if (strcmp(buf, "sup3rs3cr3t") == 0) win();  /* angr-solvable constraint path */
    printf("bye %s\n", buf);
    return 0;
}
