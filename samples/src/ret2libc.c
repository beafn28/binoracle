/* ret2libc target: overflow, NX on, no canary, no win, dynamically linked, unbuffered.
   Includes an explicit pop-rdi gadget (as many CTF challenges do). */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
void gadget(){ asm volatile("pop %rdi; ret"); }   /* pop rdi; ret gadget */
void vuln(){
    char buf[80];
    printf("data: "); fflush(stdout);
    read(0, buf, 256);
}
int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IONBF, 0);
    vuln();
    puts("done");
    return 0;
}
