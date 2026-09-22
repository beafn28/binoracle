/* format-string target: user input used as printf format, in a loop (typical challenge).
   Unbuffered. GOT of printf is overwritable to redirect to system. */
#include <stdio.h>
int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IONBF, 0);
    char buf[256];
    while (1) {
        printf("say: ");
        if (!fgets(buf, sizeof buf, stdin)) break;
        printf(buf);          /* format-string vulnerability */
    }
    return 0;
}
