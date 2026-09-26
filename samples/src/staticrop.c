/* Static, no-win ROP target: statically linked so libc is inside the binary; there is no win() and
   no system() call site, so the path is a ROP chain to execve("/bin/sh") (or SROP). Rich gadget set
   from the static libc. NX on, no PIE, no canary. AUTHORIZED practice only. */
#include <unistd.h>

void vuln(){
    char buf[80];
    read(0, buf, 400);             /* overflow: 400 into 80 */
}

int main(){
    const char *m = "go\n";
    write(1, m, 3);
    vuln();
    write(1, "ok\n", 3);
    return 0;
}
