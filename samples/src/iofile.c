/* IO_FILE / FSOP practice target (x86-64). File-Stream-Oriented Programming hijacks a `_IO_FILE`'s
   VTABLE: glibc reaches a stream operation (e.g. on exit, _IO_flush_all walks _IO_list_all and calls
   `fp->vtable->__overflow(fp, EOF)`, the pointer at vtable+0x18). By overwriting `fp->vtable` to a
   fake vtable whose __overflow slot points at attacker code, the flush calls it -> control flow. This
   ships a minimal reproduction: an `_IO_FILE`-shaped struct with the vtable at +0xd8 and a flush that
   calls `vtable[3]` (offset 0x18 = __overflow). Overwriting the vtable to a fake table whose slot 3 is
   win() pops a shell. NX on, no PIE. AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* _IO_FILE-shaped: the vtable pointer sits at offset 0xd8 (as in glibc's _IO_FILE_plus). */
struct iofile { char data[0xd8]; void *vtable; };

struct iofile fp;
void *fake_vtable[8];                       /* attacker-controlled fake vtable */

void win(void){ system("/bin/sh"); }

/* reproduces _IO_flush's call: fp->vtable->__overflow(fp)  (slot 3 == offset 0x18). */
static void io_flush(struct iofile *f){
    void (**vt)(struct iofile *) = (void (**)(struct iofile *))f->vtable;
    vt[3](f);                               /* __overflow */
}

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    write(1, "vt: ", 4);  read(0, &fp, sizeof(fp));            /* overflow sets fp.vtable */
    write(1, "ov: ", 4);  read(0, fake_vtable, sizeof(fake_vtable));  /* sets fake_vtable[3] */
    io_flush(&fp);                                             /* vtable hijack -> shell */
    write(1, "done\n", 5);
    return 0;
}
