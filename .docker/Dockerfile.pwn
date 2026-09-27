FROM python:3.11-slim
# multiarch (i386) para poder EJECUTAR binarios de 32 bits en el sandbox (ret2win32 y similares):
# sin esto, al reto de 32 bits le falta /lib/ld-linux.so.2 y no llega ni a arrancar
# ("Could not open '/lib/ld-linux.so.2'"). El kernel amd64 corre ELF i386 nativamente (modo
# compat IA32), solo hacen falta las librerias de 32 bits.
RUN dpkg --add-architecture i386 \
    && apt-get update && apt-get install -y --no-install-recommends \
        binutils gcc libc6-dev ruby strace ltrace libc6:i386 \
    && pip install --no-cache-dir pwntools \
    && gem install one_gadget --no-document \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /w
