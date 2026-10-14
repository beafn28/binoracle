# binoracle — imagen de aplicacion (Linux x86-64).
#
# Trae dentro TODO lo necesario para la parte estatica Y para la verificacion de exploits por
# ejecucion: Python, radare2, pwntools, one_gadget, gcc (+ multilib i386 para los retos de 32-bit),
# y el corpus de practica ya compilado. En un Mac M1 / Windows, Docker corre esta imagen como
# linux/amd64 (emulacion) para que los binarios x86-64/x86-32 se ejecuten de verdad.
#
# Construir + levantar:  docker compose up --build   (ver docker-compose.yml)
# Solo la UI web:        http://127.0.0.1:8080
#
# NOTA: fijamos -slim-bookworm a proposito. El tag "python:3.11-slim" a secas migro a Debian
# trixie, donde radare2 ya NO tiene candidato de instalacion y tumbaba el apt-get. Bookworm si
# trae radare2. Aun asi, radare2 se instala como best-effort (ver abajo) para no bloquear el build.
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Herramientas del sistema:
# - i386 multiarch + libc6:i386 + gcc-multilib: EJECUTAR y COMPILAR binarios de 32 bits (ret2win32,
#   srop32, fmtgot32, dlresolve32...). El kernel amd64 corre ELF i386 nativo (modo compat IA32).
# - radare2: desensamblado/analisis (chain-analyzer, nativequery, arsenal).
# - ruby: para instalar one_gadget (magic gadgets de la libc).
# - strace/ltrace/file/binutils: utilidades de apoyo.
# Paquetes CRITICOS (si fallan, el build debe fallar):
RUN dpkg --add-architecture i386 \
    && apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates file binutils make python3-dev \
        gcc gcc-multilib libc6-dev libc6-dev-i386 libc6:i386 \
        ruby strace ltrace \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# radare2: BEST-EFFORT. En bookworm existe; si en una base futura desaparece del repo, el build
# NO debe morir por ello (chain-analyzer/nativequery/arsenal degradan sin r2). Por eso va aparte
# con "|| true". Si quieres r2 garantizado aqui y no esta en el repo, instalalo luego con el
# script oficial dentro del contenedor:  r2pm -U  o  bash <(curl -fsSL https://.../r2_install.sh)
RUN apt-get update \
    && (apt-get install -y --no-install-recommends radare2 \
        || echo 'WARN: radare2 no disponible en este repo; binoracle degrada sin r2') \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Oraculos de analisis + pwntools (angr se omite a proposito: es enorme y carga perezosamente;
# instalalo con `pip install angr` dentro del contenedor si lo necesitas para reachability simbolica).
RUN pip install pyelftools pefile olefile r2pipe capstone pwntools cvss \
    && gem install one_gadget --no-document || true

WORKDIR /app
COPY . /app

# Instala el CLI `binoracle` (editable) y compila el corpus de practica DENTRO del contenedor
# (fallback a gcc del host Linux; los targets ARM/mingw se omiten si falta su toolchain).
RUN pip install -e . \
    && bash samples/build.sh || true

EXPOSE 8080

# La UI web, accesible desde el host en http://127.0.0.1:8080
CMD ["binoracle", "serve", "--host", "0.0.0.0", "--port", "8080", "--no-open"]
