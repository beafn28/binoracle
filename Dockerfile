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
        git ca-certificates curl file binutils make python3-dev \
        gcc gcc-multilib libc6-dev libc6-dev-i386 libc6:i386 \
        ruby strace ltrace \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# radare2: NO esta en los repos de Debian (retirado), asi que se instala desde el .deb OFICIAL de
# su repo de releases (amd64, coincide con la imagen linux/amd64). Se intenta apt primero por si
# una base futura vuelve a traerlo; si el .deb tampoco se puede, se degrada honestamente (el
# chain-analyzer/arsenal avisan "r2 no disponible" en vez de romperse).
ARG R2_VERSION=5.9.8
RUN apt-get update \
    && (apt-get install -y --no-install-recommends radare2 \
        || (curl -fsSL -o /tmp/r2.deb \
              "https://github.com/radareorg/radare2/releases/download/${R2_VERSION}/radare2_${R2_VERSION}_amd64.deb" \
            && apt-get install -y --no-install-recommends /tmp/r2.deb \
            && rm -f /tmp/r2.deb) \
        || echo 'WARN: radare2 no disponible; binoracle degrada sin r2') \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && (radare2 -v || true)

# Android a nivel clase/metodo/recursos: apktool (AndroidManifest + smali + recursos) y jadx
# (DEX -> pseudo-Java). Arrastran un JRE headless. BEST-EFFORT: si no estan en el repo el build no
# muere (inspect_apk estatico sigue funcionando; apk-manifest/apk-decompile avisan si faltan).
RUN apt-get update \
    && (apt-get install -y --no-install-recommends default-jre-headless apktool jadx \
        || echo 'WARN: apktool/jadx no disponibles; inspect_apk estatico sigue OK') \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Extras BEST-EFFORT que mejoran cobertura sin inflar demasiado:
# - gdb: debug dinamico (oraculo dynamic_dbg, confirmar crashes en vivo).
# - patchelf: cambiar interprete/RPATH del ELF (usar la libc de un reto).
# - binwalk: carve de firmware/blobs empotrados (inspect firmware).
# Si alguno no esta, el build NO muere; esa capacidad simplemente se marca no disponible.
RUN apt-get update \
    && (apt-get install -y --no-install-recommends gdb patchelf binwalk \
        || echo 'WARN: gdb/patchelf/binwalk no disponibles; se degradan esas capacidades') \
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
