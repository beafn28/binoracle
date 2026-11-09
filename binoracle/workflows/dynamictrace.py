"""Analisis dinamico real: ejecuta el binario en el sandbox e intercepta su comportamiento en
runtime (conexiones de red, ficheros que toca, comandos que lanza) por interposicion de simbolos
de libc con LD_PRELOAD.

Por que LD_PRELOAD y no strace: en un Mac ARM el contenedor linux/amd64 corre bajo emulacion
(qemu-user), donde ptrace/strace no funcionan (solo emiten "runs in x32/64 bit mode"). La
interposicion de simbolos, en cambio, es solo el enlazador dinamico y funciona bajo emulacion.
Se compila un pequeno .so que envuelve connect/bind/listen/execve/system/popen/open/fopen/chmod/
unlink, registra la llamada real y delega en la funcion original.

Limitacion honesta: solo ve binarios enlazados DINAMICAMENTE (usan la libc interpuesta). Un
binario estatico salta la libc y no se intercepta (se indica en la nota).

Se corre con --network none (las conexiones salientes FALLAN, pero se registra el DESTINO real
que el binario pretendia), memoria/pids limitados y timeout corto. Solo para binarios autorizados;
el binario debe ser linux/amd64.

Grounded/verified: cada evento es una llamada real observada en ejecucion (no una inferencia).

NOTA DE REGRESION (no reintroducir): este modulo vivio originalmente en `dynamic.py`. Un commit
posterior reutilizo ese MISMO nombre de fichero para el modulo adb/frida/browser no relacionado
(ver `dynamic.py`), sobrescribiendolo por completo -- incluido un arreglo de seguridad/bug ya hecho
aqui (sandbox en tmpdir aislado con nombre fijo, `--cap-drop ALL`, y el parser sin truncar comandos/
rutas con espacios) -- y dejando `audit.py`/`web.py` importando funciones que ya no existian,
silenciado por un `except Exception: pass` hasta correr la suite de tests entera. Se restaura aqui,
bajo SU PROPIO nombre, para que ambos modulos convivan sin volver a chocar.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List

from ..store.session import Finding

_IMG = "binoracle-pwn"

# shim de interposicion: registra la llamada (prefijo __BO__) y delega en la real via RTLD_NEXT.
_HOOK_C = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
static void _addr(const char* fn, const struct sockaddr* a){
  if(!a) return;
  if(a->sa_family==AF_INET){ const struct sockaddr_in* s=(const void*)a; char ip[64];
    inet_ntop(AF_INET,&s->sin_addr,ip,sizeof ip);
    fprintf(stderr,"__BO__ %s ip=%s port=%d\n",fn,ip,ntohs(s->sin_port)); }
  else if(a->sa_family==AF_INET6){ const struct sockaddr_in6* s=(const void*)a; char ip[128];
    inet_ntop(AF_INET6,&s->sin6_addr,ip,sizeof ip);
    fprintf(stderr,"__BO__ %s ip=%s port=%d\n",fn,ip,ntohs(s->sin6_port)); }
}
int connect(int fd,const struct sockaddr* a,socklen_t l){ _addr("connect",a);
  int(*r)(int,const struct sockaddr*,socklen_t)=dlsym(RTLD_NEXT,"connect"); return r(fd,a,l); }
int bind(int fd,const struct sockaddr* a,socklen_t l){ _addr("bind",a);
  int(*r)(int,const struct sockaddr*,socklen_t)=dlsym(RTLD_NEXT,"bind"); return r(fd,a,l); }
int listen(int fd,int b){ fprintf(stderr,"__BO__ listen\n");
  int(*r)(int,int)=dlsym(RTLD_NEXT,"listen"); return r(fd,b); }
extern char** environ;
int execve(const char* p,char* const av[],char* const ev[]){
  fprintf(stderr,"__BO__ execve arg=%s path=%s\n",(av&&av[0])?av[0]:"",p?p:"");
  int(*r)(const char*,char* const*,char* const*)=dlsym(RTLD_NEXT,"execve"); return r(p,av,ev); }
int execv(const char* p,char* const av[]){
  fprintf(stderr,"__BO__ execve arg=%s path=%s\n",(av&&av[0])?av[0]:"",p?p:"");
  int(*r)(const char*,char* const*)=dlsym(RTLD_NEXT,"execv"); return r(p,av); }
int execvp(const char* p,char* const av[]){
  fprintf(stderr,"__BO__ execve arg=%s path=%s\n",(av&&av[0])?av[0]:"",p?p:"");
  int(*r)(const char*,char* const*)=dlsym(RTLD_NEXT,"execvp"); return r(p,av); }
int execvpe(const char* p,char* const av[],char* const ev[]){
  fprintf(stderr,"__BO__ execve arg=%s path=%s\n",(av&&av[0])?av[0]:"",p?p:"");
  int(*r)(const char*,char* const*,char* const*)=dlsym(RTLD_NEXT,"execvpe"); return r(p,av,ev); }
/* execl/execlp: variadicas -> se reconstruye argv y se delega en execve/execvp real */
int execl(const char* p,const char* a0,...){
  fprintf(stderr,"__BO__ execve arg=%s path=%s\n",a0?a0:"",p?p:"");
  va_list ap,ap2; va_start(ap,a0); va_copy(ap2,ap);
  int n=1; while(va_arg(ap2,char*)) n++; va_end(ap2);
  char* argv[64]; int i=0; argv[0]=(char*)a0;
  for(i=1;i<n && i<63;i++) argv[i]=va_arg(ap,char*); argv[i]=0; va_end(ap);
  int(*r)(const char*,char* const*,char* const*)=dlsym(RTLD_NEXT,"execve"); return r(p,argv,environ); }
int execlp(const char* p,const char* a0,...){
  fprintf(stderr,"__BO__ execve arg=%s path=%s\n",a0?a0:"",p?p:"");
  va_list ap,ap2; va_start(ap,a0); va_copy(ap2,ap);
  int n=1; while(va_arg(ap2,char*)) n++; va_end(ap2);
  char* argv[64]; int i=0; argv[0]=(char*)a0;
  for(i=1;i<n && i<63;i++) argv[i]=va_arg(ap,char*); argv[i]=0; va_end(ap);
  int(*r)(const char*,char* const*)=dlsym(RTLD_NEXT,"execvp"); return r(p,argv); }
int system(const char* c){ fprintf(stderr,"__BO__ system cmd=%s\n",c?c:"");
  int(*r)(const char*)=dlsym(RTLD_NEXT,"system"); return r(c); }
FILE* popen(const char* c,const char* m){ fprintf(stderr,"__BO__ popen cmd=%s\n",c?c:"");
  FILE*(*r)(const char*,const char*)=dlsym(RTLD_NEXT,"popen"); return r(c,m); }
int open(const char* p,int fl,...){ mode_t m=0; if(fl&O_CREAT){va_list ap;va_start(ap,fl);m=va_arg(ap,int);va_end(ap);}
  fprintf(stderr,"__BO__ open path=%s\n",p?p:"");
  int(*r)(const char*,int,...)=dlsym(RTLD_NEXT,"open"); return r(p,fl,m); }
int open64(const char* p,int fl,...){ mode_t m=0; if(fl&O_CREAT){va_list ap;va_start(ap,fl);m=va_arg(ap,int);va_end(ap);}
  fprintf(stderr,"__BO__ open path=%s\n",p?p:"");
  int(*r)(const char*,int,...)=dlsym(RTLD_NEXT,"open64"); return r(p,fl,m); }
FILE* fopen(const char* p,const char* m){ fprintf(stderr,"__BO__ open path=%s\n",p?p:"");
  FILE*(*r)(const char*,const char*)=dlsym(RTLD_NEXT,"fopen"); return r(p,m); }
int chmod(const char* p,mode_t m){ fprintf(stderr,"__BO__ chmod mode=%o path=%s\n",m,p?p:"");
  int(*r)(const char*,mode_t)=dlsym(RTLD_NEXT,"chmod"); return r(p,m); }
int unlink(const char* p){ fprintf(stderr,"__BO__ unlink path=%s\n",p?p:"");
  int(*r)(const char*)=dlsym(RTLD_NEXT,"unlink"); return r(p); }
'''

# ficheros sensibles cuyo acceso en runtime merece un hallazgo
_SENSITIVE = ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/", ".ssh", "id_rsa",
              "/proc/self/mem", "/etc/crontab", "/etc/cron")


@dataclass
class DynTrace:
    ran: bool = False
    note: str = ""
    connects: List[dict] = field(default_factory=list)   # {ip, port}
    binds: List[dict] = field(default_factory=list)       # {ip, port}
    execs: List[str] = field(default_factory=list)         # comando/ruta ejecutada
    files: List[str] = field(default_factory=list)         # ficheros abiertos
    chmods: List[dict] = field(default_factory=list)       # {path, mode}
    unlinks: List[str] = field(default_factory=list)
    raw: str = ""

    @property
    def ok(self) -> bool:
        return self.ran


# nombre FIJO del binario dentro del sandbox: elimina inyeccion de shell por el nombre del fichero
# original y desacopla el analisis del nombre real del usuario.
_SANDBOX_NAME = "target.bin"


def dynamic_trace(binary: str, stdin: bytes = b"", timeout: int = 8) -> DynTrace:
    """Corre el binario con el shim LD_PRELOAD en el sandbox y devuelve el comportamiento observado.

    El binario se COPIA a un directorio temporal aislado que es lo unico que se monta en el
    contenedor (nunca el directorio del usuario): asi un binario malicioso no puede escribir ni
    alterar ficheros del host. Se ejecuta con nombre fijo (sin inyeccion por el nombre)."""
    import tempfile
    docker = shutil.which("docker")
    if not docker:
        return DynTrace(note="docker no disponible")
    if subprocess.run([docker, "image", "inspect", _IMG], capture_output=True).returncode != 0:
        return DynTrace(note=f"imagen {_IMG} no construida")
    work = tempfile.mkdtemp(prefix="bo_dyn_")
    try:
        import shutil as _sh
        _sh.copy2(binary, os.path.join(work, _SANDBOX_NAME))
        with open(os.path.join(work, ".dyn_stdin"), "wb") as f:
            f.write(stdin)
        with open(os.path.join(work, ".dyn_hook.c"), "w") as f:
            f.write(_HOOK_C)
        # compila el shim, ejecuta el binario con LD_PRELOAD y captura stderr (donde va el log).
        # timeout(1) mata el binario; el log del shim va a fd 2, la salida del binario se descarta.
        # nombre FIJO (_SANDBOX_NAME) -> no hay interpolacion de datos no confiables en el shell.
        inner = (f"gcc -shared -fPIC -o .dyn_hook.so .dyn_hook.c -ldl 2>/tmp/cc || echo __BO_CCFAIL__; "
                 f"chmod +x ./{_SANDBOX_NAME}; "
                 f"LD_PRELOAD=$PWD/.dyn_hook.so timeout {max(1, timeout - 2)} ./{_SANDBOX_NAME} "
                 f"< .dyn_stdin >/dev/null 2>/tmp/tr; head -c 60000 /tmp/tr")
        out = subprocess.run(
            [docker, "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--memory", "256m", "--pids-limit", "128", "--cpus", "1",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--ulimit", "fsize=10000000", "-v", work + ":/w", "-w", "/w",
             _IMG, "bash", "-c", inner],
            capture_output=True, text=True, timeout=timeout + 20)
        raw = (out.stdout or "") + (out.stderr or "")
    except subprocess.TimeoutExpired:
        return DynTrace(ran=True, note="timeout", raw="[timed out]")
    except Exception as e:
        return DynTrace(note=f"error: {e.__class__.__name__}")
    finally:
        import shutil as _sh
        _sh.rmtree(work, ignore_errors=True)
    if "__BO_CCFAIL__" in raw:
        return DynTrace(ran=False, note="no se pudo compilar el shim de interposicion")
    t = _parse(raw)
    # descarta el auto-exec del propio binario (bash lo lanza con execve -> lo intercepta el shim)
    t.execs = [e for e in t.execs
               if e.split() and os.path.basename(e.split()[0]) != _SANDBOX_NAME
               and f"./{_SANDBOX_NAME}" not in e]
    if not (t.connects or t.binds or t.execs or t.files or t.chmods or t.unlinks):
        t.note = ("sin eventos interceptados (binario estatico o sin llamadas de red/fichero/exec "
                  "via libc)")
    return t


def _tok(rest: str, key: str) -> str:
    """Valor de token unico (sin espacios): `key=<tok>`."""
    m = re.search(r'\b' + re.escape(key) + r'=(\S+)', rest)
    return m.group(1) if m else ""


def _rest_after(rest: str, key: str) -> str:
    """Valor libre HASTA FIN DE LINEA tras `key=` (puede contener espacios: comandos, rutas)."""
    i = rest.find(key + "=")
    return rest[i + len(key) + 1:].strip() if i >= 0 else ""


def _parse(raw: str) -> DynTrace:
    t = DynTrace(ran=True, raw=raw[:8000])
    for line in raw.splitlines():
        if "__BO__" not in line:
            continue
        rest = line.split("__BO__", 1)[1].strip()
        parts = rest.split(None, 1)
        if not parts:
            continue
        ev = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        # el shim emite el valor con espacios (cmd/path) SIEMPRE al final -> se toma hasta fin de linea
        if ev == "connect":
            t.connects.append({"ip": _tok(body, "ip") or "?", "port": _tok(body, "port") or "?"})
        elif ev == "bind":
            t.binds.append({"ip": _tok(body, "ip") or "?", "port": _tok(body, "port") or "?"})
        elif ev == "listen":
            pass  # se refleja junto a bind
        elif ev == "execve":
            t.execs.append((_tok(body, "arg") + " " + _rest_after(body, "path")).strip())
        elif ev in ("system", "popen"):
            t.execs.append(_rest_after(body, "cmd"))
        elif ev == "open":
            t.files.append(_rest_after(body, "path"))
        elif ev == "chmod":
            t.chmods.append({"path": _rest_after(body, "path"), "mode": _tok(body, "mode")})
        elif ev == "unlink":
            t.unlinks.append(_rest_after(body, "path"))
    t.files = [f for f in dict.fromkeys(t.files) if f]
    t.execs = [e for e in dict.fromkeys(t.execs) if e]
    t.unlinks = [u for u in dict.fromkeys(t.unlinks) if u]
    return t


def _f(title_es, title_en, sev, verdict, ev, rat_es, rat_en, rec_es, rec_en, lang, loc):
    return Finding(
        title=title_es if lang == "es" else title_en,
        severity=sev, verdict=verdict, evidence=ev, location=loc,
        rationale=rat_es if lang == "es" else rat_en,
        recommendation=rec_es if lang == "es" else rec_en,
        rationale_en=rat_en, recommendation_en=rec_en,
    )


def dynamic_findings(t: DynTrace, lang: str = "es") -> List[Finding]:
    """Convierte el comportamiento observado en hallazgos. Lo observado en ejecucion es un hecho
    (verdict=verified para el comportamiento); la interpretacion de riesgo va en el rationale."""
    out: List[Finding] = []
    if not t.ok:
        return out
    for c in t.connects[:5]:
        ipp = f"{c['ip']}:{c['port']}"
        out.append(_f(
            f"Conexion saliente en runtime a {ipp}",
            f"Runtime outbound connection to {ipp}", "high", "verified",
            f"[dynamic: LD_PRELOAD]\nconnect() -> {ipp}",
            f"Al ejecutarse, el binario intenta CONECTAR a {ipp} (llamada real interceptada; la "
            "conexion se bloqueo por el sandbox, pero el destino es el que el binario pretendia). Un "
            "destino hardcodeado es un callback: reverse shell, C2 o exfiltracion.",
            f"When run, the binary attempts to CONNECT to {ipp} (real call intercepted; the connection "
            "was blocked by the sandbox, but the destination is the one the binary intended). A "
            "hardcoded destination is a callback: reverse shell, C2 or exfiltration.",
            "Investiga el destino; un binario legitimo no debe llamar a hosts fijos. Bloquea la salida "
            "de red y revisa el codigo que construye el sockaddr.",
            "Investigate the destination; a legitimate binary should not call fixed hosts. Block egress "
            "and review the code building the sockaddr.", lang, "runtime / red"))
    for b in t.binds[:3]:
        out.append(_f(
            f"Escucha en puerto {b['port']} en runtime",
            f"Listens on port {b['port']} at runtime", "high", "verified",
            f"[dynamic: LD_PRELOAD]\nbind() -> {b['ip']}:{b['port']}",
            f"El binario abre y escucha en el puerto {b['port']} al ejecutarse. Si ademas lanza un shell "
            "es una bind shell; en cualquier caso es un servicio de red que hay que justificar.",
            f"The binary opens and listens on port {b['port']} at runtime. If it also spawns a shell it "
            "is a bind shell; either way it is a network service that must be justified.",
            "Confirma que el servicio es legitimo, escucha solo en localhost y esta autenticado/filtrado.",
            "Confirm the service is legitimate, listens only on localhost and is authenticated/firewalled.",
            lang, "runtime / red"))
    for e in t.execs:
        low = e.lower()
        if any(s in low for s in ("/bin/sh", "/bin/bash", "sh -c", "/bin/dash", "bash -c")) or e.strip():
            is_shell = any(s in low for s in ("/bin/sh", "/bin/bash", "/bin/dash", "sh -c", "bash -c"))
            out.append(_f(
                "Ejecucion de comando/shell en runtime" if is_shell else "Ejecucion de proceso en runtime",
                "Command/shell execution at runtime" if is_shell else "Process execution at runtime",
                "high" if is_shell else "medium", "verified",
                f"[dynamic: LD_PRELOAD]\nexec: {e}",
                f"El binario ejecuta `{e}` en tiempo de ejecucion. " + (
                    "Es un shell: combinado con entrada del usuario o red, es ejecucion de comandos directa."
                    if is_shell else "Justifica que este proceso hijo sea legitimo."),
                f"The binary runs `{e}` at runtime. " + (
                    "It is a shell: combined with user or network input, it is direct command execution."
                    if is_shell else "Justify that this child process is legitimate."),
                "Evita lanzar shells/procesos con entrada no confiable; usa execve con argv fijo sin `sh -c`.",
                "Avoid spawning shells/processes with untrusted input; use execve with a fixed argv, no `sh -c`.",
                lang, "runtime / ejecucion"))
    for c in t.chmods:
        if c["mode"].endswith(("777", "666")):
            out.append(_f(
                f"Permisos laxos en runtime: {c['path']} -> {c['mode']}",
                f"Loose permissions at runtime: {c['path']} -> {c['mode']}", "medium", "verified",
                f"[dynamic: LD_PRELOAD]\nchmod({c['path']}, 0{c['mode']})",
                f"El binario pone permisos {c['mode']} (escribible por todos) en {c['path']} al ejecutarse.",
                f"The binary sets {c['mode']} (world-writable) on {c['path']} at runtime.",
                "Usa permisos minimos (0600/0640); nunca 0777/0666.",
                "Use least-privilege modes (0600/0640); never 0777/0666.", lang, "runtime / ficheros"))
    sens = [p for p in t.files if any(s in p for s in _SENSITIVE)]
    if sens:
        out.append(_f(
            "Acceso a ficheros sensibles en runtime", "Sensitive file access at runtime",
            "medium", "verified",
            "[dynamic: LD_PRELOAD]\nabiertos: " + ", ".join(sens[:8]),
            "Al ejecutarse, el binario abre ficheros sensibles (" + ", ".join(sens[:5]) + "). Justifica "
            "por que los necesita; puede indicar robo de credenciales o reconocimiento.",
            "When run, the binary opens sensitive files (" + ", ".join(sens[:5]) + "). Justify why it "
            "needs them; it may indicate credential theft or reconnaissance.",
            "Limita el acceso al minimo necesario y revisa por que el binario lee esos ficheros.",
            "Restrict access to the minimum needed and review why the binary reads those files.",
            lang, "runtime / ficheros"))
    return out
