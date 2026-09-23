# VM escape / hypervisor (cheat sheet)

Escapar de una maquina virtual al host explotando el HIPERVISOR, normalmente a traves de un
dispositivo VIRTUAL emulado (QEMU/KVM, VirtualBox, VMware). Desde un guest con root, un bug en
la emulacion de un device da RCE en el proceso del hypervisor (host).

## Modelo
- El guest habla con "hardware" que en realidad emula el hypervisor (QEMU device model):
  tarjetas de red (e1000, virtio-net), audio, USB, GPU (virtio-gpu), etc.
- El guest accede al device por MMIO / PIO / DMA. Un bug en como el device emulado procesa esos
  accesos (parser de descriptores, buffers, offsets) = memory corruption en el HOST.

## Superficie tipica (QEMU)
- MMIO/PIO handlers de un device: escrituras/lecturas a registros que el device procesa.
- DMA: el device lee/escribe memoria del guest via direcciones fisicas del guest (GPA). Un
  device que confia en un tamano/offset controlado por el guest -> OOB en el host.
- virtio: colas (virtqueues) con descriptors controlados por el guest; validaciones flojas de
  indices/longitudes -> OOB.
- CVE clasicos: VENOM (floppy FDC, CVE-2015-3456), varios de e1000/rtl8139, virtio.

## Primitivas y flujo
1. desde el guest (root) programa el device emulado con valores maliciosos (registros/DMA).
2. dispara el bug -> OOB read/write en el proceso QEMU del host.
3. leak de una direccion del host (ASLR del proceso qemu) + arb write -> secuestrar un puntero
   a funcion del device (muchos structs de QEMU tienen callbacks) -> RIP en el host.
4. ROP/one_gadget en el contexto del proceso qemu -> shell en el host.

## VirtualBox / VMware
- VirtualBox: devices en C++ (VGA, network, shared folders/HGCM). Bugs en HGCM y en el device
  de graficos son historicos.
- VMware: Backdoor RPC (vmware-tools), device de graficos SVGA. Pwn2Own recurrente.

## Herramientas y entorno
- codigo fuente de QEMU (hw/ tiene todos los devices) como referencia del parser vulnerable.
- gdb sobre el proceso qemu del host; compila qemu con simbolos.
- desde el guest: acceso a /sys, ioports, o un modulo kernel propio para hacer MMIO/DMA a
  voluntad. libpci / mapear BARs.

## Notas
- Requiere normalmente root en el guest (para tocar el device a bajo nivel).
- Es la categoria mas dificil de pwn: combina kernel del guest + userland del host + el device.
