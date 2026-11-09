# [Seed] Extracting IoT Router Firmware + UART Serial to Get Root

## Scenario Classification
Firmware / IoT Security

## Target Overview
A mid-to-low-end home router. Download the firmware bin from the manufacturer's website, extract squashfs using binwalk, connect to the device's UART serial port to get a root shell, and analyze its web management interface and startup scripts.

## Complete Execution Chain

### Part 1: Firmware Analysis

1. Download the firmware file (manufacturer's official site / OpenWRT / self-dump flash memory)
2. Basic Identification
   ```bash
   file firmware.bin
   binwalk firmware.bin                    # see LZMA / SquashFS / U-Boot
   binwalk -E firmware.bin                 # entropy graph to determine if encrypted
   ```
3. Extract
   ```bash
   binwalk -e firmware.bin
   cd _firmware.bin.extracted/squashfs-root
   ```
4. Static Analysis Key Points
   ```bash
   find . -name 'shadow' -exec cat {} \;          # default password hash
   find . -name '*.cgi' -o -name 'lighttpd*'      # web services
   find . -name 'rcS' -o -name 'init.d'           # startup scripts
   grep -r 'telnetd\|busybox' .                   # suspicious backdoors
   strings $(find . -name 'httpd') | grep -i 'admin\|debug\|backdoor'
   ```
5. Get `/etc/shadow` for offline cracking:
   ```bash
   john --wordlist=rockyou.txt shadow
   ```

### Part 2: Hardware UART

1. Disassemble the device to see the PCB → find unused 4-pin / 6-pin interfaces (usually not soldered or with pins)
2. Identify using a multimeter
   - GND (connect to ground copper pad)
   - VCC (3.3V, stable during startup)
   - TX (high level changes frequently during startup, output from UART → PC)
   - RX (stable during startup)
3. Connect USB-TTL converter (CP2102 / FT232)
   - Route router TX → USB-TTL RX
   - Route RX → USB-TTL TX
   - Route GND → USB-TTL GND
   - **Do not connect VCC** (device self-powered)
4. Start serial listening on the host
   ```bash
   sudo screen /dev/ttyUSB0 115200
   # or: minicom / picocom
   ```
5. Power up and start → watch U-Boot output → Linux boot → usually enter login prompt
6. Try default credentials / cracked shadow password → get root shell

## Pitfall Records

| Issue | Reason | Solution | Time |
|-------|--------|----------|------|
| binwalk extraction results in an empty directory | Some firmwares use non-standard formats (manufacturer private headers) | Use `dd` slicing to manually extract based on offsets, or replace binwalk with `unblob` | 1h |
| binwalk -E shows entropy close to 1 | Entirely encrypted | Find the decryption key used during firmware upgrades (usually hardcoded in OEM tools) | Several hours |
| No characters seen on UART | Incorrect baud rate | Try 9600 / 38400 / 57600 / 115200 / 460800 / 921600 | 30min |
| Characters seen but garbled | TX/RX reversed / voltage mismatch | 1) Swap TX RX 2) Confirm USB-TTL is 3.3V instead of 5V | 30min |
| Login prompt but no password available | Not cracked + manufacturer default password changed | Interrupt U-Boot at boot stage → `setenv bootargs ${bootargs} init=/bin/sh` → enter single user mode | 1.5h |
| No response to button interrupt in U-Boot | Manufacturer disabled console / changed prompt | Find `bootdelay` in the firmware, physically short-circuit SPI flash to force a boot failure and allow U-Boot to enter interactive mode | Several hours |
| Entered root but telnetd doesn't work | Image missing dropbear/telnetd | Mount a busybox-static from USB into the image | 1h |

## Tool Chain Discovery

- **unblob** is stronger than binwalk (automatically recognizes more formats, won't get stuck on private headers)
- **firmware-mod-kit** is an old tool but still useful for unpacking/packing
- **firmwalker** automatically scans for "sensitive clues" in the extracted squashfs (credentials/keys/URLs/binary backdoors)
- **EMBA** is a comprehensive firmware auditing platform (automated version of firmwalker + binary CVE scanning + simulated boot)
- **FirmAE** uses QEMU to simulate starting IoT firmware, allowing dynamic analysis of web interfaces without a real device
- **ChirpStack USB-TTL**, **Bus Pirate**, and **Tigard** all work; even a cheap CP2102 is sufficient

## Key Code/Commands

Firmware Audit One-Stop:

```bash
# 1. Extract
unblob -k firmware.bin -o extracted/

# 2. Run firmwalker
git clone https://github.com/craigz28/firmwalker
./firmwalker.sh extracted/squashfs-root

# 3. Simulate boot (if supported)
docker run -it --rm -v $(pwd):/firmware firmae:latest \
  /work/run.sh -d 1 /firmware/firmware.bin

# 4. Once simulated up Web → Scan directly with nuclei / nikto / curl
```

UART Auto-try common baud rates:

```bash
for baud in 9600 19200 38400 57600 115200 460800 921600; do
    echo "--- $baud ---"
    timeout 3 sudo cat /dev/ttyUSB0 < <(stty -F /dev/ttyUSB0 $baud cs8 -cstopb -parenb)
done
```

U-Boot Single User Bypass Classic Trick:

```text
# U-Boot phase key interrupt (usually press space or Ctrl+C)
=> setenv bootargs "console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs init=/bin/sh"
=> saveenv
=> boot
# Boot directly into sh, no password needed
```

## Suggestions for Improvements to This Package

- `reverse-engineering/platforms.md` already contains a firmware section, suggest splitting out `references/iot-firmware-cheatsheet.md`
- Add new `reverse-engineering/references/uart-debug.md` covering UART/JTAG/SWD basics
- Bootstrap manifest add unblob / firmwalker

## Reusable Patterns/Script Snippets

**IoT Security Testing 4 Phases**:

```text
Phase 1 — Software
  · Vendor firmware download + binwalk/unblob extraction
  · Run firmwalker once
  · grep default credentials / private keys / backdoor strings
  · QEMU simulate boot for web vulnerability scanning

Phase 2 — Hardware
  · Disassemble to find UART/JTAG pads
  · Multimeter identify GND/VCC/TX/RX
  · USB-TTL wiring, confirm voltage level 3.3V

Phase 3 — Debugging
  · screen/minicom listen
  · U-Boot phase interrupt for interactive mode
  · init=/bin/sh single user bypass password

Phase 4 — Exploitation
  · Get root → look at /etc/shadow for offline cracking
  · Look at Web management interface CGI binaries → find command injection / SSRF
  · Look at UPnP / mDNS / Bluetooth broadcast logic
```

**Default Credentials Quick Reference** (vendor common):

```text
admin / admin
admin / password
root / root
root / 1234
support / support
ubnt / ubnt          # Ubiquiti
admin / 1234         # ZyXEL
```

## Evolution Actions
- [ ] Split out iot-firmware-cheatsheet.md
- [ ] Create new uart-debug.md
- [ ] Bootstrap-manifest add unblob / firmwalker

## Environment Information
- Kali 2026.x (binwalk / unblob / squashfs-tools / firmwalker)
- USB-TTL converter: CP2102 / FT232 (3.3V level)
- Target: ARMv7 / MIPS routers (common OpenWRT derivative firmware)

## Desensitization Requirements
This entry is seed data based on publicly available IoT security testing methods and does not involve any real vendor or model.