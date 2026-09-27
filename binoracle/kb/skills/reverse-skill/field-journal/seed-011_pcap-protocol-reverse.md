# [Seed] PCAP Custom Binary Protocol Reverse Engineering

## Scenario Classification
Packet Capture Analysis / Protocol Reversing

## Target Overview
A certain IoT device/desktop client uses a custom binary protocol over TCP (non-HTTP). A PCAP file is captured, and the frame structure, field meanings, and encryption layer (if any) need to be restored. Additionally, a local client/server implementation should be written to replicate the behavior.

## Complete Execution Chain

1. Open the PCAP file in Wireshark for basic statistics
   - `Statistics → Conversations` to view IP/port pairs
   - `Statistics → I/O Graphs` to see data flow patterns
2. Identify the true application layer stream (strip off standard layers like TLS)
3. On a specific TCP stream, go to `Follow → TCP Stream`, switch to RAW mode, and export the data
4. Binary-level observation: Are the first few bytes of each frame fixed magic/length fields?
   ```bash
   xxd dump.bin | head -20
   ```
5. Use hex mode to find patterns: Fixed header, length, TLV, CRC
6. Write a Python parser (using `struct` and `scapy`) to decode frames one by one
7. Synchronize with binary reverse engineering to trace protocol fields (use IDA/Ghidra to examine structs around send/recv calls)
8. Verify: Start your own client to send a frame → Ensure the server responds correctly

## Pitfall Records

| Issue | Reason | Solution | Time |
|-------|--------|----------|------|
| Wireshark does not recognize the protocol, only showing "Data" | It's a private protocol without a parser | Write a Wireshark Lua dissector or perform offline analysis with Python | 30min |
| Frames appear to be random and different each time | There is compression or encryption layer | Use entropy analysis (`ent dump.bin`) to determine if it's encrypted; look for nonce/IV fields | 1h |
| Length field calculation is incorrect | The length might be little-endian/big-endian/or include/exclude itself | Find a few frames of different lengths, set up equations to solve | 40min |
| TLS captured but cannot be decrypted | Client does not leave SSLKEYLOGFILE | Hook at the client process layer (use Frida to hook ssl_read/ssl_write) to capture plaintext | 1.5h |
| Data is correct but server does not respond | Protocol includes an incrementing seq/nonce, replay is rejected | Understand how the seq number is calculated (usually a hash of the previous frame or an incremental counter) | 50min |

## Toolchain Discovery

- **Wireshark Lua Dissector** Can turn private protocols into Wireshark visualizations with less than 100 lines
- **scapy** Define `Packet` subclasses in Python to write parsers
- **Kaitai Struct** Describe protocol structures using YAML, which can generate multi-language parsers (Python/Java/C++/JS), suitable for long-term reuse
- **NetworkMiner** Better suited for "post-mortem" investigations (automatically reassembles files, identifies credentials)
- **ent / binwalk -E** Check entropy; values greater than 7.5 almost certainly indicate encryption

## Key Code/Commands

scapy custom protocol example (TLV):

```python
from scapy.all import *

class MyMsg(Packet):
    name = "MyProto"
    fields_desc = [
        StrFixedLenField("magic", b"\xab\xcd", 2),
        ByteField("version", 1),
        ByteField("type", 0),
        LenField("length", None, fmt="H"),     # H = uint16 BE
        XIntField("seq", 0),
        StrLenField("payload", "", length_from=lambda p: p.length - 8),
        XShortField("crc", 0),
    ]

# Parse the PCAP file
pkts = rdpcap('dump.pcap')
for p in pkts:
    if TCP in p and p[TCP].dport == 9527 and p.payload:
        msg = MyMsg(bytes(p[TCP].payload))
        msg.show()
```

Kaitai Struct YAML (preferred for long-term projects):

```yaml
# myproto.ksy
meta:
  id: myproto
  endian: be
seq:
  - id: magic
    contents: [0xab, 0xcd]
  - id: version
    type: u1
  - id: type
    type: u1
  - id: length
    type: u2
  - id: seq_no
    type: u4
  - id: payload
    size: length - 8
  - id: crc
    type: u2
```

Entropy analysis:

```bash
binwalk -E dump.bin             # Entropy graph
ent dump.bin                    # Numeric values
```

## Suggestions for Improving This Package

- `reverse-engineering/platforms.md` Add a "Custom Protocol Reverse Engineering 4-Step Method" section
- Add a new `reverse-engineering/references/kaitai-cheatsheet.md` cheat sheet
- Bootstrap manifest add scapy (pip) and binwalk

## Reusable Patterns/Script Snippets

**Custom Protocol Reverse Engineering 4-Step Method**:

```text
1. Look at the rhythm (I/O diagram + Conversations to find session boundaries)
2. Find frame boundaries (magic / length / terminator)
3. Break down fields (fixed header, length, payload, checksum)
4. Verify encryption (entropy + find nonce + binary reverse lookup of send function)
```

**Tips for Finding Frame Lengths**:

Export all PSH packets from the same stream → Look at the total length of each TCP segment, see if the length field (positions i, i+1, i+2) can deduce the segment length.

## Evolutionary Actions
- [ ] reverse-engineering/platforms.md Add protocol reverse engineering section
- [ ] bootstrap-manifest add scapy / binwalk
- [ ] Add Kaitai Struct cheat sheet

## Environment Information
- Kali / Ubuntu, Wireshark 4.x, Python 3.10+, scapy 2.5
- Target Protocol: Custom TCP binary (with TLV / length prefix)
- Encryption Layer: Depends on the situation (common AES-CTR / ChaCha20)

## Desensitization Requirements
This entry is seed data based on publicly available protocol reverse engineering methods and does not involve real products.