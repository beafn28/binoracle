---
name: protocol-reverse
description: Use for authorized reverse engineering of custom binary protocols, Protobuf/gRPC, WebSocket frames, and PCAP-driven protocol recovery.
---

# Protocol Reverse Engineering

## ACTION REQUIRED（Read this immediately）

1. `NOW`: Read `../field-journal/precedent-reverse.md` — Confirm authorization and regular operation boundaries
2. `NOW`: Confirm if the task is for **protocol/traffic/serialization format** reverse (non-pure web parameter signature → go to `js-reverse/`)
3. `NOW`: If there are target network interactions → Run `../scripts/case-init.ps1` to complete scope; prohibit ACT if `auth` not granted
4. `NEXT`: Read `../tool-index.md`; bootstrap missing tools (tshark/wireshark, etc., may need manual installation)
5. `ACT`: Enter workflow Phase 1, produce a draft frame layout or message dictionary

## Applicable Scenarios

- Custom TCP/UDP binary protocols
- Protobuf / gRPC / FlatBuffers / MessagePack
- WebSocket / MQTT / Private RPC
- PCAP / PCAPNG to recover fields and state machines
- Client-server validation, serial numbers, encrypted frame headers

## Do Not Use This Skill

| Situation | Go To |
|-----------|-------|
| Only HTTP parameter signatures / JS encryption | `js-reverse/` |
| Only TLS certificate issues | `pentest-tools/` or browser proxy |
| Deep dive into firmware protocol stack + simulation | `firmware-pentest/` and then back to this skill |

## Workflow

### Phase 1 — Collection and Diagnosis

```text
□ Get the sample: PCAP / proxy export / client logs / binary
□ Mark direction: C→S / S→C; is there a handshake, heartbeat, reconnect?
□ Fixed header? Magic number? Length field? TLV? Fixed length?
□ Is it compressed (zlib/gzip/lz4) or encrypted (AES/ChaCha in frame)?
□ tshark -r cap.pcap -T fields -e frame.number -e ip.src -e tcp.payload
```

### Phase 2 — Frame Layout Recovery

```text
□ Align multiple similar messages, find invariant bytes / auto-incrementing sequence numbers
□ Length field: big-endian/little-endian, includes header/excludes header
□ Validation: CRC16/32, checksum, HMAC position
□ Draw state machine: Connect → Auth → Ready → Request/Response → Close
□ Tools: Wireshark custom dissector draft / ImHex / 010 Editor template / Kaitai Struct
```

### Phase 3 — Serialization and Encryption

```text
□ Protobuf: .proto recovery (blackboxprotobuf / pbtk / protoc --decode_raw)
□ gRPC: HTTP/2 headers + protobuf body
□ Encryption: Find key derivation (client so/dll/JS) → Combine ida-reverse / js-reverse / apk-reverse
□ Replay: Only within authorized scope; start with harmless fields then sensitive operations
```

### Phase 4 — Output

```text
MUST produce:
- Message type table (name / opcode / fields)
- At least one reproducible decoding command or script
- Evidence: raw hex excerpts + decoded results (anonymized)
```

## Toolchain

| Tool | Required | Purpose | Bootstrap |
|------|----------|---------|-----------|
| tshark / Wireshark | Strongly recommended | PCAP parsing | Manual / winget |
| Python3 | Yes | Decoding script | System |
| blackboxprotobuf | Optional | Unknown protobuf | pip |
| ImHex / 010 | Optional | Structure template | Manual |
| IDA / r2 / Ghidra | As needed | Client serialization functions | See corresponding skill |

## References

- `references/protocol-workflow.md` — Frame layout and Protobuf cheat sheet
- Related: `../ida-reverse/` `../js-reverse/` `../firmware-pentest/` `../pentest-tools/`

## Routing Context

**Upstream**: `MASTER-ROUTING` R21 · `routing.md`  
**Downstream**: Needs client algorithm → `ida-reverse`/`js-reverse`; needs replay → `pentest-tools`/`api-security`  
**Peer**: `malware-analysis` (C2 protocol), `digital-forensics` (traffic forensics)

## Task Completion Self-Check

- [ ] Did you recover the message layout or state machine (not just paste hex)?
- [ ] Do you have a reproducible decoding command?
- [ ] Are you within scope and anonymized?
- [ ] Have you rewritten field-journal / report checklist?