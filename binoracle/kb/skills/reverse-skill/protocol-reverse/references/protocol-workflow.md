# Protocol reverse Cheat Sheet

> Applies to: `protocol-reverse` skill · 2026-07-18

## Common Layout Patterns

| Pattern | Feature | Hint |
|---------|---------|------|
| Fixed-length header + body | First 2/4 bytes length | Note if header length is included |
| Magic number | Fixed `0xDEAD` etc. | Facilitates stream resynchronization |
| TLV | type-length-value repeated | Type enumeration forms message dictionary |
| Protobuf | Field number varint | Use `protoc --decode_raw` |
| Encrypted frame | High entropy, no plain text URL | Find nonce/IV neighborhood first |

## Minimal Python Skeleton

```python
import struct
def parse_frame(buf: bytes):
    magic, length, msg_type = struct.unpack_from(">IHI", buf, 0)
    body = buf[10:10+length]
    return {"magic": magic, "type": msg_type, "body": body}
```

## Extract TCP payload from PCAP

```bash
tshark -r cap.pcap -Y "tcp.port==4433" -T fields -e tcp.payload | head
```