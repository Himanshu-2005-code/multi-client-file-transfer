# Mini Packet Analyzer (Assignment 3)

Team: Himanshu (2024261), Divyansh Goel (2024201)

A simplified, command-line packet analyzer in Python, similar to Wireshark. It
captures the packets sent and received by this computer, numbers and timestamps
them, shows a summary list that can be filtered, and opens any packet to show
its IPv4 header, TCP or UDP header, and payload.

The IPv4, TCP and UDP headers are decoded by our own code from the raw bytes
(Python `struct` and bit operations). No packet-decoding library (Scapy,
PyShark, ...) is used; the operating system only hands us the raw bytes.

## Requirements

- Python 3.9 or newer, standard library only.
- Administrator rights: Windows needs an Administrator terminal, macOS and
  Linux need `sudo`. Capturing packets is a privileged operation.
- Capture only on systems and networks you own or are authorized to analyze.

## Project structure

```
packet_parser.py   IPv4 / TCP / UDP header parsing from raw bytes (our own code)
tests/             test_parser.py: parser checks on hand-made bytes (no admin needed)
```

## Running it

Parser tests (no capture, no admin needed):

```
python tests/test_parser.py
```

(the capture tool is added in later steps)

## How a packet is decoded

**IPv4 header** (`parse_ipv4`, lecture L17 "IP Datagram format"): 20 bytes, plus options
if the header length is more than 20.

| Bytes | Field | How it is extracted |
|---|---|---|
| 0 | version (4 bits), IHL (4 bits) | `byte >> 4`, `byte & 0x0F`; header length = IHL x 4 bytes |
| 1 | type of service | 1 byte |
| 2-3 | total length | 2 bytes, big-endian (header + payload) |
| 4-5 | identification | 2 bytes |
| 6-7 | flags (3 bits), fragment offset (13 bits) | `value >> 13`, `value & 0x1FFF` |
| 8 | TTL | 1 byte |
| 9 | protocol | 1 byte: 6 = TCP, 17 = UDP |
| 10-11 | header checksum | 2 bytes |
| 12-15 | source IP | 4 bytes, printed as a.b.c.d |
| 16-19 | destination IP | 4 bytes |

All multi-byte fields are in network byte order (big-endian), hence `!` in the
`struct.unpack` format `"!BBHHHBBH4s4s"` (B = 1 byte, H = 2 bytes, 4s = 4 raw bytes).

## Use of AI

See [`AI_PROMPTS.md`](AI_PROMPTS.md): every prompt, word for word, and what the
AI produced at each step.
