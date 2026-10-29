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

**Link layer first** (`strip_link_layer`). A captured frame is [link header | IP datagram
| ...] (encapsulation). What the link header is depends on the system:

| Captured on | Before the IP header | Handling |
|---|---|---|
| Windows (raw socket) | nothing | bytes start at the IP header |
| Mac Wi-Fi/Ethernet, Linux | Ethernet header, 14 bytes: destination MAC (6), source MAC (6), EtherType (2) | EtherType 0x0800 = IPv4 -> skip 14 bytes (18 with a VLAN tag); IPv6 (0x86DD) and ARP (0x0806) are skipped |
| Mac loopback (lo0) | 4-byte address family (little-endian) | 2 = IPv4 -> skip 4 bytes |

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

**TCP header** (`parse_tcp`, lecture L13 "TCP segment structure"): 20 bytes, plus options
if the header length is more than 20. Format `"!HHIIBBHHH"` (I = 4 bytes).

| Bytes | Field | How it is extracted |
|---|---|---|
| 0-1 | source port | 2 bytes |
| 2-3 | destination port | 2 bytes |
| 4-7 | sequence number | 4 bytes |
| 8-11 | acknowledgment number | 4 bytes |
| 12 | header length (high 4 bits) | `(byte >> 4) * 4` bytes |
| 13 | flags CWR ECE URG ACK PSH RST SYN FIN | one bit each, tested with `byte & 0x80`, ..., `byte & 0x01` |
| 14-15 | window (rwnd) | 2 bytes |
| 16-17 | checksum | 2 bytes |
| 18-19 | urgent pointer | 2 bytes |
| header length .. end | payload | its length = segment length - header length (0 for a bare SYN or ACK) |

**UDP header** (`parse_udp`): 8 bytes, format `"!HHHH"`.

| Bytes | Field | How it is extracted |
|---|---|---|
| 0-1 | source port | 2 bytes |
| 2-3 | destination port | 2 bytes |
| 4-5 | length | 2 bytes: UDP header + data |
| 6-7 | checksum | 2 bytes |
| 8 .. length | payload | its length = length field - 8 |

**TCP or UDP?** (`parse_packet`) The IP header's protocol field (byte 9) says what the IP
payload contains: 6 = TCP, 17 = UDP; other protocols (e.g. 1 = ICMP) are shown with their
IP header only. The IP payload is taken from the end of the IP header up to the IP total
length, so link-layer padding after the packet is not mistaken for data.

## Use of AI

See [`AI_PROMPTS.md`](AI_PROMPTS.md): every prompt, word for word, and what the
AI produced at each step.
