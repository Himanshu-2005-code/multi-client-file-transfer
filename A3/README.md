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

- Python 3.9 or newer (tested with 3.10 to 3.13), standard library only: nothing to install.
- Administrator rights: Windows needs an Administrator terminal, macOS and
  Linux need `sudo`. Capturing packets is a privileged operation.
- Capture only on systems and networks you own or are authorized to analyze.

## Project structure

```
packet_parser.py   IPv4 / TCP / UDP header parsing from raw bytes (our own code)
analyzer.py        the analyzer: numbering, timestamps, summary table
capture.py         getting the raw bytes from the OS (Windows: raw socket + SIO_RCVALL;
                   macOS: BPF device /dev/bpf*; Linux: AF_PACKET socket)
tests/             test_parser.py, test_capture.py, test_analyzer.py: checks on hand-made
                   bytes (no admin needed); run_all.py runs them all
AI_PROMPTS.md      every prompt given to the AI, word for word, and what it produced
```

## Running it

Open a terminal **as Administrator** (Windows: right-click PowerShell -> "Run as
administrator") or use **sudo** (Mac/Linux), go to this folder, and start the analyzer:

```
python analyzer.py                 # Windows
sudo python3 analyzer.py           # Mac / Linux
```

At the `analyzer>` prompt:

| Command | What it does |
|---|---|
| `capture [N]` | capture N more packets (default 20); Ctrl+C stops early |
| `list` | summary: No., Time, Source, Destination, Protocol, ports, Length |
| `filter <words>` | summary of matching packets, e.g. `filter tcp dport 443` (see Filters) |
| `show <N>` | details of packet N: IP header, TCP/UDP header, payload |
| `clear` | forget all packets |
| `help`, `quit` | |

The interface of the default route (Wi-Fi or Ethernet) is used. Generate traffic while
capturing, e.g. open a website.

Example session (recorded on Linux with an earlier version that could capture on the
loopback interface):

```
analyzer> capture 6
Capturing 6 packets (Linux packet socket on lo (ethernet)). Ctrl+C to stop early.
6 packets captured (6 in total, 0 non-IPv4 frames skipped). Type 'list' or 'show <N>'.
analyzer> list
  No.  Time          Source           Destination      Proto  Src Port  Dst Port  Length
----------------------------------------------------------------------------------------
    1  19:40:24.452  127.0.0.1        127.0.0.1        UDP       53479      9999      54
    2  19:40:24.452  127.0.0.1        127.0.0.1        ICMP          -         -      82
    3  19:40:24.460  127.0.0.1        127.0.0.1        TCP       53504      9998      74
    4  19:40:24.460  127.0.0.1        127.0.0.1        TCP        9998     53504      74
    5  19:40:24.460  127.0.0.1        127.0.0.1        TCP       53504      9998      66
    6  19:40:24.460  127.0.0.1        127.0.0.1        TCP       53504      9998      80
analyzer> filter tcp dport 9998
...
3 of 6 packets match 'tcp dport 9998'.
analyzer> show 1
```

Tests (no capture, no admin needed):

```
python tests/run_all.py            # all of them: 114 checks
```

## Filters

Words that can be combined; a packet is listed only if it matches all of them:

| Filter | Shows packets where |
|---|---|
| `tcp`, `udp` | the IP payload is TCP / UDP |
| `ip <addr>` | source **or** destination IP is `<addr>` |
| `src <addr>`, `dst <addr>` | source / destination IP is `<addr>` |
| `port <n>` | source **or** destination port is `<n>` |
| `sport <n>`, `dport <n>` | source / destination port is `<n>` |

Examples: `tcp`, `udp port 53`, `ip 8.8.8.8`, `tcp src 192.168.1.10 dport 443`.

## Packet details

Selecting a packet shows its Ethernet header (if any), every IPv4 header field, the TCP or
UDP header, the raw bytes of each header, and the payload as a hex dump and as text. A
packet without application data shows `Payload Length: 0 bytes` and
`(empty: payload length 0 bytes)`. Example (a real UDP datagram):

```
Packet #1
Time:                 19:35:07.054
Packet Length:        54 bytes
...
IP Header
--------------------------------
Version:              4
Header Length:        20 bytes (IHL 5)
Total Length:         40 bytes
TTL:                  64
Protocol:             UDP (17)
Header Checksum:      0xB50E
Source IP:            127.0.0.1
Destination IP:       127.0.0.1
Header bytes:         45 00 00 28 87 B4 40 00 40 11 B5 0E 7F 00 00 01 7F 00 00 01

UDP Header
--------------------------------
Source Port:          53448
Destination Port:     9999
Length:               20 bytes
Checksum:             0xFE27
Payload Length:       12 bytes
Header bytes:         D0 C8 27 0F 00 14 FE 27

Payload
--------------------------------
Hex:
  0000  48 45 4C 4C 4F 20 53 45 52 56 45 52              HELLO SERVER

Text:
HELLO SERVER
```

## How the raw bytes are captured (`capture.py`)

The OS gives us the bytes; everything after that is our code. Capturing needs
administrator rights on every system.

| System | Method | What each read gives |
|---|---|---|
| Windows | raw IPv4 socket bound to the interface's IP, `IP_HDRINCL`, then `ioctl(SIO_RCVALL, RCVALL_ON)` ("receive all") | one IPv4 packet, starting at the IP header |
| macOS | a BPF device `/dev/bpfN` (what tcpdump and Wireshark use): `ioctl` `BIOCSETIF` (attach to `en0`), `BIOCIMMEDIATE`, `BIOCGBLEN`, `BIOCGDLT` | several packets, each after an 18-byte BPF header (timestamp, lengths), padded to 4 bytes |
| Linux | `AF_PACKET` socket with `ETH_P_ALL` | one frame, starting at the Ethernet header |

Each packet is timestamped when it is read (the BPF header's own timestamp on a Mac).

## How a packet is decoded

**Link layer first** (`strip_link_layer`). A captured frame is [link header | IP datagram
| ...] (encapsulation). What the link header is depends on the system:

| Captured on | Before the IP header | Handling |
|---|---|---|
| Windows (raw socket) | nothing | bytes start at the IP header |
| Mac Wi-Fi/Ethernet, Linux | Ethernet header, 14 bytes: destination MAC (6), source MAC (6), EtherType (2) | EtherType 0x0800 = IPv4 -> skip 14 bytes; IPv6 (0x86DD) and ARP (0x0806) are skipped |

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

## Testing

`python tests/run_all.py` runs 114 checks without capturing (parser 52, capture 6,
analyzer 56): every header field on hand-made bytes, bad and short inputs, Ethernet
headers, a macOS BPF buffer, filters, the detail view (including an empty payload) and the
commands.

| Where | Result |
|---|---|
| Linux (Python 3.11, 3.12, 3.13) | 114/114 checks; live capture on `eth0` (web traffic, TCP 443) and `lo` (UDP, TCP handshake, ICMP port unreachable) |
| Himanshu's laptop, Linux VM (Python 3.10) | all checks pass; without sudo: "Permission denied: run with sudo." |
| Windows (PowerShell as Administrator, Python 3.14) | live capture of 20 and 100 packets: ICMP, IGMP, DNS (UDP 53), QUIC (UDP 443), TCP incl. a plain HTTP request/response on port 80; `filter` and `show` checked |
| macOS | not run live by us; BPF buffer splitting covered by `tests/test_capture.py` |

## Notes and limitations

- **IPv4 only**, as the assignment asks: IPv6 and ARP frames are counted as skipped.
- **Checksums are shown, not verified.**
- **Packets larger than 1500 bytes** can appear: the OS hands the network card large TCP
  chunks that the card splits into frames (segmentation offload), and we capture before that
  split. Wireshark shows the same.
- **Fragments**: a later fragment of a split IP datagram has no TCP/UDP header, so only its
  IP header is decoded.
- **Windows** raw sockets give no Ethernet header, so no MAC addresses are shown there.
- Packets are kept in memory for the session; `clear` empties the list.

## Use of AI

AI tool: Claude (Anthropic), in the Claude app. The work was done in 18 small steps, one
prompt per step, one git commit per step (branch `a3`). Our prompts, word for word:

| Step | Prompt | Result |
|---|---|---|
| 0 | Attached the A3 PDF: "this assignment 3 ok this is i am doing with my friend Divyansh Goel roll no. 2024201"; answers to the AI's questions ("ios and windows everything", "Yes, macOS (MacBook)", the submission rules, "do it on same repo i will invite divyansh", "New branch a3, A3 files only (Recommended)", "Small steps like A2", "tomorrow 23:59"); "is this in my syllabus"; attached L16-L18 slides: "chevk these" | 14-step plan; syllabus check |
| 1 | "next" | branch `a3`, README skeleton, AI log |
| 2 | "next" | IPv4 header parsing |
| 3 | "next" | TCP header parsing |
| 4 | "next" | UDP header parsing, automatic TCP/UDP detection |
| 5 | "next" | link-layer headers (Ethernet, VLAN, Mac loopback) |
| 6 | "next" | Windows capture (raw socket + SIO_RCVALL) |
| 7 | "next" | macOS capture (BPF device) |
| 8 | "next" | Linux capture (AF_PACKET) |
| 9 | "next" | packet store, numbering, timestamps, summary table |
| 10 | "next" | filters |
| 11 | "next" | packet detail view |
| 12 | "next" | interactive command line |
| 13 | "next" | capture tests with fake OS calls, run_all.py, tests on Python 3.10-3.13 |
| 14 | "next" | final README, report PDF, zip |
| 15 | "Make the pdf of assignment 2 and 3 with prompts like the assignment 1" | report rewritten in the format of our A1 report |
| 16 | "anything u can remove from these without efecting the requiremnt and that is extra from ur end"; chose "A3: VLAN + quick test" | VLAN tag handling and the capture.py quick-test mode removed |
| 17 | "what are the extra tricks concepts that i have used are theree simple replacements and"; "do all you think replace" | macOS loopback header, fake-OS capture tests and command-line options removed |

Full details of each step (what was produced and what was checked) are in
[`AI_PROMPTS.md`](AI_PROMPTS.md).
