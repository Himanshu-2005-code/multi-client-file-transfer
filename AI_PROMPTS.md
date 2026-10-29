# AI usage log (Assignment 3)

AI tool: Claude (Anthropic), used through the Claude app.
Team: Himanshu (2024261), Divyansh Goel (2024201).
The work is done in small steps, one prompt per step, one git commit per step.
Each entry lists our prompt word for word, what the AI produced, and what we
checked ourselves.

---

## Step 0: planning

**Our prompts and answers:**
1. Attached the A3 PDF: "this assignment 3 ok this is i am doing with my friend Divyansh Goel roll no. 2024201"
2. Answers to the AI's questions: capture system "ios and windows everything"; then
   "Yes, macOS (MacBook)"; submission rules pasted from the course ("You may use AI as you
   did last time. But you must give credit to it and all the details, like your prompt,
   etc. The programming assignment can be done in a team of up to 3 members. ... a single
   .zip file containing all the code files and a README or makefile ... a PDF of the report
   ... named ROLLNO1_Rollno2_Rollno3_A3.pdf and ROLLNO1_Rollno2_Rollno3_A3.zip ...");
   repository "do it on same repo i will invite divyansh", then "New branch a3, A3 files
   only (Recommended)"; pace "Small steps like A2"; deadline "tomorrow 23:59".
3. "is this in my syllabus"
4. Attached our lecture slides L16 (network layer intro), L17 (buffering, subnets),
   L18 (DHCP, NAT): "chevk these"

**AI output:** a 14-step plan (no code). Syllabus check: the TCP header (L13 "TCP segment
structure"), ports and multiplexing (L13/L14), encapsulation and packet sniffing (chapter 1)
and the IPv4 header (L17 slide 4-15 "IP Datagram format") are all in our slides; the
capture mechanics (raw sockets, BPF) are programming tools, not syllabus.

---

## Step 1: start the A3 branch

**Our prompt:** "next"

**AI output:** branch `a3` in our repository (`multi-client-file-transfer`), starting empty
so it holds only A3 files; this log; a README skeleton; `.gitignore`.

**What we checked:** the branch contains only the A3 files.

---

## Step 2: IPv4 header parsing

**Our prompt:** "next"

**AI output:**
- `packet_parser.py`: `parse_ipv4()` decodes the first 20 bytes with
  `struct.unpack("!BBHHHBBH4s4s")` (network byte order): version and header length from
  byte 0 (`>> 4` and `& 0x0F`, header length = IHL x 4), total length, identification,
  flags and fragment offset (`>> 13`, `& 0x1FFF`), TTL, protocol (6 = TCP, 17 = UDP),
  checksum, source and destination IP; options when IHL > 5. Rejects data shorter than
  20 bytes, non-IPv4 versions and IHL < 5.
- `tests/test_parser.py`: 17 checks on a real header written out byte by byte
  (`45 00 00 3c ...`), a header with options, and bad inputs.

**What we checked:** the tests pass; each field matches the L17 "IP Datagram format" slide.

---

## Step 3: TCP header parsing

**Our prompt:** "next"

**AI output:**
- `packet_parser.py`: `parse_tcp()` decodes the first 20 bytes of the IP payload with
  `struct.unpack("!HHIIBBHHH")`: ports, sequence and acknowledgment numbers (4 bytes each),
  header length from the high 4 bits of byte 12 (x 4 bytes), the eight flags of byte 13
  tested bit by bit (CWR ECE URG ACK PSH RST SYN FIN), window, checksum, urgent pointer,
  options, and the payload (everything after the header) with its length.
- `tests/test_parser.py`: 16 more checks (33 in total): an ACK+PSH segment carrying "HELLO",
  a SYN with options and no data (payload length 0), all eight flags, and bad inputs.

**What we checked:** the tests pass; the fields match the L13 "TCP segment structure" slide.

---

## Step 4: UDP header parsing and automatic TCP/UDP detection

**Our prompt:** "next"

**AI output:**
- `packet_parser.py`: `parse_udp()` decodes the 8-byte UDP header with
  `struct.unpack("!HHHH")` (ports, length, checksum); the payload ends where the length
  field says. `parse_packet()` decodes a whole IPv4 packet: IP header first, then the IP
  protocol field picks the next parser automatically (6 = TCP, 17 = UDP, others left as IP
  only). The IP payload is cut at "total length" so Ethernet padding is not counted as data;
  a later fragment (offset > 0) has no transport header, so none is decoded.
- `tests/test_parser.py`: 13 more checks (46 in total): a DNS-style UDP datagram, an empty UDP
  payload, bad UDP inputs, and whole packets detected as TCP, UDP and ICMP.

**What we checked:** the tests pass.

---

## Step 5: link-layer header before the IP header

**Our prompt:** "next"

**AI output:**
- `packet_parser.py`: `strip_link_layer(frame, link_type)` removes what comes before the IP
  header, which depends on how the bytes were captured: `"raw"` (Windows raw socket, already
  at the IP header), `"ethernet"` (Mac and Linux: 14 bytes = destination MAC, source MAC,
  EtherType; 0x0800 = IPv4; an 802.1Q VLAN tag adds 4 bytes), `"null"` (Mac loopback: 4-byte
  address family, 2 = IPv4). Frames that are not IPv4 (IPv6, ARP) are returned as skipped with
  the reason. (The Mac's extra BPF record header is handled with the Mac capture in step 7.)
- `tests/test_parser.py`: 9 more checks (55 in total).

**What we checked:** the tests pass.

---

## Step 6: packet capture on Windows

**Our prompt:** "next"

**AI output:**
- `capture.py`: `WindowsCapture` opens a raw IPv4 socket (`SOCK_RAW`, `IPPROTO_IP`), binds it to
  the local interface address, sets `IP_HDRINCL` (received packets include the IP header) and
  switches the interface to receive-all mode with `ioctl(SIO_RCVALL, RCVALL_ON)`. Each `recv()`
  returns one whole IPv4 packet starting at the IP header (link type `"raw"`), timestamped with
  `time.time()`. The local address is found by "connecting" a UDP socket (no packet is sent).
  A one-second timeout keeps Ctrl+C working; receive-all is switched off on exit; a clear
  message asks for an Administrator terminal if permission is denied.
- `python capture.py 10`: a quick test that captures 10 packets and prints number, time,
  size, IPs, protocol and ports using our parser.

**What we checked:** the AI could not run Windows itself (only a Linux shell), so the Windows
test is done by us on Himanshu's laptop (result logged in the next step).

---

## Step 7: packet capture on macOS

**Our prompt:** "next" (the Windows test from step 6 is still to be run by us)

**AI output:**
- `capture.py`: `MacCapture` uses a BPF device, as tcpdump and Wireshark do on macOS (macOS has
  no "receive all" raw socket): opens a free `/dev/bpfN`, attaches it to the default-route
  interface (e.g. `en0`, from `route -n get default`) with `ioctl(BIOCSETIF)`, sets
  `BIOCIMMEDIATE`, reads the buffer size (`BIOCGBLEN`) and link type (`BIOCGDLT`: Ethernet or
  loopback). Only the standard library (`os`, `fcntl`, `select`, `struct`).
  `parse_bpf_buffer()` splits one read into packets: each has an 18-byte `bpf_hdr` (timestamp
  seconds and microseconds, captured length, original length, header length) and is padded
  to a multiple of 4 bytes. `sudo python3 capture.py 10` runs the quick test on a Mac.
- `tests/test_capture.py`: 6 checks on a hand-made BPF buffer (two records, padding,
  timestamps, and BPF -> Ethernet -> IPv4 -> UDP decoding end to end).

**What we checked:** the tests pass; the Mac run itself is done by Divyansh on his MacBook.

---

## Step 8: packet capture on Linux

**Our prompt:** "next"

**AI output:**
- `capture.py`: `LinuxCapture` opens an `AF_PACKET` raw socket for all protocols
  (`htons(ETH_P_ALL)`), bound to the default-route interface (from `/proc/net/route`) or the one
  given. Frames start with the Ethernet header (loopback too, with zero MAC addresses); the
  interface type in `/sys/class/net/<if>/type` tells raw-IP interfaces apart. On loopback each
  packet is delivered twice (outgoing and incoming), so the outgoing copy is dropped.

**What the AI checked (Linux, as root):** `capture.py 8` on `eth0` while fetching a web page:
8 TCP packets to/from port 443 with correct addresses and ports. `capture.py 4 lo` while
sending two UDP datagrams and opening a TCP connection on 127.0.0.1: 2 UDP packets
(54 bytes = 14 Ethernet + 20 IP + 8 UDP + 12 bytes "HELLO SERVER") and the SYN / SYN-ACK,
each listed once.

---

## Step 9: packet store and summary table

**Our prompt:** "next"

**AI output:**
- `analyzer.py`: `CapturedPacket` keeps each IPv4 packet's number (1, 2, 3, ... in capture
  order), timestamp, size (captured length) and raw bytes, and decodes it once with our parser.
  `PacketStore` numbers the packets and counts skipped non-IPv4 frames (IPv6, ARP).
  `summary_line()` / `print_summary()` print the summary table: No., Time, Source,
  Destination, Protocol, Source port, Destination port, Length ("-" for protocols without
  ports, e.g. ICMP). `python analyzer.py 20` captures 20 packets and prints the table.
- `tests/test_analyzer.py`: 8 checks with hand-made frames (numbering, ARP skipped, sizes,
  timestamps, TCP / UDP / ICMP summary lines).

**What the AI checked (Linux, as root):** `analyzer.py 10` while fetching a web page printed a
correct 10-row table (TCP to/from port 443).
