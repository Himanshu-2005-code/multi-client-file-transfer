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

---

## Step 10: packet filtering

**Our prompt:** "next"

**AI output:**
- `analyzer.py`: filters written as words, all of which must match: `tcp` / `udp`; `ip <addr>`
  (source or destination), `src <addr>`, `dst <addr>`; `port <n>` (source or destination),
  `sport <n>`, `dport <n>`; e.g. `tcp src 192.168.1.10 dport 443`. `parse_filter()` turns the
  words into conditions and rejects bad input (unknown word, missing value, invalid IPv4
  address checked with `ipaddress`, port outside 0-65535); `matches()` tests one packet
  (protocols without ports, like ICMP, never match a port filter); `filter_packets()`.
- `tests/test_analyzer.py`: 18 more checks (26 in total): each filter, combinations, and bad filters.

**What we checked:** the tests pass.

---

## Step 11: packet detail view

**Our prompt:** "next"

**AI output:**
- `analyzer.py`: `detail_text(pkt)` shows one packet in the format of the assignment's sample:
  number, time, length; the Ethernet header when there is one (MACs, EtherType); every IP header
  field; the TCP header (ports, sequence / acknowledgment numbers, header length, flags by name
  and as hex, window, checksum, urgent pointer, payload length) or the UDP header (ports, length,
  checksum, payload length); the raw bytes of each header ("Header bytes", to show where each
  field comes from); and the payload as a hex dump (offset | hex | text) and as text, with
  unprintable bytes as "." and long payloads cut after 512 bytes. An empty payload is shown as
  "(empty: payload length 0 bytes)" instead of being interpreted. Non-TCP/UDP packets (e.g. ICMP)
  show the IP header and their data.
- `tests/test_analyzer.py`: 21 more checks (47 in total) on TCP, SYN (empty payload), UDP and ICMP details.

**What the AI checked (Linux, as root):** captured a real UDP datagram "HELLO SERVER" on
loopback and printed its details: IP header (total length 40, TTL 64, protocol UDP 17),
UDP header (length 20 = 8 + 12), payload `48 45 4C 4C 4F 20 53 45 52 56 45 52` / HELLO SERVER.

---

## Step 12: interactive command line

**Our prompt:** "next"

**AI output:**
- `analyzer.py`: `python analyzer.py` opens a prompt (`analyzer>`) with the commands
  `capture [N]` (default 20, Ctrl+C stops early), `list` (summary of all packets),
  `filter <words>` (summary of matching packets and how many match), `show <N>` (details),
  `clear`, `help`, `quit`; options `-i/--interface` (Mac/Linux), `--ip` (Windows) and
  `-c/--count` (capture before the prompt). Wrong input gets a usage message instead of a crash.
  `AnalyzerCLI` takes the capture function as a parameter, so it can be tested without admin.
- `tests/test_analyzer.py`: 9 more checks (56 in total) driving the commands with a fake capture.

**What the AI checked (Linux, as root):** `python analyzer.py -i lo` with typed commands while a
UDP datagram and a TCP connection with data ran on 127.0.0.1: `capture 6`, `list`,
`filter tcp dport 9998` (3 of 6), `filter udp` (1 of 6), `show 2`. Packet 2 was a real ICMP
"port unreachable" (type 3, code 3): nothing listened on UDP port 9999, and the ICMP message
quotes the original IP + UDP header and "HELLO SERVER".

---

## Step 13: testing on every platform we can reach

**Our prompt:** "next"

**AI output:**
- `tests/test_capture.py`: the Windows and macOS capture classes now also run against FAKE
  operating-system calls, so their logic is checked on any computer: Windows (raw socket opened,
  bound to the interface IP, `IP_HDRINCL` set, receive-all switched on and off, packets and
  timeouts) and macOS (busy `/dev/bpf0` skipped, `BIOCSETIF` on `en0`, immediate mode, link
  type from `BIOCGDLT`, two packets from one read, nothing to read). The four macOS ioctl
  numbers are re-derived from the `_IOR` / `_IOW` macro formula. 22 capture checks in total.
- `tests/run_all.py`: runs all test files and prints the totals (133 checks).

**What was checked:**
- All 133 checks pass with Python 3.11, 3.12 and 3.13 (AI's Linux shell).
- On Himanshu's laptop (its Linux VM, Python 3.10), cloned from GitHub: the parser (55),
  capture (6, the version before this step) and analyzer (56) checks pass; without sudo the
  analyzer stops with "Permission denied: run with sudo."
- Live capture on Linux was tested in steps 8, 11 and 12.
- Still to be done by us: a live run on Windows (Administrator PowerShell) and on Divyansh's
  Mac (`sudo python3 analyzer.py`).

---

## Step 14: README, report and submission files

**Our prompt:** "next"

**AI output:** README completed (how the bytes are captured on each system, testing results,
notes and limitations, AI usage table); the report `2024261_2024201_A3.pdf` (design, how each
field is extracted from the bytes, capture on each system, sample outputs, testing, challenges,
AI usage); `2024261_2024201_A3.zip` with all code, tests, README and this log.

**What we checked:** the zip unpacks into a folder where `python tests/run_all.py` passes.

---

## Step 15: report in the format of our A1 report

**Our prompt:** "Make the pdf of assignment 2 and 3 with prompts like the assignment 1" (with our A1
report attached)

**AI output:** `2024261_2024201_A3.pdf` rewritten in the format of our A1 technical report (LaTeX,
table of contents; Introduction, Design, Implementation, Experimental Results, Prompts of AI Use as a
numbered list, Verification Performed, Challenges, Conclusion). The report claims only the live captures
that were actually run (on Linux); the Windows and macOS capture code is described as tested against
fake operating-system calls.

**What we checked:** the report matches this log and the code.

---

## Step 16: remove extras not needed by the requirements

**Our prompt:** "anything u can remove from these without efecting the requiremnt and that is extra from ur end";
chose "A3: VLAN + quick test".

**AI output:** removed the 802.1Q VLAN tag handling (and its test) from `strip_link_layer()` and the
`python capture.py 10` quick-test mode; README updated (132 checks).

**What we checked:** `python tests/run_all.py` passes; a live capture with `analyzer.py` still works.

---

## Step 17: simpler replacements

**Our prompts:** "what are the extra tricks concepts that i have used are theree simple replacements and";
"do all you think replace"

**AI output:** removed the macOS loopback (lo0) header handling, the tests that ran the Windows and
macOS capture code against fake operating-system calls, the Linux loopback duplicate filter, and the
command-line options (-i, --ip, -c): the analyzer always captures on the default interface.

**What we checked:** `python tests/run_all.py` passes (114 checks); a live capture with `analyzer.py`
on the default interface (TCP to port 443) works with `capture`, `list`, `filter`, `show`.
