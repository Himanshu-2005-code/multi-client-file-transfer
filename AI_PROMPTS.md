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
