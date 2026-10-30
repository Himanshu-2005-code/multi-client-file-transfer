"""
Mini packet analyzer: keeps the captured packets and shows them.

Each captured IPv4 packet gets a number (1, 2, 3, ... in capture order), the
time it was captured and its size, and is decoded once with packet_parser.

Run (Administrator terminal on Windows, sudo on Mac/Linux):
    python analyzer.py              then type: capture 20, list, filter tcp, show 3, help, quit
"""

import ipaddress
import sys
from datetime import datetime

from packet_parser import ParseError, parse_packet, strip_link_layer


class CapturedPacket:
    def __init__(self, number, timestamp, frame, link_type):
        self.number = number
        self.timestamp = timestamp
        self.frame = frame                    # the raw bytes as captured
        self.length = len(frame)              # packet size in bytes
        self.link_type = link_type
        self.ip_bytes, self.link = strip_link_layer(frame, link_type)
        self.decoded = None
        self.error = None
        try:
            self.decoded = parse_packet(self.ip_bytes)
        except ParseError as e:               # header damaged or cut short
            self.error = str(e)

    @property
    def time_str(self):
        return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]

    @property
    def ip(self):
        return self.decoded["ip"] if self.decoded else None

    @property
    def transport(self):
        """The TCP or UDP header dict, or None."""
        if not self.decoded:
            return None
        return self.decoded.get("tcp") or self.decoded.get("udp")

    @property
    def protocol(self):
        if not self.decoded:
            return "?"
        return self.decoded["transport"] or self.ip["protocol_name"]


class PacketStore:
    """All packets captured in this session, in capture order."""

    def __init__(self):
        self.packets = []
        self.skipped = 0          # frames that were not IPv4 (IPv6, ARP, ...)

    def add(self, timestamp, frame, link_type):
        ip_bytes, _ = strip_link_layer(frame, link_type)
        if ip_bytes is None:
            self.skipped += 1
            return None
        pkt = CapturedPacket(len(self.packets) + 1, timestamp, frame, link_type)
        self.packets.append(pkt)
        return pkt

    def get(self, number):
        if 1 <= number <= len(self.packets):
            return self.packets[number - 1]
        return None


# --- Filtering --------------------------------------------------------------
# A filter is a list of conditions; a packet is shown only if it matches ALL
# of them. Written as words, e.g.  "tcp dport 443"  or  "udp ip 8.8.8.8".
FILTER_HELP = """Filter words (combine any of them; all must match):
  tcp | udp            protocol
  ip <addr>            source OR destination IP     src <addr> / dst <addr>
  port <n>             source OR destination port   sport <n>  / dport <n>
Examples:  tcp      udp port 53      src 192.168.1.10 tcp dport 443"""

IP_WORDS = ("ip", "src", "dst")
PORT_WORDS = ("port", "sport", "dport")


class FilterError(Exception):
    pass


def parse_filter(text):
    """'tcp dport 443' -> [('proto', 'TCP'), ('dport', 443)]; raises FilterError."""
    words = text.lower().split()
    conditions = []
    i = 0
    while i < len(words):
        w = words[i]
        if w in ("tcp", "udp"):
            conditions.append(("proto", w.upper()))
            i += 1
            continue
        if w not in IP_WORDS + PORT_WORDS:
            raise FilterError(f"unknown filter word '{w}'")
        if i + 1 >= len(words):
            raise FilterError(f"'{w}' needs a value")
        value = words[i + 1]
        if w in IP_WORDS:
            try:
                ipaddress.IPv4Address(value)          # only checks the address is valid
            except ValueError:
                raise FilterError(f"'{value}' is not an IPv4 address")
        else:
            if not value.isdigit() or not 0 <= int(value) <= 65535:
                raise FilterError(f"'{value}' is not a port number (0-65535)")
            value = int(value)
        conditions.append((w, value))
        i += 2
    return conditions


def matches(pkt, conditions):
    """True if the packet satisfies every condition."""
    if pkt.decoded is None:
        return not conditions                # undecodable packets only show unfiltered
    ip, t = pkt.ip, pkt.transport
    for kind, value in conditions:
        if kind == "proto" and pkt.decoded["transport"] != value:
            return False
        if kind == "ip" and value not in (ip["src"], ip["dst"]):
            return False
        if kind == "src" and ip["src"] != value:
            return False
        if kind == "dst" and ip["dst"] != value:
            return False
        if kind in PORT_WORDS:
            if t is None:                        # e.g. ICMP has no ports
                return False
            if kind == "port" and value not in (t["src_port"], t["dst_port"]):
                return False
            if kind == "sport" and t["src_port"] != value:
                return False
            if kind == "dport" and t["dst_port"] != value:
                return False
    return True


def filter_packets(packets, conditions):
    return [p for p in packets if matches(p, conditions)]


SUMMARY_HEADER = (f"{'No.':>5}  {'Time':<12}  {'Source':<15}  {'Destination':<15}  "
                  f"{'Proto':<5}  {'Src Port':>8}  {'Dst Port':>8}  {'Length':>6}")


def summary_line(pkt):
    if pkt.decoded is None:
        return f"{pkt.number:>5}  {pkt.time_str:<12}  (could not decode: {pkt.error})  {pkt.length:>6}"
    t = pkt.transport
    sport = str(t["src_port"]) if t else "-"
    dport = str(t["dst_port"]) if t else "-"
    return (f"{pkt.number:>5}  {pkt.time_str:<12}  {pkt.ip['src']:<15}  {pkt.ip['dst']:<15}  "
            f"{pkt.protocol:<5}  {sport:>8}  {dport:>8}  {pkt.length:>6}")


def print_summary(packets):
    print(SUMMARY_HEADER)
    print("-" * len(SUMMARY_HEADER))
    for pkt in packets:
        print(summary_line(pkt))


# --- Detail view ------------------------------------------------------------
MAX_PAYLOAD_SHOWN = 512     # longer payloads are cut, with a note


def hex_bytes(data):
    """b'HE' -> '48 45'"""
    return " ".join(f"{b:02X}" for b in data)


def hex_dump(data, width=16):
    """Offset | hex bytes | text, 16 bytes per row (unprintable bytes shown as '.')."""
    rows = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"  {off:04x}  {hex_bytes(chunk):<{width * 3}} {text}")
    return "\n".join(rows)


def field(name, value):
    return f"{name + ':':<22}{value}"


def detail_text(pkt):
    """Everything about one packet, as in the sample output of the assignment."""
    out = [f"Packet #{pkt.number}", field("Time", pkt.time_str),
           field("Packet Length", f"{pkt.length} bytes")]

    if pkt.link.get("type") == "ethernet":
        out += ["", "Ethernet Header", "-" * 32,
                field("Source MAC", pkt.link["src_mac"]),
                field("Destination MAC", pkt.link["dst_mac"]),
                field("EtherType", f"0x{pkt.link['ethertype']:04X} (IPv4)")]

    if pkt.decoded is None:
        out += ["", f"Could not decode the IP packet: {pkt.error}",
                "", "Raw bytes", "-" * 32, hex_dump(pkt.ip_bytes[:MAX_PAYLOAD_SHOWN])]
        return "\n".join(out)

    ip = pkt.ip
    flags = [n for n, on in (("DF", ip["dont_fragment"]), ("MF", ip["more_fragments"])) if on]
    out += ["", "IP Header", "-" * 32,
            field("Version", ip["version"]),
            field("Header Length", f"{ip['header_length']} bytes (IHL {ip['header_length'] // 4})"),
            field("Type of Service", f"0x{ip['tos']:02X}"),
            field("Total Length", f"{ip['total_length']} bytes"),
            field("Identification", ip["identification"]),
            field("Flags", ", ".join(flags) if flags else "none"),
            field("Fragment Offset", ip["fragment_offset"]),
            field("TTL", ip["ttl"]),
            field("Protocol", f"{ip['protocol_name']} ({ip['protocol']})"),
            field("Header Checksum", f"0x{ip['checksum']:04X}"),
            field("Source IP", ip["src"]),
            field("Destination IP", ip["dst"]),
            field("Header bytes", hex_bytes(pkt.ip_bytes[:ip["header_length"]]))]

    proto = pkt.decoded["transport"]
    if proto == "TCP":
        tcp = pkt.decoded["tcp"]
        out += ["", "TCP Header", "-" * 32,
                field("Source Port", tcp["src_port"]),
                field("Destination Port", tcp["dst_port"]),
                field("Sequence Number", tcp["seq"]),
                field("Acknowledgment", tcp["ack"]),
                field("Header Length", f"{tcp['header_length']} bytes"),
                field("Flags", f"{', '.join(tcp['flag_names']) or 'none'} (0x{tcp['flags']:02X})"),
                field("Window Size", tcp["window"]),
                field("Checksum", f"0x{tcp['checksum']:04X}"),
                field("Urgent Pointer", tcp["urgent_pointer"]),
                field("Payload Length", f"{tcp['payload_length']} bytes"),
                field("Header bytes", hex_bytes(pkt.decoded["ip_payload"][:tcp["header_length"]]))]
        payload = tcp["payload"]
    elif proto == "UDP":
        udp = pkt.decoded["udp"]
        out += ["", "UDP Header", "-" * 32,
                field("Source Port", udp["src_port"]),
                field("Destination Port", udp["dst_port"]),
                field("Length", f"{udp['length']} bytes"),
                field("Checksum", f"0x{udp['checksum']:04X}"),
                field("Payload Length", f"{udp['payload_length']} bytes"),
                field("Header bytes", hex_bytes(pkt.decoded["ip_payload"][:8]))]
        payload = udp["payload"]
    else:
        out += ["", f"({ip['protocol_name']}: not TCP or UDP, so no transport header is decoded)"]
        payload = pkt.decoded["ip_payload"]

    out += ["", "Payload", "-" * 32]
    if not payload:
        out.append("(empty: payload length 0 bytes)")
    else:
        shown = payload[:MAX_PAYLOAD_SHOWN]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in shown)
        out += ["Hex:", hex_dump(shown), "", "Text:", text]
        if len(payload) > len(shown):
            out.append(f"... ({len(payload) - len(shown)} more bytes not shown)")
    return "\n".join(out)


def capture_into(store, cap, count):
    """Capture until `count` IPv4 packets are stored, or Ctrl+C."""
    added = 0
    try:
        while added < count:
            got = cap.read()
            if got is None:
                continue
            if store.add(got[0], got[1], cap.link_type) is not None:
                added += 1
    except KeyboardInterrupt:
        print("\n(stopped)")
    return added


# --- Command-line interface -------------------------------------------------
HELP = """Commands:
  capture [N]          capture N more packets (default 20); Ctrl+C stops early
  list                 summary of all captured packets
  filter <words>       summary of the packets that match, e.g.  filter tcp dport 443
  show <N>             details of packet number N (IP / TCP / UDP headers, payload)
  clear                forget all captured packets
  help                 this help
  quit                 exit

""" + FILTER_HELP


class AnalyzerCLI:
    """One command per line. open_capture is passed in so tests can use a fake capture."""

    def __init__(self, open_capture):
        self.open_capture = open_capture
        self.store = PacketStore()

    def capture(self, count):
        cap = self.open_capture()
        print(f"Capturing {count} packets ({cap.description}). Ctrl+C to stop early.")
        try:
            added = capture_into(self.store, cap, count)
        finally:
            cap.close()
        print(f"{added} packets captured ({len(self.store.packets)} in total, "
              f"{self.store.skipped} non-IPv4 frames skipped). Type 'list' or 'show <N>'.")

    def handle(self, line):
        """Run one command. Returns False when the user wants to quit."""
        words = line.split()
        if not words:
            return True
        cmd, args = words[0].lower(), words[1:]

        if cmd in ("quit", "exit", "q"):
            return False
        if cmd == "help":
            print(HELP)
        elif cmd == "capture":
            if args and not (args[0].isdigit() and int(args[0]) > 0):
                print("Usage: capture [N]   (N = number of packets, e.g. capture 50)")
            else:
                self.capture(int(args[0]) if args else 20)
        elif cmd == "list":
            if not self.store.packets:
                print("No packets yet. Type 'capture' first.")
            else:
                print_summary(self.store.packets)
        elif cmd == "filter":
            if not args:
                print(FILTER_HELP)
                return True
            try:
                conditions = parse_filter(" ".join(args))
            except FilterError as e:
                print(f"Bad filter: {e}\n{FILTER_HELP}")
                return True
            shown = filter_packets(self.store.packets, conditions)
            print_summary(shown)
            print(f"{len(shown)} of {len(self.store.packets)} packets match '{' '.join(args)}'.")
        elif cmd == "show":
            if len(args) != 1 or not args[0].isdigit():
                print("Usage: show <N>   (N = packet number from the list)")
            elif self.store.get(int(args[0])) is None:
                print(f"No packet number {args[0]} (there are {len(self.store.packets)}).")
            else:
                print(detail_text(self.store.get(int(args[0]))))
        elif cmd == "clear":
            self.store = PacketStore()
            print("All packets cleared.")
        else:
            print(f"Unknown command '{cmd}'. Type 'help'.")
        return True

    def run(self):
        print("Mini Packet Analyzer. Type 'help' for commands.")
        while True:
            try:
                line = input("analyzer> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not self.handle(line):
                break


def main():
    from capture import open_capture
    AnalyzerCLI(open_capture).run()


if __name__ == "__main__":
    main()
