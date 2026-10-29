"""
Mini packet analyzer: keeps the captured packets and shows them.

Each captured IPv4 packet gets a number (1, 2, 3, ... in capture order), the
time it was captured and its size, and is decoded once with packet_parser.

Step 9 version:  python analyzer.py 20     captures 20 packets, prints the summary table
(needs Administrator on Windows, sudo on Mac/Linux)
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


if __name__ == "__main__":
    from capture import open_capture

    count = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    cap = open_capture(interface=sys.argv[2] if len(sys.argv) > 2 else None)
    print(f"Capturing {count} packets ({cap.description}). Ctrl+C to stop early.")
    store = PacketStore()
    try:
        capture_into(store, cap, count)
    finally:
        cap.close()
    print_summary(store.packets)
    print(f"\n{len(store.packets)} IPv4 packets captured, {store.skipped} non-IPv4 frames skipped.")
