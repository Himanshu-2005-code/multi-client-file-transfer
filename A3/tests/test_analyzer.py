"""
Tests for analyzer.py with hand-made frames (no capture, no admin needed).

Run:  python tests/test_analyzer.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer import (FilterError, PacketStore, detail_text, filter_packets,  # noqa: E402
                      parse_filter, summary_line)

failures = 0


def check(label, cond):
    global failures
    print(f"[{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        failures += 1


def ip_packet(src, dst, protocol, payload):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, 64, protocol, 0,
                       bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))) + payload


def tcp_segment(sport, dport, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 1000, 2000, 0x50, flags, 65535, 0, 0) + data


def udp_datagram(sport, dport, data=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


ETH = bytes.fromhex("aabbccddeeff1122334455660800")
ARP = bytes.fromhex("ffffffffffff1122334455660806") + bytes(28)

# Frames reused by the later steps' tests too
FRAMES = [
    ETH + ip_packet("192.168.1.10", "142.250.183.14", 6, tcp_segment(52344, 443, 0x02)),              # SYN
    ETH + ip_packet("192.168.1.10", "8.8.8.8", 17, udp_datagram(55000, 53, b"dns?")),
    ARP,
    ETH + ip_packet("142.250.183.14", "192.168.1.10", 6, tcp_segment(443, 52344, 0x18, b"HELLO SERVER")),
    ETH + ip_packet("192.168.1.10", "192.168.1.1", 1, bytes(8)),                                     # ICMP
]


def make_store():
    store = PacketStore()
    for i, frame in enumerate(FRAMES):
        store.add(1761800000.0 + i * 0.5, frame, "ethernet")
    return store


def test_store():
    store = make_store()
    check("4 IPv4 packets stored, ARP frame skipped", len(store.packets) == 4 and store.skipped == 1)
    check("packets numbered 1..4 in capture order", [p.number for p in store.packets] == [1, 2, 3, 4])
    check("packet size = captured frame length",
          store.get(1).length == len(FRAMES[0]) and store.get(3).length == len(FRAMES[3]))
    check("timestamp kept, shown as HH:MM:SS.mmm", len(store.get(2).time_str) == 12 and store.get(2).time_str.endswith(".500"))
    check("get() out of range -> None", store.get(0) is None and store.get(5) is None)

    line = summary_line(store.get(1))
    check("summary: number, IPs, TCP, ports, length",
          all(s in line for s in ("1", "192.168.1.10", "142.250.183.14", "TCP", "52344", "443", str(len(FRAMES[0])))))
    line = summary_line(store.get(2))
    check("summary: UDP with ports 55000 -> 53", "UDP" in line and "55000" in line and "53" in line)
    line = summary_line(store.get(4))
    check("summary: ICMP has no ports ('-')", "ICMP" in line and line.count(" - ") >= 1)


def numbers(store, text):
    return [p.number for p in filter_packets(store.packets, parse_filter(text))]


def test_filters():
    # packets: 1 TCP 192.168.1.10:52344 -> 142.250.183.14:443 (SYN)
    #          2 UDP 192.168.1.10:55000 -> 8.8.8.8:53
    #          3 TCP 142.250.183.14:443 -> 192.168.1.10:52344 (data)
    #          4 ICMP 192.168.1.10 -> 192.168.1.1
    store = make_store()
    check("no filter -> all 4", numbers(store, "") == [1, 2, 3, 4])
    check("tcp -> 1, 3", numbers(store, "tcp") == [1, 3])
    check("udp -> 2", numbers(store, "UDP") == [2])
    check("ip 8.8.8.8 (either side) -> 2", numbers(store, "ip 8.8.8.8") == [2])
    check("src 142.250.183.14 -> 3", numbers(store, "src 142.250.183.14") == [3])
    check("dst 192.168.1.10 -> 3", numbers(store, "dst 192.168.1.10") == [3])
    check("port 443 (either side) -> 1, 3", numbers(store, "port 443") == [1, 3])
    check("sport 443 -> 3", numbers(store, "sport 443") == [3])
    check("dport 53 -> 2", numbers(store, "dport 53") == [2])
    check("combined: tcp src 192.168.1.10 dport 443 -> 1", numbers(store, "tcp src 192.168.1.10 dport 443") == [1])
    check("combined with no match -> empty", numbers(store, "udp port 443") == [])
    check("port filter never matches ICMP (no ports)", 4 not in numbers(store, "port 0"))
    for bad in ("http", "port", "port abc", "port 70000", "src 300.1.1.1", "ip localhost"):
        try:
            parse_filter(bad)
            check(f"bad filter '{bad}' rejected", False)
        except FilterError:
            check(f"bad filter '{bad}' rejected", True)


def test_detail():
    store = make_store()
    d = detail_text(store.get(3))        # TCP 443 -> 52344, PSH+ACK, "HELLO SERVER"
    for s in ("Packet #3", "Packet Length:", "IP Header", "Version:              4",
              "Header Length:        20 bytes", "TTL:                  64", "Protocol:             TCP (6)",
              "Source IP:            142.250.183.14", "TCP Header", "Source Port:          443",
              "Sequence Number:      1000", "Acknowledgment:       2000", "Flags:                ACK, PSH (0x18)",
              "Window Size:          65535", "Payload Length:       12 bytes",
              "48 45 4C 4C 4F 20 53 45 52 56 45 52", "HELLO SERVER", "Source MAC:"):
        check(f"TCP detail shows {s!r}", s in d)

    d = detail_text(store.get(1))        # SYN, no data
    check("SYN detail: payload length 0, empty payload shown",
          "Payload Length:       0 bytes" in d and "(empty: payload length 0 bytes)" in d and "Hex:" not in d)

    d = detail_text(store.get(2))        # UDP 55000 -> 53 "dns?"
    check("UDP detail: header fields and payload",
          all(s in d for s in ("UDP Header", "Length:               12 bytes", "Payload Length:       4 bytes", "dns?")))

    d = detail_text(store.get(4))        # ICMP
    check("ICMP detail: IP header, no transport header", "IP Header" in d and "not TCP or UDP" in d)


class FakeCapture:
    """Stands in for capture.py: returns the test FRAMES, then nothing."""
    link_type = "ethernet"
    description = "fake capture"

    def __init__(self, **kwargs):
        self.frames = list(FRAMES)

    def read(self):
        if not self.frames:
            raise KeyboardInterrupt          # like the user pressing Ctrl+C
        return 1761800000.0, self.frames.pop(0)

    def close(self):
        pass


def run_cli(*lines):
    import contextlib
    import io
    from analyzer import AnalyzerCLI
    cli = AnalyzerCLI(FakeCapture)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        results = [cli.handle(line) for line in lines]
    return out.getvalue(), results, cli


def test_cli():
    out, _, cli = run_cli("list")
    check("CLI: list before capture says so", "No packets yet" in out)
    out, _, cli = run_cli("capture 3", "list")
    check("CLI: capture 3 stores 3 IPv4 packets (ARP skipped)",
          len(cli.store.packets) == 3 and "3 packets captured" in out and "1 non-IPv4" in out)
    check("CLI: list prints the summary table", "No.  Time" in out and "142.250.183.14" in out)
    out, _, _ = run_cli("capture 10", "filter udp")
    check("CLI: filter udp -> 1 of 4", "1 of 4 packets match 'udp'" in out and "8.8.8.8" in out)
    out, _, _ = run_cli("capture 10", "filter port nope")
    check("CLI: bad filter explained", "Bad filter" in out)
    out, _, _ = run_cli("capture 10", "show 3")
    check("CLI: show 3 prints the details", "Packet #3" in out and "TCP Header" in out and "HELLO SERVER" in out)
    out, _, _ = run_cli("capture 10", "show 9", "show x")
    check("CLI: show with a wrong number explained", "No packet number 9" in out and "Usage: show" in out)
    out, _, cli = run_cli("capture 10", "clear")
    check("CLI: clear empties the store", cli.store.packets == [])
    out, results, _ = run_cli("help", "blah", "quit")
    check("CLI: help, unknown command, quit", "Commands:" in out and "Unknown command" in out
          and results == [True, True, False])


if __name__ == "__main__":
    test_store()
    test_filters()
    test_detail()
    test_cli()
    print("\nALL ANALYZER TESTS PASSED" if failures == 0 else f"\n{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)
