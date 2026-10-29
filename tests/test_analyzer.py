"""
Tests for analyzer.py with hand-made frames (no capture, no admin needed).

Run:  python tests/test_analyzer.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer import PacketStore, summary_line  # noqa: E402

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


if __name__ == "__main__":
    test_store()
    print("\nALL ANALYZER TESTS PASSED" if failures == 0 else f"\n{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)
