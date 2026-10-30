"""
Test for capture.py that needs no admin rights and no real interface:
splitting a macOS BPF read buffer into packets.

Run:  python tests/test_capture.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from capture import parse_bpf_buffer  # noqa: E402
from packet_parser import parse_packet, strip_link_layer  # noqa: E402

failures = 0


def check(label, cond):
    global failures
    print(f"[{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        failures += 1


def bpf_record(sec, usec, frame):
    """bpf_hdr (18 bytes, little-endian) + frame, padded to a multiple of 4."""
    rec = struct.pack("<IIIIH", sec, usec, len(frame), len(frame), 18) + frame
    return rec + b"\0" * (-len(rec) % 4)


def test_bpf_buffer():
    udp = bytes.fromhex("d6d80035000c1234") + b"abcd"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 168, 1, 10]), bytes([8, 8, 8, 8])) + udp
    eth = bytes.fromhex("aabbccddeeff1122334455660800") + ip          # 46 bytes
    arp = bytes.fromhex("ffffffffffff1122334455660806") + bytes(28)   # 42 bytes

    buf = bpf_record(1761800000, 250000, eth) + bpf_record(1761800001, 0, arp)
    pkts = parse_bpf_buffer(buf)
    check("BPF buffer with 2 records -> 2 packets", len(pkts) == 2)
    check("BPF timestamp seconds + microseconds", pkts[0][0] == 1761800000.25)
    check("BPF first frame bytes intact (46 bytes)", pkts[0][1] == eth)
    check("BPF second record found after 4-byte padding", pkts[1][1] == arp)

    ip_bytes, _ = strip_link_layer(pkts[0][1], "ethernet")
    p = parse_packet(ip_bytes)
    check("BPF -> Ethernet -> IPv4 -> UDP decodes end to end",
          p["ip"]["src"] == "192.168.1.10" and p["udp"]["dst_port"] == 53)
    check("empty BPF buffer -> no packets", parse_bpf_buffer(b"") == [])


if __name__ == "__main__":
    test_bpf_buffer()
    print("\nALL CAPTURE TESTS PASSED" if failures == 0 else f"\n{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)
