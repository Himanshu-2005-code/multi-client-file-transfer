"""
Tests for packet_parser.py on hand-made bytes (no capture, no admin needed).

Run:  python tests/test_parser.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from packet_parser import ParseError, parse_ipv4  # noqa: E402

failures = 0


def check(label, cond):
    global failures
    print(f"[{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        failures += 1


def test_ipv4():
    # A real IPv4 header (20 bytes), written out byte by byte:
    #   45       version 4, IHL 5 (5 x 4 = 20 bytes)
    #   00       type of service
    #   00 3c    total length 60
    #   1c 46    identification 7238
    #   40 00    flags 010 (Don't Fragment), fragment offset 0
    #   40       TTL 64
    #   06       protocol 6 = TCP
    #   b1 e6    header checksum 0xB1E6
    #   ac 10 0a 63   source 172.16.10.99
    #   ac 10 0a 0c   destination 172.16.10.12
    header = bytes.fromhex("4500003c1c4640004006b1e6ac100a63ac100a0c")
    ip = parse_ipv4(header + b"payload...")

    check("IPv4 version 4", ip["version"] == 4)
    check("IPv4 header length 20 bytes (IHL 5)", ip["header_length"] == 20)
    check("IPv4 total length 60", ip["total_length"] == 60)
    check("IPv4 identification 7238", ip["identification"] == 0x1C46)
    check("IPv4 Don't Fragment set, More Fragments not", ip["dont_fragment"] and not ip["more_fragments"])
    check("IPv4 fragment offset 0", ip["fragment_offset"] == 0)
    check("IPv4 TTL 64", ip["ttl"] == 64)
    check("IPv4 protocol 6 = TCP", ip["protocol"] == 6 and ip["protocol_name"] == "TCP")
    check("IPv4 checksum 0xB1E6", ip["checksum"] == 0xB1E6)
    check("IPv4 source 172.16.10.99", ip["src"] == "172.16.10.99")
    check("IPv4 destination 172.16.10.12", ip["dst"] == "172.16.10.12")
    check("IPv4 no options", ip["options"] == b"")

    # IHL 6: 24-byte header with 4 bytes of options; protocol 17 = UDP
    with_opts = bytes.fromhex("46000020000000004011000001020304050607080000000000")
    ip = parse_ipv4(with_opts)
    check("IPv4 IHL 6 -> 24-byte header with 4 option bytes",
          ip["header_length"] == 24 and len(ip["options"]) == 4)
    check("IPv4 protocol 17 = UDP", ip["protocol_name"] == "UDP")

    for label, bad in (("too short (10 bytes)", header[:10]),
                       ("version 6 is not IPv4", bytes([0x65]) + header[1:]),
                       ("IHL 4 (< 20 bytes) is invalid", bytes([0x44]) + header[1:])):
        try:
            parse_ipv4(bad)
            check(f"IPv4 rejects {label}", False)
        except ParseError:
            check(f"IPv4 rejects {label}", True)


if __name__ == "__main__":
    test_ipv4()
    print("\nALL PARSER TESTS PASSED" if failures == 0 else f"\n{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)
