"""
Tests for packet_parser.py on hand-made bytes (no capture, no admin needed).

Run:  python tests/test_parser.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from packet_parser import ParseError, parse_ipv4, parse_tcp  # noqa: E402

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


def test_tcp():
    # A TCP header (20 bytes) followed by 5 bytes of data "HELLO":
    #   c0 00          source port 49152
    #   1f 90          destination port 8080
    #   00 01 9c 0a    sequence number 105482
    #   00 03 2f 49    acknowledgment number 208713
    #   50             header length 5 x 4 = 20 bytes (high 4 bits)
    #   18             flags 0001 1000 = ACK + PSH
    #   ff ff          window 65535
    #   2f 81          checksum 0x2F81
    #   00 00          urgent pointer
    seg = bytes.fromhex("c0001f9000019c0a00032f495018ffff2f810000") + b"HELLO"
    tcp = parse_tcp(seg)
    check("TCP source port 49152", tcp["src_port"] == 49152)
    check("TCP destination port 8080", tcp["dst_port"] == 8080)
    check("TCP sequence number 105482", tcp["seq"] == 105482)
    check("TCP acknowledgment number 208713", tcp["ack"] == 208713)
    check("TCP header length 20 bytes", tcp["header_length"] == 20)
    check("TCP flags ACK + PSH", tcp["flag_names"] == ["ACK", "PSH"])
    check("TCP window 65535", tcp["window"] == 65535)
    check("TCP checksum 0x2F81", tcp["checksum"] == 0x2F81)
    check("TCP payload 'HELLO', length 5", tcp["payload"] == b"HELLO" and tcp["payload_length"] == 5)

    # SYN with 12 bytes of options (header length 8 words = 32 bytes) and no data
    syn = (bytes.fromhex("d4310050000003e8000000008002faf0abcd0000")
           + bytes.fromhex("020405b40103030801010402"))
    tcp = parse_tcp(syn)
    check("TCP SYN: header length 32 with 12 option bytes",
          tcp["header_length"] == 32 and len(tcp["options"]) == 12)
    check("TCP SYN: only the SYN flag", tcp["flag_names"] == ["SYN"])
    check("TCP SYN: no payload (length 0)", tcp["payload_length"] == 0 and tcp["payload"] == b"")
    check("TCP all eight flags decoded",
          parse_tcp(seg[:13] + b"\xff" + seg[14:])["flag_names"]
          == ["CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"])

    for label, bad in (("too short (19 bytes)", seg[:19]),
                       ("header length 16 (< 20)", seg[:12] + b"\x40" + seg[13:]),
                       ("header length beyond the data", syn[:20])):
        try:
            parse_tcp(bad)
            check(f"TCP rejects {label}", False)
        except ParseError:
            check(f"TCP rejects {label}", True)


if __name__ == "__main__":
    test_ipv4()
    test_tcp()
    print("\nALL PARSER TESTS PASSED" if failures == 0 else f"\n{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)
