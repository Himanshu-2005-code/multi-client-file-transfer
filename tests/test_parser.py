"""
Tests for packet_parser.py on hand-made bytes (no capture, no admin needed).

Run:  python tests/test_parser.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from packet_parser import (ParseError, parse_ipv4, parse_packet, parse_tcp, parse_udp,  # noqa: E402
                           strip_link_layer)

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


def test_udp():
    # A DNS query over UDP: 8-byte header + 4 bytes of data
    #   d6 d8   source port 55000
    #   00 35   destination port 53 (DNS)
    #   00 0c   length 12 (8 header + 4 data)
    #   12 34   checksum 0x1234
    dgram = bytes.fromhex("d6d80035000c1234") + b"abcd"
    udp = parse_udp(dgram)
    check("UDP source port 55000", udp["src_port"] == 55000)
    check("UDP destination port 53", udp["dst_port"] == 53)
    check("UDP length 12", udp["length"] == 12)
    check("UDP checksum 0x1234", udp["checksum"] == 0x1234)
    check("UDP payload 'abcd', length 4", udp["payload"] == b"abcd" and udp["payload_length"] == 4)
    check("UDP with no data: payload length 0",
          parse_udp(bytes.fromhex("d6d8003500081234"))["payload_length"] == 0)
    for label, bad in (("too short (7 bytes)", dgram[:7]),
                       ("length field 4 (< 8)", dgram[:4] + b"\x00\x04" + dgram[6:])):
        try:
            parse_udp(bad)
            check(f"UDP rejects {label}", False)
        except ParseError:
            check(f"UDP rejects {label}", True)


def ip_header(protocol, payload_len, frag=0):
    """A 20-byte IPv4 header 10.0.0.1 -> 10.0.0.2 for the given protocol."""
    import struct
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, 1, frag, 64, protocol, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))


def test_packet():
    tcp_seg = bytes.fromhex("c0001f9000019c0a00032f495018ffff2f810000") + b"HELLO"
    udp_dgram = bytes.fromhex("d6d80035000c1234") + b"abcd"

    p = parse_packet(ip_header(6, len(tcp_seg)) + tcp_seg)
    check("protocol 6 -> decoded as TCP automatically",
          p["transport"] == "TCP" and p["tcp"]["dst_port"] == 8080 and p["tcp"]["payload"] == b"HELLO")
    p = parse_packet(ip_header(17, len(udp_dgram)) + udp_dgram)
    check("protocol 17 -> decoded as UDP automatically",
          p["transport"] == "UDP" and p["udp"]["dst_port"] == 53 and p["udp"]["payload"] == b"abcd")
    p = parse_packet(ip_header(1, 8) + bytes(8))
    check("protocol 1 (ICMP) -> IP only, no TCP/UDP", p["transport"] is None and p["ip"]["protocol_name"] == "ICMP")
    p = parse_packet(ip_header(6, len(tcp_seg)) + tcp_seg + bytes(10))
    check("padding after total length is not payload", p["tcp"]["payload"] == b"HELLO")
    p = parse_packet(ip_header(17, 8, frag=0x00B9) + bytes(8))
    check("later fragment (offset > 0): no transport header decoded", p["transport"] is None)


def test_link_layer():
    udp_dgram = bytes.fromhex("d6d80035000c1234") + b"abcd"
    ip_pkt = ip_header(17, len(udp_dgram)) + udp_dgram

    ip, info = strip_link_layer(ip_pkt, "raw")
    check("raw (Windows): bytes already start at the IP header", ip == ip_pkt)

    #   dst MAC aa:bb:cc:dd:ee:ff | src MAC 11:22:33:44:55:66 | EtherType 08 00 (IPv4)
    eth = bytes.fromhex("aabbccddeeff" "112233445566" "0800")
    ip, info = strip_link_layer(eth + ip_pkt, "ethernet")
    check("Ethernet: 14-byte header removed", ip == ip_pkt)
    check("Ethernet: MAC addresses read",
          info["src_mac"] == "11:22:33:44:55:66" and info["dst_mac"] == "aa:bb:cc:dd:ee:ff")
    check("Ethernet frame -> packet decodes as UDP", parse_packet(ip)["udp"]["dst_port"] == 53)

    vlan = bytes.fromhex("aabbccddeeff" "112233445566" "8100" "0064" "0800")
    ip, info = strip_link_layer(vlan + ip_pkt, "ethernet")
    check("Ethernet with VLAN tag: 18-byte header removed", ip == ip_pkt)

    for label, ethertype in (("IPv6", "86dd"), ("ARP", "0806")):
        ip, info = strip_link_layer(bytes.fromhex("aabbccddeeff112233445566" + ethertype) + bytes(28), "ethernet")
        check(f"Ethernet {label} frame skipped", ip is None and label in info["skip_reason"])

    #   loopback "null" header: address family 2 (AF_INET) little-endian = 02 00 00 00
    ip, info = strip_link_layer(bytes.fromhex("02000000") + ip_pkt, "null")
    check("Mac loopback: 4-byte family header removed", ip == ip_pkt)
    ip, info = strip_link_layer(bytes.fromhex("1e000000") + bytes(40), "null")
    check("Mac loopback: IPv6 (family 30) skipped", ip is None)


if __name__ == "__main__":
    test_ipv4()
    test_tcp()
    test_udp()
    test_packet()
    test_link_layer()
    print("\nALL PARSER TESTS PASSED" if failures == 0 else f"\n{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)
