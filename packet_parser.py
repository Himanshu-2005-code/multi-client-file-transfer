"""
Header parsing for the mini packet analyzer, written by hand from the raw bytes.

Every header is a fixed layout of fields at known byte positions. We read them
with struct.unpack, where the format string says how many bytes each field
has, and "!" means network byte order (big-endian: most significant byte
first). Fields smaller than a byte (4-bit, 3-bit, 13-bit, 1-bit flags) are
taken out of a bigger number with shifts (>>) and masks (&).
"""

import struct

# IPv4 "protocol" field (upper layer protocol): which header comes next.
IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}


class ParseError(Exception):
    """The bytes are too short or do not look like the expected header."""


def ipv4_to_str(four_bytes):
    """4 raw bytes -> dotted decimal, e.g. b'\\xc0\\xa8\\x01\\x0a' -> '192.168.1.10'."""
    return ".".join(str(b) for b in four_bytes)


def parse_ipv4(data):
    """
    Decode the IPv4 header at the start of `data` (bytes).

    Layout (RFC 791; lecture L17, "IP Datagram format"), 32 bits per row:

      byte 0      byte 1      bytes 2-3
      ver | IHL   type of     total length
      (4) | (4)   service
      bytes 4-5               bytes 6-7
      identification          flags (3) | fragment offset (13)
      byte 8      byte 9      bytes 10-11
      TTL         protocol    header checksum
      bytes 12-15: source IP address
      bytes 16-19: destination IP address
      options (only if IHL > 5), then the payload (a TCP or UDP segment)

    Returns a dict of the fields; "header_length" tells where the payload starts.
    """
    if len(data) < 20:
        raise ParseError(f"IPv4 header needs at least 20 bytes, got {len(data)}")

    # ! = network byte order. B = 1 byte, H = 2 bytes, 4s = 4 raw bytes.
    (ver_ihl, tos, total_length, identification, flags_frag,
     ttl, protocol, checksum, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:20])

    version = ver_ihl >> 4              # high 4 bits of byte 0
    ihl = ver_ihl & 0x0F                # low 4 bits: header length in 32-bit words
    header_length = ihl * 4             # ... so x4 gives bytes (5 words = 20 bytes)

    if version != 4:
        raise ParseError(f"not IPv4 (version {version})")
    if ihl < 5 or len(data) < header_length:
        raise ParseError(f"bad IPv4 header length {header_length}")

    return {
        "version": version,
        "header_length": header_length,
        "tos": tos,
        "total_length": total_length,             # header + payload, in bytes
        "identification": identification,
        "flags": flags_frag >> 13,                 # top 3 bits: reserved, DF, MF
        "dont_fragment": bool(flags_frag & 0x4000),
        "more_fragments": bool(flags_frag & 0x2000),
        "fragment_offset": flags_frag & 0x1FFF,    # low 13 bits, in 8-byte units
        "ttl": ttl,
        "protocol": protocol,
        "protocol_name": IP_PROTOCOLS.get(protocol, f"Other ({protocol})"),
        "checksum": checksum,
        "src": ipv4_to_str(src),
        "dst": ipv4_to_str(dst),
        "options": data[20:header_length],
    }
