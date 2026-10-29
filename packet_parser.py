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


# TCP flag bits in byte 13, highest bit first: the "C E U A P R S F" row of the
# lecture slide (L13, "TCP segment structure").
TCP_FLAGS = [(0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"), (0x10, "ACK"),
             (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")]


def parse_tcp(segment):
    """
    Decode a TCP segment: `segment` is the IP payload (bytes after the IP header).

    Layout (RFC 793; lecture L13, "TCP segment structure"):

      bytes 0-1   source port          bytes 2-3   destination port
      bytes 4-7   sequence number
      bytes 8-11  acknowledgment number
      byte 12     header length (high 4 bits, in 32-bit words) | reserved
      byte 13     flags: CWR ECE URG ACK PSH RST SYN FIN (one bit each)
      bytes 14-15 receive window (rwnd)
      bytes 16-17 checksum             bytes 18-19 urgent pointer
      options (if header length > 20), then the application data (payload)
    """
    if len(segment) < 20:
        raise ParseError(f"TCP header needs at least 20 bytes, got {len(segment)}")

    # H = 2 bytes, I = 4 bytes, B = 1 byte: 2+2+4+4+1+1+2+2+2 = 20 bytes
    (src_port, dst_port, seq, ack, offset_byte, flags,
     window, checksum, urgent) = struct.unpack("!HHIIBBHHH", segment[:20])

    header_length = (offset_byte >> 4) * 4     # "data offset": 32-bit words -> bytes
    if header_length < 20 or len(segment) < header_length:
        raise ParseError(f"bad TCP header length {header_length}")

    payload = segment[header_length:]
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "header_length": header_length,
        "flags": flags,
        "flag_names": [name for bit, name in TCP_FLAGS if flags & bit],
        "window": window,
        "checksum": checksum,
        "urgent_pointer": urgent,
        "options": segment[20:header_length],
        "payload": payload,
        "payload_length": len(payload),
    }


def parse_udp(datagram):
    """
    Decode a UDP datagram: `datagram` is the IP payload (bytes after the IP header).

    Layout (RFC 768): four 2-byte fields, 8 bytes in total.
      bytes 0-1 source port      bytes 2-3 destination port
      bytes 4-5 length (UDP header + data, in bytes)
      bytes 6-7 checksum
      then the application data (payload)
    """
    if len(datagram) < 8:
        raise ParseError(f"UDP header needs 8 bytes, got {len(datagram)}")

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", datagram[:8])
    if length < 8:
        raise ParseError(f"bad UDP length {length}")

    # The length field says where the data ends; never read past what we have.
    payload = datagram[8:length]
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
        "payload": payload,
        "payload_length": len(payload),
    }


def parse_packet(data):
    """
    Decode a whole IPv4 packet (bytes starting at the IP header).

    The IP "protocol" field decides automatically what comes next:
    6 -> parse_tcp, 17 -> parse_udp, anything else is left undecoded.
    Returns {"ip": ..., "transport": "TCP" / "UDP" / None, "tcp" or "udp": ...}.
    """
    ip = parse_ipv4(data)
    # The IP payload runs from the end of the IP header to "total length".
    # Bytes after total length are link-layer padding (Ethernet pads small
    # frames to 60 bytes), not part of the packet.
    end = min(ip["total_length"], len(data))
    ip_payload = data[ip["header_length"]:end]
    packet = {"ip": ip, "transport": None, "ip_payload": ip_payload}

    if ip["fragment_offset"] != 0:
        # A later fragment of a split datagram: it starts in the middle of
        # the TCP/UDP data, so there is no transport header to decode.
        return packet
    if ip["protocol"] == 6:
        packet["transport"] = "TCP"
        packet["tcp"] = parse_tcp(ip_payload)
    elif ip["protocol"] == 17:
        packet["transport"] = "UDP"
        packet["udp"] = parse_udp(ip_payload)
    return packet


# ---------------------------------------------------------------------------
# What comes BEFORE the IP header depends on how the bytes were captured
# (encapsulation, lecture slides: frame = [link header | datagram]):
#   "raw"      Windows raw socket: the bytes start directly at the IP header
#   "ethernet" Mac (Wi-Fi / Ethernet) and Linux: 14-byte Ethernet header first
#   "null"     Mac loopback (lo0, 127.0.0.1): 4-byte address-family header first
# ---------------------------------------------------------------------------

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN"}


def mac_to_str(six_bytes):
    return ":".join(f"{b:02x}" for b in six_bytes)


def strip_link_layer(frame, link_type):
    """
    Remove the link-layer header and return (ip_bytes, link_info).
    ip_bytes is None when the frame does not carry IPv4 (e.g. IPv6, ARP);
    link_info["skip_reason"] then says why.
    """
    if link_type == "raw":
        return frame, {"type": "raw"}

    if link_type == "null":
        # 4-byte address family, in the sending machine's byte order
        # (little-endian on Macs). AF_INET = 2 means IPv4.
        if len(frame) < 4:
            return None, {"type": "null", "skip_reason": "frame too short"}
        family = struct.unpack("<I", frame[:4])[0]
        if family != 2:
            return None, {"type": "null", "skip_reason": f"not IPv4 (address family {family})"}
        return frame[4:], {"type": "null"}

    if link_type == "ethernet":
        # destination MAC (6 bytes) | source MAC (6) | EtherType (2)
        if len(frame) < 14:
            return None, {"type": "ethernet", "skip_reason": "frame too short"}
        dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", frame[:14])
        offset = 14
        if ethertype == ETHERTYPE_VLAN and len(frame) >= 18:
            # 802.1Q VLAN tag: 4 extra bytes, the real EtherType is in the last 2
            ethertype = struct.unpack("!H", frame[16:18])[0]
            offset = 18
        info = {"type": "ethernet", "src_mac": mac_to_str(src_mac), "dst_mac": mac_to_str(dst_mac),
                "ethertype": ethertype}
        if ethertype != ETHERTYPE_IPV4:
            name = ETHERTYPES.get(ethertype, f"0x{ethertype:04x}")
            info["skip_reason"] = f"not IPv4 (EtherType {name})"
            return None, info
        return frame[offset:], info

    raise ValueError(f"unknown link type {link_type!r}")
