"""
Packet capture: getting the raw bytes from the operating system.

This part only OBTAINS the bytes; all decoding is done by packet_parser.py.
Each capture object has:
    link_type   what comes before the IP header ("raw", "ethernet", "null"),
                passed to packet_parser.strip_link_layer()
    read()      waits for the next packet and returns (timestamp, frame_bytes),
                or None if nothing arrived within about a second
    close()

Capturing needs Administrator (Windows) or root (sudo, Mac/Linux).

Quick test:  python capture.py 10      (captures 10 packets and prints them)
"""

import socket
import sys
import time


def default_local_ip():
    """
    The IP address of the interface that leads to the internet. Connecting a
    UDP socket sends no packet; it only makes the OS choose a route, and
    getsockname() then tells us our address on that route.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class WindowsCapture:
    """
    Windows: a raw IPv4 socket bound to one local interface, switched to
    "receive all" mode with the SIO_RCVALL ioctl. It then receives a copy of
    every IPv4 packet sent or received on that interface, starting at the IP
    header (Windows gives no Ethernet header), so link_type is "raw".
    """
    link_type = "raw"

    def __init__(self, local_ip=None):
        self.local_ip = local_ip or default_local_ip()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        except PermissionError:
            sys.exit("[!] Permission denied: run this from an Administrator terminal.")
        self.sock.bind((self.local_ip, 0))
        # Packets we receive include their IP header.
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Receive ALL packets on this interface, not only those for this socket.
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        # Wake up every second so Ctrl+C works on Windows.
        self.sock.settimeout(1.0)
        self.description = f"Windows raw socket on {self.local_ip}"

    def read(self):
        try:
            data = self.sock.recv(65535)        # one whole IP packet per call
        except socket.timeout:
            return None
        return time.time(), data

    def close(self):
        try:
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        finally:
            self.sock.close()


def open_capture(local_ip=None):
    """Open the capture method for this operating system."""
    if sys.platform == "win32":
        return WindowsCapture(local_ip)
    sys.exit(f"[!] Capture on {sys.platform} is not supported yet.")


def _quick_test(count):
    from datetime import datetime
    from packet_parser import ParseError, parse_packet, strip_link_layer

    cap = open_capture()
    print(f"Capturing {count} packets ({cap.description}). Ctrl+C to stop.")
    n = 0
    try:
        while n < count:
            got = cap.read()
            if got is None:
                continue
            ts, frame = got
            ip_bytes, link = strip_link_layer(frame, cap.link_type)
            if ip_bytes is None:
                continue
            n += 1
            when = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
            try:
                p = parse_packet(ip_bytes)
            except ParseError as e:
                print(f"{n:4} {when} {len(frame):5} bytes  (could not decode: {e})")
                continue
            ip = p["ip"]
            t = p.get("tcp") or p.get("udp")
            ports = f"{t['src_port']} -> {t['dst_port']}" if t else ""
            print(f"{n:4} {when} {len(frame):5} bytes  {ip['src']:>15} -> {ip['dst']:<15} "
                  f"{ip['protocol_name']:<5} {ports}")
    except KeyboardInterrupt:
        pass
    finally:
        cap.close()


if __name__ == "__main__":
    _quick_test(int(sys.argv[1]) if len(sys.argv) > 1 else 10)
