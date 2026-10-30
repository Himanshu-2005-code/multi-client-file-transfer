"""
Packet capture: getting the raw bytes from the operating system.

This part only OBTAINS the bytes; all decoding is done by packet_parser.py.
Each capture object has:
    link_type   what comes before the IP header ("raw" or "ethernet"),
                passed to packet_parser.strip_link_layer()
    read()      waits for the next packet and returns (timestamp, frame_bytes),
                or None if nothing arrived within about a second
    close()

Capturing needs Administrator (Windows) or root (sudo, Mac/Linux).

Used by analyzer.py (run that, not this file).
"""

import collections
import os
import select
import socket
import struct
import subprocess
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


# --- macOS: Berkeley Packet Filter (BPF) device -------------------------------
# ioctl request numbers from macOS <net/bpf.h> (_IOR/_IOW macros, group 'B'):
BIOCGBLEN = 0x40044266      # get the buffer length the kernel uses
BIOCSETIF = 0x8020426C      # attach the device to a network interface (struct ifreq)
BIOCGDLT = 0x4004426A       # get the link type (data link type) of that interface
BIOCIMMEDIATE = 0x80044270  # return packets as soon as they arrive (no batching delay)
DLT_EN10MB = 1              # Ethernet


def parse_bpf_buffer(buf):
    """
    One read() from a BPF device returns SEVERAL packets, each preceded by a
    bpf_hdr record header (macOS, little-endian):

      bytes 0-3   timestamp seconds        bytes 4-7    timestamp microseconds
      bytes 8-11  captured length          bytes 12-15  original length on the wire
      bytes 16-17 length of this bpf_hdr (usually 18)
      then the packet (captured length bytes), then padding to a multiple of 4

    Returns a list of (timestamp, frame_bytes).
    """
    packets = []
    offset = 0
    while offset + 18 <= len(buf):
        sec, usec, caplen, datalen, hdrlen = struct.unpack_from("<IIIIH", buf, offset)
        start = offset + hdrlen
        packets.append((sec + usec / 1e6, bytes(buf[start:start + caplen])))
        # next record starts at the next 4-byte boundary (BPF_WORDALIGN)
        offset += (hdrlen + caplen + 3) & ~3
    return packets


def default_mac_interface():
    """The interface of the default route, e.g. en0 (Wi-Fi on most Macs)."""
    try:
        out = subprocess.run(["route", "-n", "get", "default"], capture_output=True,
                             text=True, timeout=3).stdout
        for line in out.splitlines():
            if line.strip().startswith("interface:"):
                return line.split(":", 1)[1].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "en0"


class MacCapture:
    """
    macOS has no "receive all" raw socket. Packet capture tools (tcpdump,
    Wireshark) use a BPF device /dev/bpfN instead: open a free one, attach it
    to an interface with ioctl(BIOCSETIF), then read() raw frames, each with
    a small BPF record header. We do exactly that with os.open + fcntl.ioctl.
    The frames start with the Ethernet header (Wi-Fi/Ethernet); BIOCGDLT
    confirms that.
    """

    def __init__(self, interface=None):
        import fcntl
        self.interface = interface or default_mac_interface()
        self.fd = None
        for i in range(256):                  # find a BPF device nobody is using
            try:
                self.fd = os.open(f"/dev/bpf{i}", os.O_RDONLY)
                break
            except PermissionError:
                sys.exit("[!] Permission denied: run with sudo.")
            except OSError:                   # busy or does not exist: try the next one
                continue
        if self.fd is None:
            sys.exit("[!] No free /dev/bpf device found.")

        # attach to the interface: struct ifreq = 16-byte name + 16 bytes we don't use
        fcntl.ioctl(self.fd, BIOCSETIF, struct.pack("16s16x", self.interface.encode()))
        fcntl.ioctl(self.fd, BIOCIMMEDIATE, struct.pack("I", 1))
        self.buf_len = struct.unpack("I", fcntl.ioctl(self.fd, BIOCGBLEN, struct.pack("I", 0)))[0]
        dlt = struct.unpack("I", fcntl.ioctl(self.fd, BIOCGDLT, struct.pack("I", 0)))[0]
        if dlt == DLT_EN10MB:
            self.link_type = "ethernet"
        else:
            sys.exit(f"[!] Interface {self.interface} has link type {dlt}, which we do not decode.")
        self.pending = collections.deque()
        self.description = f"macOS BPF on {self.interface} ({self.link_type})"

    def read(self):
        if not self.pending:
            # wait at most 1 s so Ctrl+C and the caller's loop stay responsive
            ready, _, _ = select.select([self.fd], [], [], 1.0)
            if not ready:
                return None
            self.pending.extend(parse_bpf_buffer(os.read(self.fd, self.buf_len)))
            if not self.pending:
                return None
        return self.pending.popleft()

    def close(self):
        os.close(self.fd)


# --- Linux: packet socket ------------------------------------------------------
ETH_P_ALL = 0x0003          # "all protocols" (from <linux/if_ether.h>)
ARPHRD_ETHER, ARPHRD_LOOPBACK, ARPHRD_NONE = 1, 772, 65534


def default_linux_interface():
    """The interface of the default route (destination 00000000 in /proc/net/route)."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.split()
                if fields[1] == "00000000":
                    return fields[0]
    except OSError:
        pass
    return "lo"


class LinuxCapture:
    """
    Linux: an AF_PACKET raw socket receives a copy of every frame on an
    interface, sent or received, starting at the link-layer header: a 14-byte
    Ethernet header (VPN-style interfaces give raw IP).
    """

    def __init__(self, interface=None):
        self.interface = interface or default_linux_interface()
        try:
            # socket.htons: the protocol number must be in network byte order
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError:
            sys.exit("[!] Permission denied: run with sudo.")
        self.sock.bind((self.interface, 0))
        with open(f"/sys/class/net/{self.interface}/type") as f:
            hw_type = int(f.read())
        self.link_type = "raw" if hw_type == ARPHRD_NONE else "ethernet"
        self.sock.settimeout(1.0)
        self.description = f"Linux packet socket on {self.interface} ({self.link_type})"

    def read(self):
        try:
            data = self.sock.recv(65535)
        except socket.timeout:
            return None
        return time.time(), data

    def close(self):
        self.sock.close()


def open_capture(local_ip=None, interface=None):
    """Open the capture method for this operating system."""
    if sys.platform == "win32":
        return WindowsCapture(local_ip)
    if sys.platform == "darwin":
        return MacCapture(interface)
    if sys.platform.startswith("linux"):
        return LinuxCapture(interface)
    sys.exit(f"[!] Capture on {sys.platform} is not supported.")
