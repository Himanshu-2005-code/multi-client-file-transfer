"""
Tests for capture.py that need no admin rights and no real interface:
splitting a macOS BPF read buffer into packets, and the Windows and macOS
capture classes run against FAKE operating-system calls (so their logic is
checked on any computer; the real runs are done on Windows and on a Mac).

Run:  python tests/test_capture.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import capture  # noqa: E402
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


UDP_PKT = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 32, 1, 0, 64, 17, 0, bytes([192, 168, 1, 10]),
                      bytes([8, 8, 8, 8])) + bytes.fromhex("d6d80035000c1234") + b"abcd"


def test_windows_capture_with_fake_socket():
    calls = []

    class FakeTimeout(Exception):
        pass

    class FakeSock:
        def __init__(self, *args):
            calls.append(("socket", args))
            self.queue = [UDP_PKT]

        def bind(self, addr):
            calls.append(("bind", addr))

        def setsockopt(self, *args):
            calls.append(("setsockopt", args))

        def ioctl(self, *args):
            calls.append(("ioctl", args))

        def settimeout(self, t):
            pass

        def recv(self, n):
            if self.queue:
                return self.queue.pop(0)
            raise FakeTimeout()

        def close(self):
            calls.append(("close",))

    class FakeSocketModule:
        AF_INET, SOCK_RAW, IPPROTO_IP, IP_HDRINCL = 2, 3, 0, 2
        SIO_RCVALL, RCVALL_ON, RCVALL_OFF = 0x98000001, 1, 0
        timeout = FakeTimeout
        socket = FakeSock

    real = capture.socket
    capture.socket = FakeSocketModule
    try:
        cap = capture.WindowsCapture("192.168.1.10")
        got = cap.read()
        nothing = cap.read()
        cap.close()
    finally:
        capture.socket = real
    check("Windows: raw IPv4 socket opened", ("socket", (2, 3, 0)) in calls)
    check("Windows: bound to the interface IP", ("bind", ("192.168.1.10", 0)) in calls)
    check("Windows: IP_HDRINCL set", ("setsockopt", (0, 2, 1)) in calls)
    check("Windows: receive-all switched on, then off",
          ("ioctl", (0x98000001, 1)) in calls and ("ioctl", (0x98000001, 0)) in calls)
    check("Windows: read() returns (timestamp, packet); link type raw",
          got[1] == UDP_PKT and got[0] > 0 and cap.link_type == "raw")
    check("Windows: read() returns None after a timeout", nothing is None)


def test_mac_capture_with_fake_bpf():
    import types
    calls = []
    eth_frame = bytes.fromhex("aabbccddeeff1122334455660800") + UDP_PKT
    buffer = bpf_record(1761800000, 0, eth_frame) + bpf_record(1761800001, 0, eth_frame)

    def fake_ioctl(fd, request, arg):
        calls.append((request, arg))
        if request == capture.BIOCGBLEN:
            return struct.pack("I", 4096)
        if request == capture.BIOCGDLT:
            return struct.pack("I", capture.DLT_EN10MB)
        return arg

    opened = []

    def fake_open(path, flags):
        if path == "/dev/bpf0":
            raise OSError("busy")            # first device in use: try the next one
        opened.append(path)
        return 99

    reads = [buffer]
    saved = (capture.os.open, capture.os.read, capture.os.close, capture.select.select,
             sys.modules.get("fcntl"))
    capture.os.open = fake_open
    capture.os.read = lambda fd, n: reads.pop(0)
    capture.os.close = lambda fd: None
    capture.select.select = lambda r, w, x, t: (r, [], []) if reads else ([], [], [])
    sys.modules["fcntl"] = types.SimpleNamespace(ioctl=fake_ioctl)
    try:
        cap = capture.MacCapture("en0")
        first, second, third = cap.read(), cap.read(), cap.read()
        cap.close()
    finally:
        capture.os.open, capture.os.read, capture.os.close, capture.select.select, fcntl = saved
        if fcntl is None:
            sys.modules.pop("fcntl", None)
        else:
            sys.modules["fcntl"] = fcntl
    check("Mac: busy /dev/bpf0 skipped, /dev/bpf1 used", opened == ["/dev/bpf1"])
    check("Mac: attached to en0 with BIOCSETIF",
          (capture.BIOCSETIF, struct.pack("16s16x", b"en0")) in calls)
    check("Mac: immediate mode set", (capture.BIOCIMMEDIATE, struct.pack("I", 1)) in calls)
    check("Mac: link type Ethernet from BIOCGDLT", cap.link_type == "ethernet")
    check("Mac: one read() buffer gives two packets in turn",
          first[1] == eth_frame and second[1] == eth_frame and second[0] == 1761800001)
    check("Mac: read() returns None when nothing arrives", third is None)


def test_mac_ioctl_numbers():
    # The request numbers are built by the _IOR / _IOW macros of <sys/ioccom.h>:
    #   direction (OUT 0x40000000 / IN 0x80000000) | size of the argument << 16 | 'B' << 8 | number
    def ioc(direction, size, number):
        return direction | (size << 16) | (ord("B") << 8) | number
    OUT, IN = 0x40000000, 0x80000000
    check("BIOCGBLEN = _IOR('B', 102, u_int)", capture.BIOCGBLEN == ioc(OUT, 4, 102))
    check("BIOCSETIF = _IOW('B', 108, struct ifreq of 32 bytes)", capture.BIOCSETIF == ioc(IN, 32, 108))
    check("BIOCGDLT = _IOR('B', 106, u_int)", capture.BIOCGDLT == ioc(OUT, 4, 106))
    check("BIOCIMMEDIATE = _IOW('B', 112, u_int)", capture.BIOCIMMEDIATE == ioc(IN, 4, 112))


if __name__ == "__main__":
    test_bpf_buffer()
    test_mac_ioctl_numbers()
    test_windows_capture_with_fake_socket()
    test_mac_capture_with_fake_bpf()
    print("\nALL CAPTURE TESTS PASSED" if failures == 0 else f"\n{failures} TEST(S) FAILED")
    sys.exit(1 if failures else 0)
