"""
Test 4 (Assignment 2): secure file transfer of 100 KB, 1 MB and 10 MB files.

For each size, over TLS and with SHA-256 integrity checks:
  1. upload    alice -> server       (server verifies the digest)
  2. download  server -> bob         (bob verifies the digest recorded at upload)
  3. send      alice -> server -> bob (server verifies, then bob verifies)
Prints the time and throughput of each transfer and whether integrity passed.

Run (server must be running):  python experiments/test4_secure_transfer.py [host] [port]
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secure_conn import connect_and_login  # noqa: E402
from protocol import send_line, recv_line, recv_exact, send_exact, sha256_hex  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5050
SIZES = [("100KB", 100 * 1024), ("1MB", 1024 * 1024), ("10MB", 10 * 1024 * 1024)]


def mbps(nbytes, seconds):
    return nbytes / (1024 * 1024) / seconds if seconds > 0 else float("inf")


def main():
    alice = connect_and_login(HOST, PORT, "test4_alice")
    bob = connect_and_login(HOST, PORT, "test4_bob")
    print(f"Test 4: secure transfers over TLS ({alice.version()}, {alice.cipher()[0]})")
    print(f"{'size':>6} | {'transfer':<24} | {'time':>9} | {'MB/s':>7} | integrity")
    print("-" * 66)

    all_ok = True
    for label, size in SIZES:
        data = os.urandom(size)
        digest = sha256_hex(data)                      # computed before sending
        name = f"test4_{label}.bin"

        # 1. upload: the server recomputes and compares
        t = time.perf_counter()
        send_line(alice, "UPLOAD", name, size, digest)
        recv_line(alice)                               # READY
        send_exact(alice, data)
        reply = recv_line(alice)
        up_time = time.perf_counter() - t
        up_ok = reply[0] == "UPLOAD_OK"

        # 2. download: bob recomputes and compares with the recorded digest
        t = time.perf_counter()
        send_line(bob, "DOWNLOAD", name)
        header = recv_line(bob)
        got = recv_exact(bob, int(header[2]))
        down_time = time.perf_counter() - t
        down_ok = header[0] == "DOWNLOAD_OK" and sha256_hex(got) == header[3] == digest

        # 3. send alice -> bob: the server checks, then bob checks
        t = time.perf_counter()
        send_line(alice, "SEND", "test4_bob", name, size, digest)
        recv_line(alice)                               # READY
        send_exact(alice, data)
        incoming = recv_line(bob)                      # SEND_INCOMING|name|sender|size|sha256
        got = recv_exact(bob, int(incoming[3]))
        send_time = time.perf_counter() - t
        send_ok = (recv_line(alice)[0] == "SEND_OK"
                   and sha256_hex(got) == incoming[4] == digest)

        for what, secs, ok in (("upload alice->server", up_time, up_ok),
                               ("download server->bob", down_time, down_ok),
                               ("send alice->server->bob", send_time, send_ok)):
            all_ok &= ok
            print(f"{label:>6} | {what:<24} | {secs * 1000:7.1f} ms | {mbps(size, secs):7.1f} | "
                  f"{'PASS' if ok else 'FAIL'}")

    print("-" * 66)
    print(f"SHA-256 of every file: {'all transfers verified' if all_ok else 'SOME TRANSFERS FAILED'}")
    for s in (alice, bob):
        send_line(s, "LOGOUT")
        recv_line(s)
        s.close()


if __name__ == "__main__":
    main()
