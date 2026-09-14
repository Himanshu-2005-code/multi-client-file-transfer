"""
Test 3: 10 clients download a file from the server concurrently; measure
server throughput (total bytes served / wall-clock time) at different file
sizes.

Run:
  python test3_throughput.py [host] [port] [size_mb] [num_clients]

Example (assignment asks for 1, 100, 1000 MB):
  python test3_throughput.py 127.0.0.1 5050 1
  python test3_throughput.py 127.0.0.1 5050 100
  python test3_throughput.py 127.0.0.1 5050 1000
"""

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))
from protocol import send_line, recv_line, recv_exact, send_exact

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5050
SIZE_MB = int(sys.argv[3]) if len(sys.argv) > 3 else 1
NUM_CLIENTS = int(sys.argv[4]) if len(sys.argv) > 4 else 10

FILENAME = f"throughput_test_{SIZE_MB}mb.bin"
FILESIZE = SIZE_MB * 1024 * 1024

bytes_received = [0] * NUM_CLIENTS
ready_barrier = threading.Barrier(NUM_CLIENTS + 1)


def seed_file():
    """Upload a random file of the target size once, so all clients can
    download the same thing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    send_line(sock, "LOGIN", "throughput_seeder", "pw")
    recv_line(sock)

    send_line(sock, "UPLOAD", FILENAME, FILESIZE)
    recv_line(sock)  # READY

    chunk = os.urandom(1024 * 1024)
    remaining = FILESIZE
    while remaining > 0:
        n = min(len(chunk), remaining)
        send_exact(sock, chunk[:n])
        remaining -= n
    recv_line(sock)  # UPLOAD_OK

    send_line(sock, "LOGOUT")
    recv_line(sock)
    sock.close()


def downloader(idx):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    send_line(sock, "LOGIN", f"throughput_client_{idx}", "pw")
    recv_line(sock)

    ready_barrier.wait()  # all clients issue DOWNLOAD at (about) the same time

    send_line(sock, "DOWNLOAD", FILENAME)
    header = recv_line(sock)
    if header[0] != "DOWNLOAD_OK":
        print(f"client {idx}: download failed: {header}")
        sock.close()
        return
    size = int(header[2])
    recv_exact(sock, size)
    bytes_received[idx] = size

    send_line(sock, "LOGOUT")
    recv_line(sock)
    sock.close()


def main():
    print(f"Seeding {SIZE_MB} MB test file...")
    seed_file()

    threads = [threading.Thread(target=downloader, args=(i,)) for i in range(NUM_CLIENTS)]
    for t in threads:
        t.start()

    ready_barrier.wait()
    start = time.perf_counter()

    for t in threads:
        t.join()

    elapsed = time.perf_counter() - start
    total_bytes = sum(bytes_received)
    total_mb = total_bytes / (1024 * 1024)
    throughput = total_mb / elapsed if elapsed > 0 else float("inf")

    print(f"Test 3: {NUM_CLIENTS} concurrent clients downloading {SIZE_MB} MB each")
    print(f"  total transferred: {total_mb:.2f} MB")
    print(f"  elapsed:           {elapsed:.3f} s")
    print(f"  server throughput: {throughput:.2f} MB/s")


if __name__ == "__main__":
    main()
