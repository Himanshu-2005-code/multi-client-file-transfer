"""
Test 1: 1 client sends a request to the server and receives a response.
Measures round-trip time (RTT) over N repetitions using LIST as the
request/response pair (cheapest command that guarantees an immediate reply).

Run:  python test1_rtt.py [host] [port] [repetitions]
"""

import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import send_line, recv_line
from secure_conn import connect_and_login

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5050
REPS = int(sys.argv[3]) if len(sys.argv) > 3 else 100


def main():
    # TLS handshake and login happen before timing starts: RTT measures
    # one encrypted request/response, not the connection setup.
    sock = connect_and_login(HOST, PORT, "rtt_test_user")

    rtts_ms = []
    for _ in range(REPS):
        start = time.perf_counter()
        send_line(sock, "LIST")
        recv_line(sock)
        end = time.perf_counter()
        rtts_ms.append((end - start) * 1000)

    send_line(sock, "LOGOUT")
    recv_line(sock)
    sock.close()

    print(f"Test 1: RTT over {REPS} requests (over TLS)")
    print(f"  min:    {min(rtts_ms):.3f} ms")
    print(f"  avg:    {statistics.mean(rtts_ms):.3f} ms")
    print(f"  median: {statistics.median(rtts_ms):.3f} ms")
    print(f"  max:    {max(rtts_ms):.3f} ms")


if __name__ == "__main__":
    main()
