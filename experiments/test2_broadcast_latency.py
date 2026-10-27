"""
Test 2: send a message from one client to 5 other connected clients and
measure the average response (delivery) time.

Each of the 5 receiver threads times the gap between the sender embedding a
send-timestamp in the broadcast text and that receiver's reader loop getting
it, so the result reflects real network + server-relay latency, not just
scheduling jitter of a single thread.

Run:  python test2_broadcast_latency.py [host] [port]
"""

import os
import statistics
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import send_line, recv_line
from secure_conn import connect_and_login

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5050
NUM_RECEIVERS = 5

latencies_ms = []
latencies_lock = threading.Lock()
ready_barrier = threading.Barrier(NUM_RECEIVERS + 1)  # + main thread


def receiver(idx):
    sock = connect_and_login(HOST, PORT, f"latency_rx_{idx}")

    ready_barrier.wait()  # don't listen until every receiver is logged in

    fields = recv_line(sock)  # BROADCAST|sender|<sent_timestamp>
    recv_time = time.perf_counter()
    assert fields[0] == "BROADCAST", fields
    sent_time = float(fields[2])

    with latencies_lock:
        latencies_ms.append((recv_time - sent_time) * 1000)

    send_line(sock, "LOGOUT")
    recv_line(sock)
    sock.close()


def main():
    threads = [threading.Thread(target=receiver, args=(i,)) for i in range(NUM_RECEIVERS)]
    for t in threads:
        t.start()

    sender = connect_and_login(HOST, PORT, "latency_sender")

    ready_barrier.wait()  # wait until all 5 receivers are logged in and listening

    send_line(sender, "BROADCAST", str(time.perf_counter()))
    recv_line(sender)  # BROADCAST_OK

    for t in threads:
        t.join()

    send_line(sender, "LOGOUT")
    recv_line(sender)
    sender.close()

    print(f"Test 2: broadcast delivery latency to {NUM_RECEIVERS} clients (over TLS)")
    print(f"  avg: {statistics.mean(latencies_ms):.3f} ms")
    print(f"  min: {min(latencies_ms):.3f} ms")
    print(f"  max: {max(latencies_ms):.3f} ms")


if __name__ == "__main__":
    main()
