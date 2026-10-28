"""
Demo: what can the server see?

Runs the REAL server (server/server.py, same port and certificates), but
prints every line and every byte the server's code receives AFTER TLS has
been decrypted, i.e. everything the server itself could read or log.

Use two clients and send a private message and a file:
  - LOGIN / REGISTER lines: the server sees them (it must check the password),
    shown here with the password hidden.
  - MSG: the server sees only "E2E:" + base64 ciphertext, not the text.
  - SEND: the server sees only the name "E2E", the size and the bytes of the
    encrypted envelope, not the file name or contents.
  - UPLOAD / DOWNLOAD: stored on the server, so those are readable (they are
    protected by TLS on the network, not end-to-end).

Run instead of the normal server:   python demo/curious_server.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))
import server as srv  # noqa: E402

_recv_line, _recv_exact = srv.recv_line, srv.recv_exact


def short(s, n=70):
    return s if len(s) <= n else f"{s[:n]}... ({len(s)} chars)"


def spy_recv_line(sock):
    fields = _recv_line(sock)
    shown = list(fields)
    if shown and shown[0] in ("LOGIN", "REGISTER") and len(shown) > 2:
        shown[2] = "***"
    print("[server sees] " + short("|".join(shown)), flush=True)
    return fields


def spy_recv_exact(sock, n):
    data = _recv_exact(sock, n)
    print(f"[server sees] {n} payload bytes, first 24: {data[:24]!r}", flush=True)
    return data


srv.recv_line, srv.recv_exact = spy_recv_line, spy_recv_exact

if __name__ == "__main__":
    srv.main()
