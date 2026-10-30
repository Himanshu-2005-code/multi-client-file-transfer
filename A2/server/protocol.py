"""
Wire-format helpers.

Every control message is one line of UTF-8 text terminated by '\n':

    COMMAND|FIELD1|FIELD2|...

Fields are separated by '|' and must not themselves contain '|' or '\n'.

A file payload is sent as raw bytes with NO delimiter of its own -- the
control line right before it always announces the exact byte count, so the
reader knows precisely how many bytes to pull off the socket.
"""

import hashlib
import socket

ENCODING = "utf-8"
DELIM = "|"


def send_line(sock: socket.socket, *fields) -> None:
    """Send one control message: fields joined by '|', terminated by '\n'."""
    line = DELIM.join(str(f) for f in fields) + "\n"
    sock.sendall(line.encode(ENCODING))


def recv_line(sock: socket.socket):
    """
    Block until one '\n'-terminated control message arrives, and return it
    split on '|' (a list of strings). Raises ConnectionError if the peer
    closes the socket before a full line arrives.
    """
    chunks = []
    while True:
        b = sock.recv(1)
        if not b:
            if chunks:
                raise ConnectionError("connection closed mid-message")
            raise ConnectionError("connection closed")
        if b == b"\n":
            break
        chunks.append(b)
    line = b"".join(chunks).decode(ENCODING)
    return line.split(DELIM)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Block until exactly n bytes have been received."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("connection closed during file transfer")
        buf.extend(chunk)
    return bytes(buf)


def send_exact(sock: socket.socket, data: bytes) -> None:
    sock.sendall(data)


def sha256_hex(data: bytes) -> str:
    """
    Cryptographic digest (fingerprint) of the file contents: 64 hex chars.
    Changing even one bit of the data gives a completely different value.
    Sent next to a file and recomputed after reception to check integrity.
    """
    return hashlib.sha256(data).hexdigest()
