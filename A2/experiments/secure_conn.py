"""
Shared helper for the experiment scripts (Assignment 2).

connect_and_login(host, port, user, pw) opens a TCP connection, does the TLS
handshake (trusting only certs/ca.crt, with the server name checked), creates
the account with REGISTER if it does not exist yet, and logs in.
"""

import os
import socket
import ssl
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "client"))
from protocol import send_line, recv_line  # noqa: E402

CA_FILE = os.path.join(ROOT, "certs", "ca.crt")


def connect_tls(host, port):
    raw = socket.create_connection((host, port))
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   # same as the real client
    ctx = ssl.create_default_context(cafile=CA_FILE)
    return ctx.wrap_socket(raw, server_hostname=host)


def connect_and_login(host, port, user, password="pw"):
    sock = connect_tls(host, port)
    send_line(sock, "REGISTER", user, password)
    reply = recv_line(sock)
    if reply[0] != "REGISTER_OK" and reply != ["ERROR", "USER_EXISTS"]:
        raise RuntimeError(f"REGISTER {user} failed: {reply}")
    send_line(sock, "LOGIN", user, password)
    reply = recv_line(sock)
    if reply[0] != "LOGIN_OK":
        raise RuntimeError(f"LOGIN {user} failed: {reply}")
    return sock
