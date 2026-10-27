"""
End-to-end protocol test.

Starts a real server instance as a subprocess, drives it with plain sockets
(bypassing the interactive client's input() prompts), and checks every
command and error path defined in docs/protocol_spec.md.

Run:  python tests/test_protocol.py
"""

import os
import shutil
import socket
import ssl
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "client"))
from protocol import send_line, recv_line, recv_exact, send_exact

HOST, PORT = "127.0.0.1", 5098
CA_FILE = os.path.join(ROOT, "certs", "ca.crt")


def connect():
    """TCP connect, then TLS handshake, trusting only our own CA."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    ctx = ssl.create_default_context(cafile=CA_FILE)
    return ctx.wrap_socket(s, server_hostname=HOST)


def check(label, cond):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {label}")
    if not cond:
        raise SystemExit(1)


def wait_for_server(timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect((HOST, PORT))
            s.close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("server did not start in time")


def run_checks():
    # --- login two users ---
    alice = connect()
    send_line(alice, "LOGIN", "alice", "pw1")
    r = recv_line(alice)
    check("alice login", r[0] == "LOGIN_OK")

    bob = connect()
    send_line(bob, "LOGIN", "bob", "pw2")
    r = recv_line(bob)
    check("bob login", r[0] == "LOGIN_OK")

    # duplicate username rejected
    dup = connect()
    send_line(dup, "LOGIN", "alice", "whatever")
    r = recv_line(dup)
    check("duplicate username rejected", r[0] == "ERROR" and r[1] == "USER_ALREADY_ONLINE")
    dup.close()

    # wrong password rejected (must test while alice is NOT online, otherwise
    # the "already online" check fires first)
    send_line(alice, "LOGOUT")
    r = recv_line(alice)
    check("alice logout (for wrong-password test)", r[0] == "LOGOUT_OK")
    alice.close()

    wrongpw = connect()
    send_line(wrongpw, "LOGIN", "alice", "wrongpw")
    r = recv_line(wrongpw)
    check("wrong password rejected", r[0] == "ERROR" and r[1] == "AUTH_FAILED")
    wrongpw.close()

    alice = connect()
    send_line(alice, "LOGIN", "alice", "pw1")
    r = recv_line(alice)
    check("alice re-login", r[0] == "LOGIN_OK")

    # --- list ---
    send_line(alice, "LIST")
    r = recv_line(alice)
    check("list contains alice and bob", r[0] == "USERS" and "alice" in r[1] and "bob" in r[1])

    # --- allusers (online + offline) ---
    dupattempt = connect()
    send_line(dupattempt, "LOGIN", "charlie", "pw3")
    r = recv_line(dupattempt)
    check("charlie login (then goes offline)", r[0] == "LOGIN_OK")
    send_line(dupattempt, "LOGOUT")
    recv_line(dupattempt)
    dupattempt.close()

    send_line(alice, "ALLUSERS")
    r = recv_line(alice)
    entries = dict(e.split(":") for e in r[1].split(","))
    check("allusers lists alice as online", entries.get("alice") == "online")
    check("allusers lists charlie as offline", entries.get("charlie") == "offline")

    # --- private message ---
    send_line(alice, "MSG", "bob", "hello bob")
    r_ok = recv_line(alice)
    check("msg ok reply", r_ok[0] == "MSG_OK")
    r_push = recv_line(bob)
    check("bob received msg", r_push[0] == "MSG" and r_push[1] == "alice" and r_push[2] == "hello bob")

    # --- broadcast ---
    send_line(bob, "BROADCAST", "hi everyone")
    r_ok = recv_line(bob)
    check("broadcast ok reply", r_ok[0] == "BROADCAST_OK")
    r_push = recv_line(alice)
    check("alice received broadcast", r_push[0] == "BROADCAST" and r_push[1] == "bob")

    # --- upload / download ---
    payload = b"hello world file contents" * 100
    send_line(alice, "UPLOAD", "test.txt", len(payload))
    r = recv_line(alice)
    check("upload ready", r[0] == "READY")
    send_exact(alice, payload)
    r = recv_line(alice)
    check("upload ok", r[0] == "UPLOAD_OK")

    send_line(bob, "DOWNLOAD", "test.txt")
    r = recv_line(bob)
    check("download ok header", r[0] == "DOWNLOAD_OK" and int(r[2]) == len(payload))
    data = recv_exact(bob, int(r[2]))
    check("downloaded bytes match", data == payload)

    send_line(bob, "DOWNLOAD", "doesnotexist.txt")
    r = recv_line(bob)
    check("download missing file errors", r[0] == "ERROR" and r[1] == "FILE_NOT_FOUND")

    # --- files listing ---
    send_line(bob, "FILES")
    r = recv_line(bob)
    check("files lists uploaded file", r[0] == "FILES" and "test.txt" in r[1].split(","))

    # --- send (client to client relay) ---
    send_payload = b"direct send payload" * 50
    send_line(alice, "SEND", "bob", "direct.bin", len(send_payload))
    r = recv_line(alice)
    check("send ready", r[0] == "READY")
    send_exact(alice, send_payload)
    r = recv_line(alice)
    check("send ok", r[0] == "SEND_OK")

    r = recv_line(bob)
    check("bob got send_incoming header", r[0] == "SEND_INCOMING" and r[1] == "direct.bin" and r[2] == "alice")
    data = recv_exact(bob, int(r[3]))
    check("bob received correct bytes", data == send_payload)

    # send to offline user
    send_line(alice, "SEND", "nobody", "x.txt", 3)
    r = recv_line(alice)
    check("send to offline user errors", r[0] == "ERROR" and r[1] == "USER_NOT_FOUND")

    # --- logout ---
    send_line(alice, "LOGOUT")
    r = recv_line(alice)
    check("alice logout ok", r[0] == "LOGOUT_OK")

    send_line(bob, "LOGOUT")
    r = recv_line(bob)
    check("bob logout ok", r[0] == "LOGOUT_OK")

    print("\nALL CHECKS PASSED")


def main():
    if not os.path.isfile(CA_FILE):
        subprocess.run([sys.executable, os.path.join(ROOT, "certs", "gen_certs.py")], check=True)

    server_dir = os.path.join(ROOT, "server")
    users_file = os.path.join(server_dir, "users.txt")
    storage_dir = os.path.join(server_dir, "storage")

    # start from a clean slate so re-runs are deterministic
    if os.path.exists(users_file):
        os.remove(users_file)
    if os.path.exists(storage_dir):
        shutil.rmtree(storage_dir)

    proc = subprocess.Popen(
        [sys.executable, "server.py", HOST, str(PORT)],
        cwd=server_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        wait_for_server()
        run_checks()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(users_file):
            os.remove(users_file)
        if os.path.exists(storage_dir):
            shutil.rmtree(storage_dir)


if __name__ == "__main__":
    main()
