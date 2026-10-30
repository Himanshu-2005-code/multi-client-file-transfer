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
from protocol import send_line, recv_line, recv_exact, send_exact, sha256_hex

HOST, PORT = "127.0.0.1", 5098
CA_FILE = os.path.join(ROOT, "certs", "ca.crt")


def connect():
    """TCP connect, then TLS handshake, trusting only our own CA."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   # same as the real client
    s.connect((HOST, PORT))
    ctx = ssl.create_default_context(cafile=CA_FILE)
    return ctx.wrap_socket(s, server_hostname=HOST)


def check(label, cond):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {label}")
    if not cond:
        raise SystemExit(1)


def wait_for_server(timeout=5.0, port=PORT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect((HOST, port))
            s.close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("server did not start in time")


def run_checks():
    # --- registration ---
    reg = connect()
    for name, pw in (("alice", "pw1"), ("bob", "pw2"), ("charlie", "pw3")):
        send_line(reg, "REGISTER", name, pw)
        r = recv_line(reg)
        check(f"register {name}", r[0] == "REGISTER_OK" and r[1] == name)
    send_line(reg, "REGISTER", "alice", "other")
    r = recv_line(reg)
    check("registering a taken name rejected", r == ["ERROR", "USER_EXISTS"])
    send_line(reg, "REGISTER", "bad,name", "x")
    r = recv_line(reg)
    check("invalid username rejected", r == ["ERROR", "BAD_USERNAME"])
    reg.close()

    users_txt = open(os.path.join(ROOT, "server", "users.txt"), encoding="utf-8").read()
    check("users.txt holds no plaintext passwords",
          all(pw not in users_txt for pw in ("pw1", "pw2", "pw3")) and users_txt.count("$") == 3)

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

    unknown = connect()
    send_line(unknown, "LOGIN", "mallory", "pw1")
    r = recv_line(unknown)
    check("login as an unregistered user rejected", r == ["ERROR", "AUTH_FAILED"])
    unknown.close()

    guesser = connect()
    replies = []
    for guess in ("a", "b", "c"):
        send_line(guesser, "LOGIN", "alice", guess)
        replies.append(recv_line(guesser))
    check("every wrong password rejected", replies == [["ERROR", "AUTH_FAILED"]] * 3)
    guesser.close()

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
    send_line(alice, "UPLOAD", "test.txt", len(payload), sha256_hex(payload))
    r = recv_line(alice)
    check("upload ready", r[0] == "READY")
    send_exact(alice, payload)
    r = recv_line(alice)
    check("upload ok (digest matches)", r[0] == "UPLOAD_OK")
    with open(os.path.join(ROOT, "server", "digests", "test.txt.sha256")) as f:
        check("server recorded the verified digest", f.read().strip() == sha256_hex(payload))

    # digest of the original, but one byte changed on the way
    corrupted = b"X" + payload[1:]
    send_line(alice, "UPLOAD", "corrupt.txt", len(corrupted), sha256_hex(payload))
    recv_line(alice)                                   # READY
    send_exact(alice, corrupted)
    r = recv_line(alice)
    check("upload with wrong digest rejected", r == ["ERROR", "INTEGRITY_FAIL"])
    check("corrupted upload not stored",
          not os.path.exists(os.path.join(ROOT, "server", "storage", "corrupt.txt")))

    send_line(alice, "UPLOAD", "nodigest.txt", 3)
    r = recv_line(alice)
    check("upload without a digest rejected", r == ["ERROR", "BAD_ARGS"])

    send_line(bob, "DOWNLOAD", "test.txt")
    r = recv_line(bob)
    check("download ok header", r[0] == "DOWNLOAD_OK" and int(r[2]) == len(payload))
    data = recv_exact(bob, int(r[2]))
    check("downloaded bytes match", data == payload)
    check("download carries the recorded digest, and it verifies",
          len(r) == 4 and r[3] == sha256_hex(payload) == sha256_hex(data))

    # modify the stored file on the server's disk after upload
    stored = os.path.join(ROOT, "server", "storage", "test.txt")
    with open(stored, "r+b") as f:
        f.write(b"Z")
    send_line(bob, "DOWNLOAD", "test.txt")
    r = recv_line(bob)
    data = recv_exact(bob, int(r[2]))
    check("file modified on the server is detected on download",
          r[3] == sha256_hex(payload) and sha256_hex(data) != r[3])
    with open(stored, "wb") as f:          # put the original back
        f.write(payload)

    send_line(bob, "DOWNLOAD", "doesnotexist.txt")
    r = recv_line(bob)
    check("download missing file errors", r[0] == "ERROR" and r[1] == "FILE_NOT_FOUND")

    # --- files listing ---
    send_line(bob, "FILES")
    r = recv_line(bob)
    check("files lists uploaded file", r[0] == "FILES" and "test.txt" in r[1].split(","))

    # --- send (client to client relay) ---
    send_payload = b"direct send payload" * 50
    send_line(alice, "SEND", "bob", "direct.bin", len(send_payload), sha256_hex(send_payload))
    r = recv_line(alice)
    check("send ready", r[0] == "READY")
    send_exact(alice, send_payload)
    r = recv_line(alice)
    check("send ok", r[0] == "SEND_OK")

    r = recv_line(bob)
    check("bob got send_incoming header", r[0] == "SEND_INCOMING" and r[1] == "direct.bin" and r[2] == "alice")
    data = recv_exact(bob, int(r[3]))
    check("bob received correct bytes", data == send_payload)
    check("sender's digest forwarded to bob, and it verifies",
          len(r) == 5 and r[4] == sha256_hex(send_payload) == sha256_hex(data))

    # one byte changed on the way, digest of the original
    bad = b"X" + send_payload[1:]
    send_line(alice, "SEND", "bob", "bad.bin", len(bad), sha256_hex(send_payload))
    recv_line(alice)                                     # READY
    send_exact(alice, bad)
    r = recv_line(alice)
    check("corrupted send rejected by the server", r == ["ERROR", "INTEGRITY_FAIL"])
    bob.settimeout(0.5)
    try:
        nothing_forwarded = False
        recv_line(bob)
    except (socket.timeout, TimeoutError):
        nothing_forwarded = True
    bob.settimeout(None)
    check("corrupted file not forwarded to bob", nothing_forwarded)

    send_line(alice, "SEND", "bob", "nodigest.bin", 3)
    r = recv_line(alice)
    check("send without a digest rejected", r == ["ERROR", "BAD_ARGS"])

    # send to offline user
    send_line(alice, "SEND", "nobody", "x.txt", 3, sha256_hex(b"abc"))
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


def check_client_rejects(cert, key, label, port):
    """Start a second server with the given certificate; the client-side TLS
    settings (trust only certs/ca.crt) must refuse to connect to it."""
    certs = os.path.join(ROOT, "certs")
    proc = subprocess.Popen(
        [sys.executable, "server.py", HOST, str(port),
         "--cert", os.path.join(certs, cert), "--key", os.path.join(certs, key)],
        cwd=os.path.join(ROOT, "server"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        wait_for_server(port=port)
        s = socket.create_connection((HOST, port))
        try:
            ssl.create_default_context(cafile=CA_FILE).wrap_socket(s, server_hostname=HOST)
            reason = None
        except ssl.SSLCertVerificationError as e:
            reason = e.verify_message
        finally:
            s.close()
        check(f"{label} rejected by the client ({reason})", reason is not None)
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def check_rejects_untrusted_server():
    certs = os.path.join(ROOT, "certs")
    if not os.path.isfile(os.path.join(certs, "rogue.crt")):
        subprocess.run([sys.executable, os.path.join(certs, "gen_rogue_cert.py")],
                       check=True, cwd=certs)
    # self-signed: not signed by our CA (untrusted)
    check_client_rejects("rogue.crt", "rogue.key", "untrusted (self-signed) certificate", PORT + 1)
    # signed by our CA, right names, but only valid in January 2025 (invalid)
    check_client_rejects("expired.crt", "server.key", "expired certificate", PORT + 2)


def main():
    if not (os.path.isfile(CA_FILE) and os.path.isfile(os.path.join(ROOT, "certs", "expired.crt"))):
        subprocess.run([sys.executable, os.path.join(ROOT, "certs", "gen_certs.py")], check=True)

    server_dir = os.path.join(ROOT, "server")
    users_file = os.path.join(server_dir, "users.txt")
    storage_dir = os.path.join(server_dir, "storage")
    digest_dir = os.path.join(server_dir, "digests")

    # start from a clean slate so re-runs are deterministic
    if os.path.exists(users_file):
        os.remove(users_file)
    if os.path.exists(storage_dir):
        shutil.rmtree(storage_dir)
    if os.path.exists(digest_dir):
        shutil.rmtree(digest_dir)

    proc = subprocess.Popen(
        [sys.executable, "server.py", HOST, str(PORT)],
        cwd=server_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        wait_for_server()
        check_rejects_untrusted_server()
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
        if os.path.exists(digest_dir):
            shutil.rmtree(digest_dir)


if __name__ == "__main__":
    main()
