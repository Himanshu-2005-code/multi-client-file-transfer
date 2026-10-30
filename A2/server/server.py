"""
Multi-client file transfer server.

Accepts TCP connections, spawns one thread per client, and dispatches each
client's control messages (COMMAND|FIELD|...) to a handler.

Run:  python server.py [host] [port]
"""

import argparse
import base64
import binascii
import hashlib
import os
import re
import socket
import ssl
import sys
import threading
import traceback

from protocol import recv_line, recv_exact, sha256_hex
from protocol import send_line as _send_line, send_exact as _send_exact

HOST = "0.0.0.0"
PORT = 5050

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.txt")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)
# SHA-256 of each stored file, recorded when its upload passed the integrity
# check: digests/<filename>.sha256. Kept apart from storage/ so FILES only
# lists real files.
DIGEST_DIR = os.path.join(BASE_DIR, "digests")
os.makedirs(DIGEST_DIR, exist_ok=True)
# Each user's PUBLIC key for end-to-end encryption (pubkeys/<user>.pub, one
# line of base64). The private keys stay on the clients, so the server can
# hand public keys out but cannot decrypt anything encrypted with them.
PUBKEY_DIR = os.path.join(BASE_DIR, "pubkeys")
os.makedirs(PUBKEY_DIR, exist_ok=True)

# Server certificate and private key, made by certs/gen_certs.py (OpenSSL).
CERTS_DIR = os.path.join(BASE_DIR, "..", "certs")
CERT_FILE = os.path.join(CERTS_DIR, "server.crt")
KEY_FILE = os.path.join(CERTS_DIR, "server.key")

# username -> socket, for every currently-logged-in client
active_clients = {}
clients_lock = threading.Lock()

# One write lock per socket. Several server threads can write to the SAME
# client socket (its own thread sending replies, other clients' threads
# pushing MSG / BROADCAST / SEND_INCOMING to it). Without a lock, two
# sendall() calls can interleave and corrupt the byte stream. RLock so a
# thread can hold it across a header + payload pair and still call send_line.
write_locks = {}
write_locks_guard = threading.Lock()


def write_lock(sock):
    with write_locks_guard:
        return write_locks.setdefault(sock, threading.RLock())


def send_line(sock, *fields):
    with write_lock(sock):
        _send_line(sock, *fields)


def send_exact(sock, data):
    with write_lock(sock):
        _send_exact(sock, data)


# ---------------------------------------------------------------------------
# Password hashing (passwords are never stored in plaintext)
# ---------------------------------------------------------------------------
# users.txt stores   <SHA-256 message digest of the password, in hex>
# (message digests, Chapter 8 / L9: a hash function is many-to-one and it is
#  computationally infeasible to find a password m from its digest H(m)).
# A login recomputes H(password) and compares it with the stored digest, so
# the server never stores (or needs) the plaintext password.


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password, stored):
    """Recompute the digest of the typed password and compare."""
    return hash_password(password) == stored


def load_users():
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                u, p = line.split(":", 1)
                users[u] = p
    return users


def save_user(username, password_hash):
    """Append one 'username:hash' line. The plaintext password is never written."""
    with open(USERS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username}:{password_hash}\n")


users_lock = threading.Lock()


def check_login(username, password):
    """
    True only if the user is registered AND the password matches.
    Unknown users are rejected (accounts are created with REGISTER only).
    """
    with users_lock:
        stored = load_users().get(username)
    if stored is None:
        return False
    return verify_password(password, stored)


# Usernames end up in users.txt ("name:hash") and in comma-separated LIST
# replies, so ':' ',' '|' and spaces are not allowed.
USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")


def register_user(username, password):
    """Create a new account. Returns None on success, else an error code."""
    if not USERNAME_RE.fullmatch(username):
        return "BAD_USERNAME"
    if not password:
        return "BAD_PASSWORD"
    new_hash = hash_password(password)
    with users_lock:
        if username in load_users():
            return "USER_EXISTS"
        save_user(username, new_hash)
    return None


def handle_register(sock, fields):
    if len(fields) != 3:
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    _, username, password = fields
    error = register_user(username, password)
    if error:
        send_line(sock, "ERROR", error)
        return
    send_line(sock, "REGISTER_OK", username)
    print(f"[+] new account: {username}")


def handle_login(sock, fields):
    """
    Returns (username, None) after sending LOGIN_OK, or (None, error_code)
    without sending anything: the caller sends the error (exactly one reply
    per request).
    """
    if len(fields) != 3:
        return None, "BAD_ARGS"
    _, username, password = fields

    with clients_lock:
        already_online = username in active_clients

    if already_online:
        return None, "USER_ALREADY_ONLINE"

    if not check_login(username, password):
        return None, "AUTH_FAILED"

    with clients_lock:
        active_clients[username] = sock

    send_line(sock, "LOGIN_OK", username)
    print(f"[+] {username} logged in from {sock.getpeername()}")
    return username, None


def handle_list(sock):
    with clients_lock:
        names = list(active_clients.keys())
    send_line(sock, "USERS", ",".join(names))


def handle_allusers(sock):
    all_usernames = sorted(load_users().keys())
    with clients_lock:
        online = set(active_clients.keys())
    entries = [f"{u}:{'online' if u in online else 'offline'}" for u in all_usernames]
    send_line(sock, "ALLUSERS", ",".join(entries))


def handle_files(sock):
    names = sorted(
        f for f in os.listdir(STORAGE_DIR)
        if os.path.isfile(os.path.join(STORAGE_DIR, f))
    )
    send_line(sock, "FILES", ",".join(names))


def handle_msg(sock, sender, fields):
    if len(fields) < 3:
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    target = fields[1]
    text = "|".join(fields[2:])  # allow '|' inside the message text itself

    with clients_lock:
        target_sock = active_clients.get(target)

    if target_sock is None:
        send_line(sock, "ERROR", "USER_NOT_FOUND")
        return

    if text.startswith("E2E:"):
        # End-to-end encrypted: the server only sees base64 ciphertext.
        print(f"[relay] MSG {sender}->{target}: end-to-end encrypted, "
              f"{len(text)} chars the server cannot read")
    try:
        send_line(target_sock, "MSG", sender, text)
    except OSError:
        send_line(sock, "ERROR", "USER_NOT_FOUND")
        return

    send_line(sock, "MSG_OK")


def handle_pubkey(sock, username, fields):
    # PUBKEY|<base64 public key>   the logged-in user publishes their own key
    if len(fields) != 2 or not (0 < len(fields[1]) <= 4096):
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    try:
        base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError):
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    with open(os.path.join(PUBKEY_DIR, username + ".pub"), "w", encoding="utf-8") as f:
        f.write(fields[1] + "\n")
    send_line(sock, "PUBKEY_OK")


def handle_getkey(sock, fields):
    # GETKEY|<user>  ->  KEY|<user>|<base64 public key>
    if len(fields) != 2 or not USERNAME_RE.fullmatch(fields[1]):
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    try:
        with open(os.path.join(PUBKEY_DIR, fields[1] + ".pub"), encoding="utf-8") as f:
            key = f.read().strip()
    except OSError:
        send_line(sock, "ERROR", "NO_KEY")
        return
    send_line(sock, "KEY", fields[1], key)


def safe_filename(name):
    """Strip any path components so clients can't escape STORAGE_DIR."""
    return os.path.basename(name.replace("\\", "/"))


def save_digest(filename, digest):
    os.makedirs(DIGEST_DIR, exist_ok=True)
    with open(os.path.join(DIGEST_DIR, filename + ".sha256"), "w", encoding="utf-8") as f:
        f.write(digest + "\n")


def load_digest(filename):
    """The digest recorded at upload time, or None if there is none."""
    try:
        with open(os.path.join(DIGEST_DIR, filename + ".sha256"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def handle_upload(sock, fields):
    # UPLOAD|filename|size|sha256   (the client computed the digest before sending)
    if len(fields) != 4:
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    filename = safe_filename(fields[1])
    try:
        filesize = int(fields[2])
    except ValueError:
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    sent_digest = fields[3].lower()

    send_line(sock, "READY")
    data = recv_exact(sock, filesize)

    # Integrity check: recompute the digest of what actually arrived and
    # compare it with the digest the client sent. Only matching files are kept.
    got_digest = sha256_hex(data)
    if got_digest != sent_digest:
        print(f"[integrity] UPLOAD '{filename}' FAILED: "
              f"sent {sent_digest[:16]}..., received {got_digest[:16]}...")
        send_line(sock, "ERROR", "INTEGRITY_FAIL")
        return
    print(f"[integrity] UPLOAD '{filename}' OK ({got_digest[:16]}...)")

    path = os.path.join(STORAGE_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    save_digest(filename, got_digest)

    send_line(sock, "UPLOAD_OK", filename)


def handle_download(sock, fields):
    if len(fields) != 2:
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    filename = safe_filename(fields[1])
    path = os.path.join(STORAGE_DIR, filename)

    if not os.path.isfile(path):
        send_line(sock, "ERROR", "FILE_NOT_FOUND")
        return

    with open(path, "rb") as f:
        data = f.read()
    filesize = len(data)
    # Send the digest recorded when the file was uploaded, NOT one computed
    # now: if the stored file was modified or corrupted on the server's disk
    # since then, the client's check will fail. Files without a record (put
    # into storage/ by hand) get a digest of their current contents.
    digest = load_digest(filename) or sha256_hex(data)
    # Header and payload must go out back-to-back with nothing in between.
    with write_lock(sock):
        send_line(sock, "DOWNLOAD_OK", filename, filesize, digest)
        send_exact(sock, data)


def handle_send(sock, sender, fields):
    # SEND|target|filename|size|sha256
    if len(fields) != 5:
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    target = fields[1]
    filename = safe_filename(fields[2])
    try:
        filesize = int(fields[3])
    except ValueError:
        send_line(sock, "ERROR", "BAD_ARGS")
        return

    with clients_lock:
        target_sock = active_clients.get(target)

    if target_sock is None:
        send_line(sock, "ERROR", "USER_NOT_FOUND")
        return

    # Pull the file off the sender first so its socket isn't left hanging
    # regardless of what happens on the target side.
    send_line(sock, "READY")
    data = recv_exact(sock, filesize)

    # Hop 1 (sender -> server): check before forwarding, so a corrupted
    # file is never passed on. The receiver checks hop 2 itself.
    sent_digest = fields[4].lower()
    got_digest = sha256_hex(data)
    if got_digest != sent_digest:
        print(f"[integrity] SEND '{filename}' {sender}->{target} FAILED: "
              f"sent {sent_digest[:16]}..., received {got_digest[:16]}...")
        send_line(sock, "ERROR", "INTEGRITY_FAIL")
        return
    print(f"[integrity] SEND '{filename}' {sender}->{target} OK ({got_digest[:16]}...)")
    if filename == "E2E":
        print(f"[relay] SEND {sender}->{target}: end-to-end encrypted file, "
              f"{filesize} bytes the server cannot read")

    try:
        # Header and payload must go out back-to-back with nothing in between.
        # The sender's digest is forwarded so the receiver can verify too.
        with write_lock(target_sock):
            send_line(target_sock, "SEND_INCOMING", filename, sender, filesize, sent_digest)
            send_exact(target_sock, data)
    except OSError:
        send_line(sock, "ERROR", "USER_NOT_FOUND")
        return

    send_line(sock, "SEND_OK", filename)


def handle_broadcast(sock, sender, fields):
    if len(fields) < 2:
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    text = "|".join(fields[1:])

    with clients_lock:
        targets = [(u, s) for u, s in active_clients.items() if u != sender]

    for username, target_sock in targets:
        try:
            send_line(target_sock, "BROADCAST", sender, text)
        except OSError:
            pass  # best-effort; a dead peer will be cleaned up by its own thread

    send_line(sock, "BROADCAST_OK")


def cleanup(username, sock):
    if username:
        with clients_lock:
            if active_clients.get(username) is sock:
                del active_clients[username]
        print(f"[-] {username} disconnected")
    with write_locks_guard:
        write_locks.pop(sock, None)
    try:
        sock.close()
    except OSError:
        pass


def make_tls_context(cert_file=CERT_FILE, key_file=KEY_FILE):
    """
    TLS settings for the server side. Every client connection is wrapped
    with this context, so each client gets its own TLS session (its own
    handshake and its own session keys).
    """
    if not (os.path.isfile(cert_file) and os.path.isfile(key_file)):
        sys.exit(f"[!] Missing {cert_file} or {key_file}. "
                 "Run: python certs/gen_certs.py")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # refuse old SSL/TLS versions
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    # No TLS 1.3 session tickets. Tickets are sent right after the handshake
    # and processed by the client's reader thread while its main thread may
    # already be writing the first command; one TLS connection used by two
    # threads at that moment can hang (seen in ~50% of client starts). We do
    # not use session resumption, so nothing is lost.
    ctx.num_tickets = 0
    return ctx


def handle_client(raw_sock, addr, tls_ctx):
    # TLS handshake first, inside this client's own thread, so a slow or
    # broken handshake never holds up accept() for everyone else. The
    # timeout stops a client that connects but never speaks TLS from
    # keeping a thread forever.
    # Send small messages immediately (disable Nagle's algorithm). Without
    # this, the first small message after the TLS handshake waited ~40 ms
    # for a delayed ACK. File transfers are large writes and unaffected.
    raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        raw_sock.settimeout(10)
        sock = tls_ctx.wrap_socket(raw_sock, server_side=True)
        sock.settimeout(None)
    except (ssl.SSLError, OSError) as e:
        print(f"[!] TLS handshake with {addr} failed: {e}")
        raw_sock.close()
        return
    print(f"[TLS] {addr}: {sock.version()}, cipher {sock.cipher()[0]}")

    username = None
    try:
        while True:
            try:
                fields = recv_line(sock)
            except ConnectionError:
                break

            command = fields[0] if fields else ""

            if command == "REGISTER":
                if username is not None:
                    send_line(sock, "ERROR", "ALREADY_LOGGED_IN")
                    continue
                handle_register(sock, fields)
                continue

            if command == "LOGIN":
                if username is not None:
                    send_line(sock, "ERROR", "ALREADY_LOGGED_IN")
                    continue
                try:
                    username, error = handle_login(sock, fields)
                except ConnectionError:
                    break
                except Exception:
                    print(f"[!] Unhandled error while handling LOGIN from {addr}:")
                    traceback.print_exc()
                    try:
                        send_line(sock, "ERROR", "SERVER_ERROR")
                    except OSError:
                        pass
                    break
                if error:
                    send_line(sock, "ERROR", error)
                continue

            if username is None:
                send_line(sock, "ERROR", "NOT_LOGGED_IN")
                continue

            try:
                if command == "LOGOUT":
                    # Go offline BEFORE confirming, so anyone who asks for
                    # LIST / ALLUSERS after our LOGOUT_OK never sees us online.
                    with clients_lock:
                        if active_clients.get(username) is sock:
                            del active_clients[username]
                    send_line(sock, "LOGOUT_OK")
                    break
                elif command == "LIST":
                    handle_list(sock)
                elif command == "FILES":
                    handle_files(sock)
                elif command == "ALLUSERS":
                    handle_allusers(sock)
                elif command == "MSG":
                    handle_msg(sock, username, fields)
                elif command == "BROADCAST":
                    handle_broadcast(sock, username, fields)
                elif command == "UPLOAD":
                    handle_upload(sock, fields)
                elif command == "DOWNLOAD":
                    handle_download(sock, fields)
                elif command == "SEND":
                    handle_send(sock, username, fields)
                elif command == "PUBKEY":
                    handle_pubkey(sock, username, fields)
                elif command == "GETKEY":
                    handle_getkey(sock, fields)
                else:
                    send_line(sock, "ERROR", "UNKNOWN_COMMAND")
            except ConnectionError:
                # Peer dropped mid-transfer; nothing more we can do for
                # this connection, but this isn't a server bug.
                break
            except Exception:
                # Anything unexpected: log the real cause to the server
                # console (instead of the client just silently dropping)
                # and close this connection -- after a failed command the
                # byte stream position can no longer be trusted, so we
                # can't safely keep using this socket.
                print(f"[!] Unhandled error while handling {command!r} "
                      f"from {username}:")
                traceback.print_exc()
                try:
                    send_line(sock, "ERROR", "SERVER_ERROR")
                except OSError:
                    pass
                break
    finally:
        cleanup(username, sock)


def main():
    ap = argparse.ArgumentParser(description="Secure multi-client file transfer server")
    ap.add_argument("host", nargs="?", default=HOST)
    ap.add_argument("port", nargs="?", type=int, default=PORT)
    ap.add_argument("--cert", default=CERT_FILE, help="server certificate (default certs/server.crt)")
    ap.add_argument("--key", default=KEY_FILE, help="server private key (default certs/server.key)")
    args = ap.parse_args()
    host, port = args.host, args.port
    tls_ctx = make_tls_context(args.cert, args.key)
    print(f"[*] Certificate: {os.path.normpath(args.cert)}")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(20)
    # A timeout on accept() makes the loop wake up periodically instead of
    # blocking forever -- on Windows in particular, Ctrl+C can't interrupt
    # a thread stuck in a blocking accept() with no incoming connection,
    # so without this, shutting down cleanly could require a connection
    # attempt to ever happen.
    server_sock.settimeout(1.0)
    print(f"[*] Server listening on {host}:{port}")

    try:
        while True:
            try:
                client_sock, addr = server_sock.accept()
            except socket.timeout:
                continue
            t = threading.Thread(target=handle_client, args=(client_sock, addr, tls_ctx),
                                 daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
