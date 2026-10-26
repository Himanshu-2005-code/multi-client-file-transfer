"""
Multi-client file transfer server.

Accepts TCP connections, spawns one thread per client, and dispatches each
client's control messages (COMMAND|FIELD|...) to a handler.

Run:  python server.py [host] [port]
"""

import os
import socket
import sys
import threading
import traceback

from protocol import recv_line, recv_exact
from protocol import send_line as _send_line, send_exact as _send_exact

HOST = "0.0.0.0"
PORT = 5050

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.txt")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

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


def save_user(username, password):
    with open(USERS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username}:{password}\n")


users_lock = threading.Lock()


def check_or_register(username, password):
    """
    Returns True if the credentials are valid. Unknown usernames are
    auto-registered with the given password (per assignment scope: plain
    unencrypted username/password, no separate signup flow).
    """
    with users_lock:
        users = load_users()
        if username in users:
            return users[username] == password
        save_user(username, password)
        return True


def handle_login(sock, fields):
    if len(fields) != 3:
        send_line(sock, "ERROR", "BAD_ARGS")
        return None
    _, username, password = fields

    with clients_lock:
        already_online = username in active_clients

    if already_online:
        send_line(sock, "ERROR", "USER_ALREADY_ONLINE")
        return None

    if not check_or_register(username, password):
        send_line(sock, "ERROR", "AUTH_FAILED")
        return None

    with clients_lock:
        active_clients[username] = sock

    send_line(sock, "LOGIN_OK", username)
    print(f"[+] {username} logged in from {sock.getpeername()}")
    return username


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

    try:
        send_line(target_sock, "MSG", sender, text)
    except OSError:
        send_line(sock, "ERROR", "USER_NOT_FOUND")
        return

    send_line(sock, "MSG_OK")


def safe_filename(name):
    """Strip any path components so clients can't escape STORAGE_DIR."""
    return os.path.basename(name.replace("\\", "/"))


def handle_upload(sock, fields):
    if len(fields) != 3:
        send_line(sock, "ERROR", "BAD_ARGS")
        return
    filename = safe_filename(fields[1])
    try:
        filesize = int(fields[2])
    except ValueError:
        send_line(sock, "ERROR", "BAD_ARGS")
        return

    send_line(sock, "READY")
    data = recv_exact(sock, filesize)

    path = os.path.join(STORAGE_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)

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

    filesize = os.path.getsize(path)
    with open(path, "rb") as f:
        data = f.read()
    # Header and payload must go out back-to-back with nothing in between.
    with write_lock(sock):
        send_line(sock, "DOWNLOAD_OK", filename, filesize)
        send_exact(sock, data)


def handle_send(sock, sender, fields):
    if len(fields) != 4:
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

    try:
        # Header and payload must go out back-to-back with nothing in between.
        with write_lock(target_sock):
            send_line(target_sock, "SEND_INCOMING", filename, sender, filesize)
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


def handle_client(sock, addr):
    username = None
    try:
        while True:
            try:
                fields = recv_line(sock)
            except ConnectionError:
                break

            command = fields[0] if fields else ""

            if command == "LOGIN":
                if username is not None:
                    send_line(sock, "ERROR", "ALREADY_LOGGED_IN")
                    continue
                try:
                    username = handle_login(sock, fields)
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
                continue

            if username is None:
                send_line(sock, "ERROR", "NOT_LOGGED_IN")
                continue

            try:
                if command == "LOGOUT":
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
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

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
            t = threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
