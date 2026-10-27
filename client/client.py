"""
Interactive client for the multi-client file transfer server.

A single background thread ("reader") owns every socket READ: it prints
unsolicited pushes (MSG, BROADCAST, SEND_INCOMING) as they arrive, and
pushes any other line onto `reply_queue` for the main thread, which is the
only thread that ever WRITEs to the socket. Because TCP read/write are
independent directions, this split avoids any locking around the socket
itself.

Run:  python client.py [host] [port]
"""

import os
import queue
import socket
import ssl
import sys
import threading

from protocol import send_line, recv_line, recv_exact, send_exact

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads")
RECEIVED_DIR = os.path.join(BASE_DIR, "received")  # files pushed via SEND
os.makedirs(DOWNLOADS_DIR, exist_ok=True)
os.makedirs(RECEIVED_DIR, exist_ok=True)

# The CA certificate this client trusts (made by certs/gen_certs.py). Only a
# server whose certificate is signed by this CA will be accepted.
CA_FILE = os.path.join(BASE_DIR, "..", "certs", "ca.crt")


def make_tls_context():
    """
    Client-side TLS settings:
    - trust ONLY our own CA (not the system's list of public CAs)
    - require the server to present a valid certificate (CERT_REQUIRED)
    - check the certificate is for the address we connected to (check_hostname)
    """
    if not os.path.isfile(CA_FILE):
        sys.exit("[!] Missing certs/ca.crt. Run: python certs/gen_certs.py")
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

reply_queue = queue.Queue()

PUSH_COMMANDS = {"MSG", "BROADCAST", "SEND_INCOMING"}

# Set right before we close our own end of the socket after a clean LOGOUT,
# so the reader thread's subsequent "connection closed" isn't reported as an
# unexpected disconnect -- it's just noticing the shutdown it was told about.
expected_close = threading.Event()


def reader_thread(sock):
    while True:
        try:
            fields = recv_line(sock)
        except ConnectionError:
            if not expected_close.is_set():
                print("\n[!] Disconnected from server.")
                reply_queue.put(["ERROR", "DISCONNECTED"])
            break

        command = fields[0] if fields else ""

        if command == "MSG":
            _, sender, text = fields[0], fields[1], "|".join(fields[2:])
            print(f"\n[MSG from {sender}] {text}\n> ", end="", flush=True)
        elif command == "BROADCAST":
            _, sender, text = fields[0], fields[1], "|".join(fields[2:])
            print(f"\n[BROADCAST from {sender}] {text}\n> ", end="", flush=True)
        elif command == "SEND_INCOMING":
            _, filename, sender, filesize = fields
            filesize = int(filesize)
            data = recv_exact(sock, filesize)
            path = os.path.join(RECEIVED_DIR, filename)
            with open(path, "wb") as f:
                f.write(data)
            print(f"\n[+] Received '{filename}' from {sender} "
                  f"({filesize} bytes) -> {RECEIVED_DIR}\n> ", end="", flush=True)
        elif command == "DOWNLOAD_OK":
            # The reader thread owns all socket reads, so it must pull the
            # file bytes itself before handing the reply to the main thread.
            _, filename, filesize = fields
            filesize = int(filesize)
            data = recv_exact(sock, filesize)
            path = os.path.join(DOWNLOADS_DIR, filename)
            with open(path, "wb") as f:
                f.write(data)
            reply_queue.put(["DOWNLOAD_OK", filename, str(filesize)])
        else:
            reply_queue.put(fields)


def expect(*expected_commands):
    """Block for the next reply and return it, printing ERROR replies inline."""
    fields = reply_queue.get()
    if fields[0] == "ERROR":
        print(f"[ERROR] {'|'.join(fields[1:])}")
    return fields


def do_login(sock):
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    send_line(sock, "LOGIN", username, password)
    fields = expect("LOGIN_OK")
    if fields[0] == "LOGIN_OK":
        print(f"Logged in as {username}")
        return username
    return None


def do_list(sock):
    send_line(sock, "LIST")
    fields = expect("USERS")
    if fields[0] == "USERS":
        names = fields[1].split(",") if fields[1] else []
        print("Online users:", ", ".join(names) if names else "(none)")


def do_allusers(sock):
    send_line(sock, "ALLUSERS")
    fields = expect("ALLUSERS")
    if fields[0] == "ALLUSERS":
        entries = fields[1].split(",") if fields[1] else []
        if entries:
            print("All registered users:")
            for entry in entries:
                name, _, status = entry.partition(":")
                print(f"  {name} ({status})")
        else:
            print("All registered users: (none)")


def do_files(sock):
    send_line(sock, "FILES")
    fields = expect("FILES")
    if fields[0] == "FILES":
        names = fields[1].split(",") if fields[1] else []
        if names:
            print("Files on server:")
            for name in names:
                print(f"  {name}")
        else:
            print("Files on server: (none)")


def do_msg(sock):
    target = input("To user: ").strip()
    text = input("Message: ").strip()
    send_line(sock, "MSG", target, text)
    fields = expect("MSG_OK")
    if fields[0] == "MSG_OK":
        print("Sent.")


def do_broadcast(sock):
    text = input("Broadcast text: ").strip()
    send_line(sock, "BROADCAST", text)
    fields = expect("BROADCAST_OK")
    if fields[0] == "BROADCAST_OK":
        print("Broadcast sent.")


def do_upload(sock):
    path = input("Local file path to upload: ").strip()
    if not os.path.isfile(path):
        print("File not found locally.")
        return
    filename = os.path.basename(path)
    filesize = os.path.getsize(path)

    send_line(sock, "UPLOAD", filename, filesize)
    fields = expect("READY")
    if fields[0] != "READY":
        return

    with open(path, "rb") as f:
        data = f.read()
    send_exact(sock, data)

    fields = expect("UPLOAD_OK")
    if fields[0] == "UPLOAD_OK":
        print(f"Uploaded '{filename}' ({filesize} bytes).")


def do_download(sock):
    filename = input("Filename to download: ").strip()
    send_line(sock, "DOWNLOAD", filename)
    fields = expect("DOWNLOAD_OK")
    if fields[0] == "DOWNLOAD_OK":
        _, name, size = fields
        print(f"Downloaded '{name}' ({size} bytes) -> {DOWNLOADS_DIR}")


def do_send(sock):
    target = input("Send to user: ").strip()
    path = input("Local file path to send: ").strip()
    if not os.path.isfile(path):
        print("File not found locally.")
        return
    filename = os.path.basename(path)
    filesize = os.path.getsize(path)

    send_line(sock, "SEND", target, filename, filesize)
    fields = expect("READY")
    if fields[0] != "READY":
        return

    with open(path, "rb") as f:
        data = f.read()
    send_exact(sock, data)

    fields = expect("SEND_OK")
    if fields[0] == "SEND_OK":
        print(f"Sent '{filename}' to {target}.")


HELP = """
Commands:
  list                 - show online (currently connected) users
  allusers             - show every registered user, online or offline
  files                - show files available on the server
  msg                  - send a private message
  broadcast            - send a message to everyone
  upload               - upload a file to the server
  download             - download a file from the server
  send                 - send a file to another user
  help                 - show this help
  logout               - disconnect
"""


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5050

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.connect((host, port))

    # TLS handshake: the server sends its certificate and we verify it
    # (signed by our CA, valid dates, issued for `host`). If any check
    # fails we refuse to talk to this server at all.
    try:
        sock = make_tls_context().wrap_socket(raw, server_hostname=host)
    except ssl.SSLCertVerificationError as e:
        raw.close()
        sys.exit(f"[!] Server certificate rejected: {e.verify_message.rstrip('.')}. "
                 "Not connecting to an untrusted server.")
    except (ssl.SSLError, OSError) as e:
        raw.close()
        sys.exit(f"[!] Secure connection failed: {e}")
    print(f"Secure connection: {sock.version()}, cipher {sock.cipher()[0]}")
    print(f"Server certificate verified (issued to "
          f"{dict(x[0] for x in sock.getpeercert()['subject'])['commonName']}, "
          f"by {dict(x[0] for x in sock.getpeercert()['issuer'])['commonName']})")

    t = threading.Thread(target=reader_thread, args=(sock,), daemon=True)
    t.start()

    username = None
    while username is None:
        username = do_login(sock)

    print(HELP)
    try:
        while True:
            cmd = input("> ").strip().lower()
            if cmd == "list":
                do_list(sock)
            elif cmd == "allusers":
                do_allusers(sock)
            elif cmd == "files":
                do_files(sock)
            elif cmd == "msg":
                do_msg(sock)
            elif cmd == "broadcast":
                do_broadcast(sock)
            elif cmd == "help":
                print(HELP)
            elif cmd == "logout":
                # Set this BEFORE sending LOGOUT: the server closes its
                # socket immediately after replying, so the reader thread
                # could observe that close before this thread gets
                # scheduled again if the flag were set after expect().
                expected_close.set()
                send_line(sock, "LOGOUT")
                expect("LOGOUT_OK")
                break
            elif cmd == "upload":
                do_upload(sock)
            elif cmd == "download":
                do_download(sock)
            elif cmd == "send":
                do_send(sock)
            elif cmd == "":
                continue
            else:
                print("Unknown command. Type 'help'.")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
