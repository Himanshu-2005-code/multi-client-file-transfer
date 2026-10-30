"""
End-to-end encryption test (MSG and SEND).

Starts demo/curious_server.py (the real server, printing everything it reads
after TLS decryption), runs two REAL interactive clients (client/client.py)
with scripted input, and checks that:
  - bob reads alice's private message and receives her file correctly
  - the server never saw the message text, the file contents or the file name
  - a different user's key cannot decrypt, and a modified envelope is rejected
  - PUBKEY / GETKEY replies

Run:  python tests/test_e2e.py      (needs: pip install cryptography)
"""

import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "client"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import e2e  # noqa: E402
from protocol import send_line, recv_line  # noqa: E402
import test_protocol as tp  # noqa: E402  (connect / check / wait_for_server)

PORT = 5097
tp.PORT = PORT
SECRET_MSG = "meet at gate 3, code 7781"
SECRET_FILE = b"SECRET-FILE-CONTENTS " * 200
SECRET_NAME = "e2e_secret_plan.txt"
check = tp.check


def client(script_lines, delay):
    """Run client/client.py, typing the given lines with a pause between them."""
    p = subprocess.Popen([sys.executable, "-u", os.path.join(ROOT, "client", "client.py"),
                          "127.0.0.1", str(PORT)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    for line in script_lines:
        time.sleep(delay)
        p.stdin.write(line + "\n")
        p.stdin.flush()
    return p


def run_checks():
    # --- PUBKEY / GETKEY with plain sockets ---
    s = tp.connect()
    for msg in (("REGISTER", "alice", "pw1"), ("REGISTER", "bob", "pw2"),
                ("REGISTER", "carol", "pw3")):
        send_line(s, *msg)
        recv_line(s)
    send_line(s, "LOGIN", "carol", "pw3")
    check("carol login", recv_line(s)[0] == "LOGIN_OK")
    send_line(s, "GETKEY", "nobody")
    check("GETKEY for a user with no key -> NO_KEY", recv_line(s) == ["ERROR", "NO_KEY"])
    send_line(s, "PUBKEY", "not base64 !!")
    check("PUBKEY with bad data rejected", recv_line(s) == ["ERROR", "BAD_ARGS"])
    keydir = os.path.join(ROOT, "client", "keys")
    carol_key = e2e.load_or_create_private_key("carol", keydir)
    send_line(s, "PUBKEY", e2e.public_key_b64(carol_key))
    check("PUBKEY ok", recv_line(s) == ["PUBKEY_OK"])
    send_line(s, "GETKEY", "carol")
    r = recv_line(s)
    check("GETKEY returns the published key", r == ["KEY", "carol", e2e.public_key_b64(carol_key)])
    send_line(s, "LOGOUT")
    recv_line(s)
    s.close()

    # --- two real clients: bob waits, alice sends a message and a file ---
    src = os.path.join(ROOT, "tests", SECRET_NAME)
    with open(src, "wb") as f:
        f.write(SECRET_FILE)
    bob = client(["l", "bob", "pw2"], 0.3)
    time.sleep(1.5)
    alice = client(["l", "alice", "pw1", "msg", "bob", SECRET_MSG,
                    "send", "bob", src, "logout"], 0.6)
    a_out, _ = alice.communicate(timeout=30)
    time.sleep(1.0)
    bob.stdin.write("logout\n")
    bob.stdin.flush()
    b_out, _ = bob.communicate(timeout=30)

    check("alice: message sent end-to-end encrypted", "Sent (end-to-end encrypted" in a_out)
    check("bob: message decrypted correctly",
          f"[MSG from alice, end-to-end encrypted] {SECRET_MSG}" in b_out)
    got_path = os.path.join(ROOT, "client", "received", SECRET_NAME)
    check("bob: file decrypted, original name restored", os.path.isfile(got_path))
    check("bob: decrypted file identical to the original",
          open(got_path, "rb").read() == SECRET_FILE)

    # --- what the server saw ---
    time.sleep(0.5)
    seen = open(SERVER_LOG, encoding="utf-8", errors="replace").read()
    check("server relayed an E2E message (saw only ciphertext)", "MSG|bob|E2E:" in seen)
    check("server never saw the message text", SECRET_MSG not in seen)
    check("server never saw the file contents", "SECRET-FILE" not in seen)
    check("server never saw the file name", SECRET_NAME not in seen)

    # --- cryptographic properties (module level) ---
    bob_key = e2e.load_or_create_private_key("bob", keydir)
    bob_pub = e2e.public_key_b64(bob_key)
    env = e2e.encrypt(bob_pub, b"for bob only", "MSG", "alice", "bob")
    check("bob's key decrypts", e2e.decrypt(bob_key, env, "MSG", "alice", "bob") == b"for bob only")
    try:
        e2e.decrypt(carol_key, env, "MSG", "alice", "bob")
        ok = False
    except e2e.E2EError:
        ok = True
    check("another user's key (carol) cannot decrypt", ok)
    bad = bytearray(env)
    bad[-20] ^= 1
    try:
        e2e.decrypt(bob_key, bytes(bad), "MSG", "alice", "bob")
        ok = False
    except e2e.E2EError:
        ok = True
    check("a modified envelope is rejected (AES-GCM tag)", ok)
    try:
        e2e.decrypt(bob_key, env, "MSG", "carol", "bob")
        ok = False
    except e2e.E2EError:
        ok = True
    check("an envelope cannot be passed off as from another sender", ok)


SERVER_LOG = os.path.join(ROOT, "tests", "curious_server.log")


def cleanup():
    for d in ("server/storage", "server/digests", "server/pubkeys", "client/keys"):
        shutil.rmtree(os.path.join(ROOT, d), ignore_errors=True)
    for f in ("server/users.txt", "tests/curious_server.log", f"tests/{SECRET_NAME}",
              f"client/received/{SECRET_NAME}"):
        try:
            os.remove(os.path.join(ROOT, f))
        except OSError:
            pass


def main():
    cleanup()
    log = open(SERVER_LOG, "w", encoding="utf-8")
    server = subprocess.Popen([sys.executable, "-u", os.path.join(ROOT, "demo", "curious_server.py"),
                               "127.0.0.1", str(PORT)], stdout=log, stderr=subprocess.STDOUT)
    try:
        tp.wait_for_server(port=PORT)
        run_checks()
        print("\nALL E2E CHECKS PASSED")
    finally:
        server.terminate()
        server.wait()
        log.close()
        cleanup()


if __name__ == "__main__":
    main()
