# Secure Multi-Client File Transfer (Assignment 2)

Roll number: 2024261

This is Assignment 1's multi-client TCP file transfer application with security
added. Everything from A1 still works (login, LIST, ALLUSERS, FILES, MSG,
BROADCAST, UPLOAD, DOWNLOAD, SEND, LOGOUT, many clients at once); it now runs
over TLS and checks every file with SHA-256.

| A2 requirement | How it is done |
|---|---|
| 1. Authentication: no plaintext passwords; invalid attempts rejected | Passwords only travel inside TLS; the server stores salted PBKDF2-SHA256 hashes. New users must `REGISTER`; wrong password or unknown user gets `AUTH_FAILED`; 3 failures close the connection. |
| 2. Certificates and secure communication | Our own CA and a server certificate made with **OpenSSL**. The client trusts only our CA, checks the server's certificate and name, and refuses untrusted servers. Each client connection has its own TLS session. |
| 3. Secure messaging | MSG and BROADCAST travel inside each client's TLS session. |
| 4. Secure file transfer (100 KB, 1 MB, 10 MB) | UPLOAD, DOWNLOAD and SEND all go over TLS. `experiments/test4_secure_transfer.py` runs all three sizes. |
| 5. Message digests and file integrity | SHA-256 computed before sending, recomputed after receiving, compared; failures reported and the file is not kept. `demo/tamper_file.py` shows a failure. |

## Requirements

- Python 3.9 or newer (developed and tested with Python 3.13). Standard library only, no `pip install`.
- OpenSSL command-line tool, only to generate the certificates.
  On Windows it comes with Git for Windows; `certs/gen_certs.py` finds it there too.

## Project structure

```
server/        server.py (TLS server, auth, integrity checks), protocol.py
client/        client.py (interactive TLS client), protocol.py (same as server's)
certs/         gen_certs.py, server_ext.cnf (CA + server certificate with OpenSSL)
               gen_rogue_cert.py (untrusted certificate for the rejection demo)
demo/          integrity_test.txt, tamper_file.py (integrity failure demo)
experiments/   test1-3 from A1 (now over TLS), test4 secure transfer 100KB/1MB/10MB
tests/         test_protocol.py (automated end-to-end checks)
AI_PROMPTS.md  every prompt given to the AI and what it produced
```

Created when running (not part of the submission): `server/users.txt`,
`server/storage/`, `server/digests/`, `client/downloads/`, `client/received/`,
and the generated keys and certificates in `certs/`.

## Running it

Run all commands from the project folder.

**1. Generate the certificates (once):**

```
python certs/gen_certs.py
```

This makes `ca.key`, `ca.crt`, `server.key`, `server.csr` and `server.crt` and ends
with `server.crt: OK`. To run the server on another laptop on the same network, add
that laptop's IP: `python certs/gen_certs.py 192.168.1.5`.

**2. Start the server** (default `0.0.0.0:5050`):

```
python server/server.py
```

**3. Start clients**, each in its own terminal (default `127.0.0.1:5050`):

```
python client/client.py
python client/client.py 192.168.1.5 5050      (server on another machine)
```

The client prints the TLS version and who the certificate was issued to. Choose `r`
to register a new account, then `l` to log in. Type `help` for the commands:
`list`, `allusers`, `files`, `msg`, `broadcast`, `upload`, `download`, `send`, `logout`.
Uploads and sends print the file's SHA-256; downloads and received files report whether
the integrity check passed.

**4. Automated tests** (start their own server; run them when no demo is going on,
because they delete `users.txt`, `storage/` and `digests/`):

```
python tests/test_protocol.py
```

**Upgrading from A1:** an A1 `server/users.txt` holds plaintext passwords and is not
accepted by A2. Delete it and register the users again.

## Protocol (A2 version)

### Layers

```
our application protocol   COMMAND|field|field\n  + raw file bytes
TLS 1.2 / 1.3              encryption, server authentication, record integrity
TCP                        reliable byte stream (port 5050)
```

A client first opens a TCP connection, then does a TLS handshake. Only after the
handshake succeeds is any application message sent, so every message below,
including passwords, is encrypted.

### Message format (unchanged from A1)

- Control message: one line of UTF-8 text, fields separated by `|`, ending in `\n`.
- File data: raw bytes sent right after a control line that states their exact size.
  The receiver reads exactly that many bytes (length-prefix framing).
- New in A2: file transfers carry the file's SHA-256 digest (64 hex characters).

### Commands

Changes from A1 are in **bold**.

| Client sends | Server replies | Errors |
|---|---|---|
| **`REGISTER\|user\|password`** | **`REGISTER_OK\|user`** | **USER_EXISTS, BAD_USERNAME, BAD_PASSWORD**, BAD_ARGS, ALREADY_LOGGED_IN |
| `LOGIN\|user\|password` | `LOGIN_OK\|user` | AUTH_FAILED (wrong password **or unknown user**), USER_ALREADY_ONLINE, BAD_ARGS, ALREADY_LOGGED_IN, **TOO_MANY_ATTEMPTS** (3rd failure, then disconnect) |
| `LIST` | `USERS\|alice,bob` | |
| `ALLUSERS` | `ALLUSERS\|alice:online,carol:offline` | |
| `FILES` | `FILES\|a.txt,b.pdf` | |
| `MSG\|to\|text` | `MSG_OK`; receiver gets `MSG\|from\|text` | USER_NOT_FOUND |
| `BROADCAST\|text` | `BROADCAST_OK`; every other user gets `BROADCAST\|from\|text` | |
| `UPLOAD\|name\|size\|`**`sha256`** | `READY`, client sends bytes, then `UPLOAD_OK\|name` | BAD_ARGS (incl. missing digest), **INTEGRITY_FAIL** |
| `DOWNLOAD\|name` | `DOWNLOAD_OK\|name\|size\|`**`sha256`** + bytes | FILE_NOT_FOUND |
| `SEND\|to\|name\|size\|`**`sha256`** | `READY`, bytes, `SEND_OK\|name`; receiver gets `SEND_INCOMING\|name\|from\|size\|`**`sha256`** + bytes | USER_NOT_FOUND, BAD_ARGS, **INTEGRITY_FAIL** |
| `LOGOUT` | `LOGOUT_OK`, then the server closes the connection | |

Any command other than REGISTER or LOGIN before logging in gets `ERROR|NOT_LOGGED_IN`;
an unknown command gets `ERROR|UNKNOWN_COMMAND`; an unexpected server fault gets
`ERROR|SERVER_ERROR` and the connection is closed. Every request gets exactly one reply.

Usernames: 1-32 characters from letters, digits, `_`, `.`, `-` (`:` `,` `|` and spaces
would break `users.txt` or the comma-separated LIST reply).

### Sequence diagrams

**Connect, register and log in**

```
Client                                        Server
  |---- TCP SYN / SYN-ACK / ACK -------------->|   (done by the OS)
  |---- TLS ClientHello ----------------------->|
  |<--- ServerHello + server.crt ---------------|
  |  client checks: signed by ca.crt? not expired? issued for this address?
  |  (any check fails -> close, nothing else is sent)
  |<--- key exchange done, session keys ------->|   everything below is encrypted
  |---- REGISTER|alice|pw1 -------------------->|   hash = PBKDF2(pw1, random salt)
  |<--- REGISTER_OK|alice ----------------------|   users.txt: alice:pbkdf2_sha256$...
  |---- LOGIN|alice|pw1 ----------------------->|   recompute hash with stored salt, compare
  |<--- LOGIN_OK|alice -------------------------|
```

**Upload with integrity check**

```
Client                                        Server
  | digest = SHA-256(file)   (before sending)  |
  |---- UPLOAD|notes.pdf|102400|<digest> ----->|
  |<--- READY ----------------------------------|
  |---- 102400 raw bytes ---------------------->|   SHA-256(received) == digest ?
  |<--- UPLOAD_OK|notes.pdf --------------------|   yes: save file, save digest in digests/
  |<--- ERROR|INTEGRITY_FAIL -------------------|   no:  file not saved
```

**Download with integrity check**

```
Client                                        Server
  |---- DOWNLOAD|notes.pdf -------------------->|   digest = the one saved at upload
  |<--- DOWNLOAD_OK|notes.pdf|102400|<digest> --|
  |<--- 102400 raw bytes -----------------------|
  | SHA-256(received) == digest ?  yes: save to downloads/   no: report FAILED, don't save
```

**Send to another user (two checks)**

```
Alice                         Server                          Bob
  | digest = SHA-256(file)      |                               |
  |-- SEND|bob|f|size|digest -->|                               |
  |<-- READY -------------------|                               |
  |-- raw bytes --------------->| check 1: SHA-256 == digest?   |
  |                             |   no: ERROR|INTEGRITY_FAIL to Alice, nothing forwarded
  |                             |-- SEND_INCOMING|f|alice|size|digest -->|
  |                             |-- raw bytes ---------------->| check 2: SHA-256 == digest?
  |<-- SEND_OK|f ---------------|                               | no: report FAILED, don't save
```

## Security design

- **Certificates (`certs/gen_certs.py`, OpenSSL).** We act as our own Certificate
  Authority: `ca.key` signs `server.crt`. The server certificate lists the names it is
  valid for (`localhost`, `127.0.0.1`, plus any IP given to the script) and can only be
  used for TLS server authentication. The private keys never leave the machine and are
  in `.gitignore`.
- **TLS (Python `ssl`, built on OpenSSL).** Server: `make_tls_context()` loads
  `server.crt`/`server.key`, minimum TLS 1.2; each accepted socket is wrapped in its own
  thread (10 s handshake timeout), so each client gets an independent session with its
  own keys. Client: trusts only `ca.crt`, requires a valid certificate and checks the
  server name; on failure it exits before sending anything. In practice TLS 1.3 with
  `TLS_AES_256_GCM_SHA384` is negotiated.
- **Passwords.** Stored as `pbkdf2_sha256$200000$<16-byte salt>$<hash>`; compared with
  `hmac.compare_digest`. Unknown users are checked against a dummy hash so a login takes
  the same time whether or not the user exists.
- **Integrity.** SHA-256 (`protocol.sha256_hex`) on every UPLOAD, DOWNLOAD and SEND, as
  in the diagrams above. The server records each upload's verified digest in
  `server/digests/`, so a file changed on the server's disk later is caught on download.
- **Concurrency.** Several threads can write to one client's TLS socket (its own replies,
  and MSG/BROADCAST/SEND_INCOMING from other clients). A write lock per socket keeps
  every message, and every header + file pair, from being mixed with another.

## Demos

### 1. The client rejects an untrusted server

```
python certs/gen_rogue_cert.py
python server/server.py --cert certs/rogue.crt --key certs/rogue.key
python client/client.py
```

`rogue.crt` is self-signed: its names and dates are fine, but our CA did not sign it
(what a fake server in a man-in-the-middle attack would have). The client prints
`[!] Server certificate rejected: self-signed certificate. Not connecting to an untrusted server.`
and never asks for the password; the fake server logs `tlsv1 alert unknown ca`.
Restart the real server (without `--cert/--key`) afterwards.

**Wrong address:** start the real server with `python server/server.py 0.0.0.0` and run
`python client/client.py 127.0.0.2`. The certificate is not issued for 127.0.0.2, so the
client prints `IP address mismatch, certificate is not valid for '127.0.0.2'`.

### 2. Integrity failure on an intentionally modified file

With the server running and a client logged in:

1. client: `upload` -> `demo/integrity_test.txt` (prints the SHA-256, "Integrity check passed")
2. another terminal: `python demo/tamper_file.py integrity_test.txt`
   (flips one bit in `server/storage/integrity_test.txt`: "Integrity" -> "Hntegrity")
3. client: `download` -> `integrity_test.txt` -> **"Integrity check FAILED"**, the expected and
   received SHA-256 are printed and the file is not saved
4. `python demo/tamper_file.py integrity_test.txt --restore`, then download again -> passes

A corrupted upload or send is rejected by the server with `INTEGRITY_FAIL`
(`tests/test_protocol.py` checks this by sending one changed byte with the original digest).

### 3. Wireshark shows no unencrypted data

1. Start Wireshark. For traffic on the same machine, capture on the loopback interface
   (on Windows: "Adapter for loopback traffic capture", from Npcap's loopback support).
2. Display filter: `tcp.port == 5050`. If the packets show only as TCP data, use
   Analyze -> Decode As -> TCP port 5050 -> TLS.
3. Register, log in, send a message, broadcast, upload/download/send a file.
4. Wireshark shows the TLS handshake (Client Hello, Server Hello) and then only
   "Application Data" records. Follow -> TCP Stream shows random-looking bytes, and
   Edit -> Find Packet -> String finds neither the password, the message text nor the
   file contents.

For comparison, the same steps against the A1 code (`main` branch) show
`LOGIN|alice|<password>` and the message and file text in plain sight.

The same check was done during development with a packet capture on loopback:
the A1 capture contained the password, a broadcast message and a file's contents in
plaintext; the A2 capture of the same actions (58 packets) contained none of them, and
its first bytes are `16 03 01`, a TLS handshake record.
