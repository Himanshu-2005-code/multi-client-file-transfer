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
