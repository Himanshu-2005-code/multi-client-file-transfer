# Secure Multi-Client File Transfer (Assignment 2)

Roll number: 2024261

This is Assignment 1's multi-client TCP file transfer application with security
added. Everything from A1 still works (login, LIST, ALLUSERS, FILES, MSG,
BROADCAST, UPLOAD, DOWNLOAD, SEND, LOGOUT, many clients at once); it now runs
over TLS, checks every file with SHA-256, and private messages and files sent
from one user to another are **end-to-end encrypted**: the server relays them
but cannot read them.

| A2 requirement | How it is done |
|---|---|
| 1. Authentication: no plaintext passwords; invalid attempts rejected | Passwords only travel inside TLS; the server stores only SHA-256 message digests of them. New users must `REGISTER`; wrong password or unknown user gets `AUTH_FAILED`. |
| 2. Certificates and secure communication | Our own CA and a server certificate made with **OpenSSL**. The client trusts only our CA, checks the server's certificate and name, and refuses untrusted servers. Each client connection has its own TLS session. |
| 3. Secure messaging | MSG and BROADCAST travel inside each client's TLS session. **MSG is end-to-end encrypted**: the sender's client encrypts it for the receiver's public key (RSA-OAEP + AES-256-GCM), so the server, which only relays it, cannot read it. |
| 4. Secure file transfer (100 KB, 1 MB, 10 MB) | UPLOAD, DOWNLOAD and SEND all go over TLS. **SEND (user to user) is end-to-end encrypted**, file name included. `experiments/test4_secure_transfer.py` runs all three sizes. |
| 5. Message digests and file integrity | SHA-256 computed before sending, recomputed after receiving, compared; failures reported and the file is not kept. `demo/tamper_file.py` shows a failure. |

## Requirements

- Python 3.9 or newer (developed and tested with Python 3.13).
- Server: standard library only. Client: the `cryptography` package for the end-to-end
  encryption (`pip install -r requirements.txt`, i.e. `pip install cryptography`).
- OpenSSL command-line tool, only to generate the certificates.
  On Windows it comes with Git for Windows; `certs/gen_certs.py` finds it there too.

## Project structure

```
server/        server.py (TLS server, auth, integrity checks), protocol.py
client/        client.py (interactive TLS client), protocol.py (same as server's),
               e2e.py (end-to-end encryption: keys, encrypt/decrypt)
certs/         gen_certs.py, server_ext.cnf (CA + server certificate with OpenSSL)
               gen_rogue_cert.py (untrusted certificate for the rejection demo)
demo/          integrity_test.txt, tamper_file.py (integrity failure demo),
               curious_server.py (shows what the server can see)
experiments/   test1-3 from A1 (now over TLS), test4 secure transfer 100KB/1MB/10MB
tests/         test_protocol.py (protocol checks), test_e2e.py (end-to-end encryption)
AI_PROMPTS.md  every prompt given to the AI and what it produced
```

Created when running (not part of the submission): `server/users.txt`,
`server/storage/`, `server/digests/`, `server/pubkeys/`, `client/downloads/`,
`client/received/`, `client/keys/` (each user's private key; never sent anywhere),
and the generated keys and certificates in `certs/`.

## Running it

Run all commands from the project folder.

**1. Certificates.** The submitted zip already contains everything needed to run
(made with `certs/gen_certs.py`): `ca.crt`, `server.crt`, `server.key`, and for the demos
`expired.crt`, `rogue.crt`, `rogue.key`. So the server and client run straight away.
The CA's private key `ca.key` is deliberately **not** in the zip: it is only needed to
sign certificates, and anyone holding it could make certificates every client trusts.
To make a completely new set (new CA included):

```
python certs/gen_certs.py
```

This makes `ca.key`, `ca.crt`, `server.key`, `server.csr`, `server.crt` and `expired.crt`,
and checks the chain (`server.crt: OK`). The keys in the zip are test keys for this
assignment only. To run the server on another laptop on the same network, add that
laptop's IP: `python certs/gen_certs.py 192.168.1.5`.

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
to register a new account, then `l` to log in (the password is not shown while typing). Type `help` for the commands:
`list`, `allusers`, `files`, `msg`, `broadcast`, `upload`, `download`, `send`, `logout`.
Uploads and sends print the file's SHA-256; downloads and received files report whether
the integrity check passed. At login the client makes the user's key pair (first time
only) and publishes the public key; `msg` and `send` are then end-to-end encrypted.

**4. Automated tests** (start their own server; run them when no demo is going on,
because they delete `users.txt`, `storage/` and `digests/`):

```
python tests/test_protocol.py
python tests/test_e2e.py
```

(`test_e2e.py` also deletes `client/keys/` and `server/pubkeys/`.)

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
- End-to-end encrypted MSG text is `E2E:` + base64 of the envelope; an end-to-end
  encrypted SEND uses the file name `E2E` (the real name is inside the envelope).

### Commands

Changes from A1 are in **bold**.

| Client sends | Server replies | Errors |
|---|---|---|
| **`REGISTER\|user\|password`** | **`REGISTER_OK\|user`** | **USER_EXISTS, BAD_USERNAME, BAD_PASSWORD**, BAD_ARGS, ALREADY_LOGGED_IN |
| `LOGIN\|user\|password` | `LOGIN_OK\|user` | AUTH_FAILED (wrong password **or unknown user**), USER_ALREADY_ONLINE, BAD_ARGS, ALREADY_LOGGED_IN |
| `LIST` | `USERS\|alice,bob` | |
| `ALLUSERS` | `ALLUSERS\|alice:online,carol:offline` | |
| `FILES` | `FILES\|a.txt,b.pdf` | |
| `MSG\|to\|text` | `MSG_OK`; receiver gets `MSG\|from\|text` | USER_NOT_FOUND |
| `BROADCAST\|text` | `BROADCAST_OK`; every other user gets `BROADCAST\|from\|text` | |
| `UPLOAD\|name\|size\|`**`sha256`** | `READY`, client sends bytes, then `UPLOAD_OK\|name` | BAD_ARGS (incl. missing digest), **INTEGRITY_FAIL** |
| `DOWNLOAD\|name` | `DOWNLOAD_OK\|name\|size\|`**`sha256`** + bytes | FILE_NOT_FOUND |
| `SEND\|to\|name\|size\|`**`sha256`** | `READY`, bytes, `SEND_OK\|name`; receiver gets `SEND_INCOMING\|name\|from\|size\|`**`sha256`** + bytes | USER_NOT_FOUND, BAD_ARGS, **INTEGRITY_FAIL** |
| **`PUBKEY\|base64 public key`** | **`PUBKEY_OK`** (stored in `server/pubkeys/`) | BAD_ARGS |
| **`GETKEY\|user`** | **`KEY\|user\|base64 public key`** | **NO_KEY**, BAD_ARGS |
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
  |---- REGISTER|alice|pw1 -------------------->|   hash = SHA-256(pw1)
  |<--- REGISTER_OK|alice ----------------------|   users.txt: alice:<hash>
  |---- LOGIN|alice|pw1 ----------------------->|   recompute SHA-256(typed pw), compare
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

**End-to-end encrypted message and file (the server only relays)**

```
Alice                          Server                          Bob
  |                              |<-- PUBKEY|<bob's public key> | (at bob's login)
  |-- GETKEY|bob --------------->|                              |
  |<- KEY|bob|<public key> ------|                              |
  | K = random AES-256 key;  C = AES-GCM(K, text);  W = RSA-OAEP(bob's public key, K)
  |-- MSG|bob|E2E:base64(W+nonce+C) ->| sees only ciphertext      |
  |                              |-- MSG|alice|E2E:... -------->| K = RSA-OAEP decrypt(W, bob's
  |<- MSG_OK --------------------|                              |     private key); text = AES-GCM decrypt
SEND: the same, with the file name and contents inside the envelope; the SHA-256 checks of
the SEND diagram above run on the encrypted bytes.
```

## Security design

### Concepts from the course notes (Chapter 8, Security)

| What A2 does | Where it is in the CN slides |
|---|---|
| Server certificate signed by our own CA; client trusts only `ca.crt` | Public-key Certification Authorities (L9, slides 21-23) |
| Rogue / expired certificate rejected before any password is sent | Man-in-the-middle attack on ap5.0 and its fix with certified public keys (L9, slides 12, 20-23) |
| LOGIN sends the password, but only inside TLS | ap3.0 password authentication and the playback attack (L9, slides 6-9); TLS prevents playback |
| `users.txt` stores SHA-256(password), never the password | Message digests: many-to-one, infeasible to find m from H(m) (L9, slides 16, 19) |
| SHA-256 digest of every uploaded / downloaded / sent file, `INTEGRITY_FAIL` on mismatch | Message integrity with a hash H(m) (L8, slide 4; L9, slides 16-19); the Internet checksum is too weak (L9, slide 17) |
| RSA-2048 key pair per user (public key published with PUBKEY/GETKEY) | Public key cryptography, RSA (L8, slides 16-27) |
| AES-256 key for each message / file | Symmetric key cryptography, AES with 256-bit keys (L8, slides 11, 15) |
| Random AES key encrypted with the receiver's RSA public key; the server only relays ciphertext | Secure e-mail confidentiality: K_S(m) and K_B+(K_S) (L10-1, slides 2-3); RSA session keys (L8, slide 28) |
| TLS on every connection | Securing TCP connections: TLS (Chapter 8 outline) |

SHA-256 belongs to the SHA family on L9, slide 19 (SHA-1 there gives 160 bits, SHA-256 gives 256 bits). AES is used in GCM mode, which also detects a changed ciphertext.

- **Certificates (`certs/gen_certs.py`, OpenSSL).** We act as our own Certificate
  Authority: `ca.key` signs `server.crt`. The server certificate lists the names it is
  valid for (`localhost`, `127.0.0.1`, plus any IP given to the script) and can only be
  used for TLS server authentication. The private keys are in `.gitignore`, and the
  CA's key is not part of the submission.
- **TLS (Python `ssl`, built on OpenSSL).** Server: `make_tls_context()` loads
  `server.crt`/`server.key`, minimum TLS 1.2; each accepted socket is wrapped in its own
  thread (10 s handshake timeout), so each client gets an independent session with its
  own keys. Client: trusts only `ca.crt`, requires a valid certificate and checks the
  server name; on failure it exits before sending anything. In practice TLS 1.3 with
  `TLS_AES_256_GCM_SHA384` is negotiated.
- **Passwords.** Stored as `<SHA-256 message digest of the password>` (message
  digests, Chapter 8); a login recomputes the digest of the typed password and compares. An unknown user gets the same `AUTH_FAILED` reply as a wrong
  password.
- **Integrity.** SHA-256 (`protocol.sha256_hex`) on every UPLOAD, DOWNLOAD and SEND, as
  in the diagrams above. The server records each upload's verified digest in
  `server/digests/`, so a file changed on the server's disk later is caught on download.
- **End-to-end encryption (`client/e2e.py`, `cryptography` package).** TLS ends at the
  server, so on its own the server could read every relayed MSG and SEND. Now each user
  has an RSA-2048 key pair made by their own client (`client/keys/<user>.key`; the private
  key never leaves the client) and publishes the public key with `PUBKEY`. To send, the
  client gets the receiver's public key with `GETKEY`, encrypts the data with a fresh random
  AES-256-GCM key, and encrypts that AES key with RSA-OAEP (SHA-256) for the receiver
  (hybrid encryption: RSA is slow and can only encrypt a few hundred bytes). Only the
  receiver's private key can recover the AES key. The GCM tag detects any change to the
  envelope, and the sender, receiver and kind (MSG/SEND) are authenticated with it, so an
  envelope cannot be replayed to someone else or as from someone else. The server is
  standard-library only and never touches these keys.
- **Concurrency.** Several threads can write to one client's TLS socket (its own replies,
  and MSG/BROADCAST/SEND_INCOMING from other clients). A write lock per socket keeps
  every message, and every header + file pair, from being mixed with another.

## Demos

### 1. The client rejects untrusted and invalid certificates

**Untrusted (not signed by our CA):**

```
python certs/gen_rogue_cert.py
python server/server.py --cert certs/rogue.crt --key certs/rogue.key
python client/client.py
```

`rogue.crt` is self-signed: its names and dates are fine, but our CA did not sign it
(what a fake server in a man-in-the-middle attack would have). The client prints
`[!] Server certificate rejected: self-signed certificate. Not connecting to an untrusted server.`
and never asks for the password; the fake server logs `tlsv1 alert unknown ca`.

**Invalid: expired.** `expired.crt` is signed by our CA and issued for localhost /
127.0.0.1, but was only valid in January 2025:

```
python server/server.py --cert certs/expired.crt --key certs/server.key
python client/client.py
```

The client prints `[!] Server certificate rejected: certificate has expired.`

Restart the real server (without `--cert/--key`) after these demos.

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

### 3. The server cannot read private messages or files (end-to-end encryption)

```
python demo/curious_server.py          # the real server, printing everything it reads after TLS
python client/client.py                # bob: r (register), l (log in)
python client/client.py                # alice: register, log in, msg -> bob, send -> bob
```

The curious server prints `MSG|bob|E2E:R7YRFk6R1K0G...` and, for the file,
`SEND|bob|E2E|4505|...` followed by random-looking bytes: neither the message text, the
file name nor the contents. Bob's client prints the message and saves the file under its
real name. (Uploads are different: a file uploaded to the server is stored there for
anyone to download, so it is protected by TLS on the network, not end-to-end.)

### 4. Wireshark shows no unencrypted data

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

## Tests and experiments

With the server running (`python server/server.py`), from another terminal:

```
python experiments/test1_rtt.py                      # RTT of LIST, 100 requests
python experiments/test2_broadcast_latency.py        # broadcast to 5 clients
python experiments/test3_throughput.py 127.0.0.1 5050 1      # 10 clients x 1 MB
python experiments/test3_throughput.py 127.0.0.1 5050 100    # 10 clients x 100 MB
python experiments/test4_secure_transfer.py          # 100 KB / 1 MB / 10 MB upload, download, E2E send
```

All of them connect over TLS (helper: `experiments/secure_conn.py`, which registers the
test accounts if needed). Test 3 and test 4 check the SHA-256 of every file received.

Results on my laptop (Linux VM on the laptop, 2 cores, Python 3.10, loopback).
A1 is the same machine without TLS or digests:

| Test | A1 (no security) | A2 (TLS + SHA-256) |
|---|---|---|
| 1. RTT of LIST, median of 3 runs | 0.049 ms | 0.065 ms |
| 2. Broadcast to 5 clients, avg of 3 runs | 0.52 ms | 0.49 ms |
| 3. 10 clients x 1 MB | 196 MB/s | 355 MB/s |
| 3. 10 clients x 100 MB | 641 MB/s | 342 MB/s, 10/10 verified |

Test 4 (A2 only, median of 3 runs), every transfer PASSES its SHA-256 check and every
end-to-end encrypted file decrypts to the original:

| Size | Upload | Download | Send, end-to-end encrypted (two hops) |
|---|---|---|---|
| 100 KB | 0.9 ms | 0.5 ms | 2.5 ms |
| 1 MB | 2.3 ms | 2.2 ms | 7.9 ms |
| 10 MB | 23.7 ms | 19.9 ms | 61.4 ms |

TLS adds a little to every request (RTT +0.016 ms) and makes no measurable difference to
small broadcasts, but it roughly halves bulk throughput: every byte is encrypted and
authenticated (AES-256-GCM) on both ends and hashed (SHA-256) on both ends. The 1 MB
throughput run is too short (~0.03-0.05 s) to compare reliably. "Send" is slowest because
the file crosses two TLS connections, is checked twice, and is also encrypted by the
sender and decrypted by the receiver (the 100 KB send includes one RSA operation each way).

`tests/test_protocol.py` starts its own server and runs 48 checks: rejection of an
untrusted and an expired certificate, registration and login rules, no plaintext in `users.txt`, every A1 command,
and the integrity checks for upload, download (including a file modified on the server)
and send (including a corrupted file that must not be forwarded).
`tests/test_e2e.py` runs the curious server and two real clients and checks 17 things:
bob reads alice's message and file; the server never saw the text, the file name or the
contents; another user's key cannot decrypt; a changed envelope or a wrong sender is
rejected; PUBKEY / GETKEY replies.

## Problems found and fixed during A2

- **Strict certificate checks (Python 3.13+).** The first CA certificate was rejected
  because it did not state `CA:TRUE` / `keyCertSign`. Fixed in `gen_certs.py`.
- **40 ms delay on the first message.** With TLS, the first small message after each
  login waited ~42 ms (broadcast latency went from 0.9 ms to 31 ms). Cause: Nagle's
  algorithm with delayed ACKs, triggered by the small TLS records sent right after the
  handshake. Fixed with `TCP_NODELAY` on the server's sockets.
- **Client hung on its first command (intermittent).** Testing the packaged zip, the
  client sometimes hung right after sending REGISTER (3 of 20 starts in one test). Thread
  dumps showed the reader thread inside an SSL read while the main thread had just written
  the command. Right after the handshake a TLS 1.3 server sends session tickets; the
  client's reader thread processed them while the main thread wrote on the same TLS
  connection, and the write was lost. Fixed by sending no session tickets
  (`ctx.num_tickets = 0`; we do not use session resumption): 20 of 20 starts work.
- **40 ms stall on uploads (client side).** On my laptop a 1 MB upload took ~43 ms every
  time while a 10 MB upload took ~22 ms and downloads only ~2 ms: the same Nagle /
  delayed-ACK effect on the client's writes. Fixed with `TCP_NODELAY` on the client socket
  too (1 MB upload now ~3 ms).
- **From A1:** concurrent writes to one client's socket could mix bytes (1 of 4 files
  intact in a stress test); fixed with a write lock per socket. LOGOUT_OK was sent before
  the user was marked offline; now the user goes offline first.

## Limitations

- Files are read into memory whole; very large files (GBs) need a lot of RAM.
- The server's own copy of the digests could be changed by someone who controls the
  server; signing digests with the uploader's private key would cover that.
- End-to-end: a public key is trusted as the server gives it; private keys are stored unencrypted in
  `client/keys/`; BROADCAST and uploads are protected by TLS only (the server is their
  intended reader / storage); the server still sees who talks to whom, when, and sizes.
  Messages are not signed: the server cannot read or change an envelope, but since public
  keys are public it could create a new one claiming to be from another user (signing
  with the sender's private key, RSA-PSS, would close this).
- Only the server is authenticated by certificate; clients authenticate with passwords
  (client certificates, i.e. mutual TLS, would be the next step).

## Use of AI

**Tool:** Claude (Anthropic), in the Claude app. Also used: OpenSSL (certificates),
Python standard library only.

**How it was used.** A2 was built in small steps, one short prompt per step, never the
whole program from one prompt. For each step the AI proposed and wrote the code change
as small changes (branch `a2` of my A1 repository; one git commit per step), ran the
tests, and explained the change; I checked the result before giving the next prompt. Design
decisions were mine (OpenSSL instead of PuTTYgen, a REGISTER command instead of A1's
auto-registration, editing the stored file for the tamper demo).

**My prompts** (word for word; full details of each step's output and checks are in
[`AI_PROMPTS.md`](AI_PROMPTS.md)):

| Step | Prompt / decision | Result |
|---|---|---|
| 0 | Attached the A2 PDF: "okay so i got a assignment 2 on continuation of this with same policy ... You may use AI as you did last time. But you must give credit to it and all the details, like your prompt, etc. ..."; then "see we have to do it in parts not in single prompt keep steps as small as possible prompts too do not make any assumptions" | 12-step plan, no code |
| 1 | "have you followed the assignment pdf if so then continue"; "no keep pushing with maximum commits for it to be as detailed as i want" | A2 branch from A1; write lock per socket; logout ordering fix |
| 2 | "is the open ssl allowed"; "okay then continue" | `certs/gen_certs.py` (CA + server certificate with OpenSSL) |
| 3 | "ok next" | TLS on the server |
| 4 | "next" | TLS and certificate check in the client |
| 5 | "next" | rogue certificate + rejection demo and test |
| 6 | Chose "Add a REGISTER command" | salted password hashes, REGISTER, login rules, 3-attempt limit |
| 7 | "next" | SHA-256 integrity on upload |
| 8 | "next" | SHA-256 integrity on download and send |
| 9 | Chose "Edit the stored file" for the demo | `demo/tamper_file.py` |
| 10 | "next" | experiments over TLS, test 4 (100 KB / 1 MB / 10 MB), TCP_NODELAY fix |
| 11 | "next" | this README |
| 12 | Chose "Include them" (certificates in the zip) | `2024261_A2.zip` |
| 13 | "next"; chose "Full technical report"; "you can run it on my laptop" | experiments run on my laptop, client TCP_NODELAY fix, `2024261_A2.pdf` |
| 14 | "check alll the requirements as i donot wantt o lose marks" | requirement audit; expired-certificate demo; CA key left out of the zip; password hidden while typing |
| 15 | "where can i loose marks"; "76 commits in one day is too much"; chose "Squash to one commit per step" | git history squashed to one commit per step (no code change) |
| 16 | "The end-to-end encryption means that only the intended receiver should be able to see the decrypted data. If server is only a relay, then it should not be able to see it."; chose "cryptography package" and "MSG + SEND" | end-to-end encryption of MSG and SEND, curious-server demo, `tests/test_e2e.py` |
| 17 | "Make the pdf of assignment 2 and 3 with prompts like the assignment 1" | report rewritten in the format of my A1 report |
| 18 | "anything u can remove from these without efecting the requiremnt and that is extra from ur end"; chose the login timing trick, the 3-attempt lockout and the key fingerprint check | those three extras removed |
| 19 | "what are the extra tricks concepts that i have used are theree simple replacements"; "do all you think replace" | salted SHA-256 instead of PBKDF2; plain comparison instead of `hmac.compare_digest` |
| 20 | Attached my CN notes (L6-L12): "these ar the complete notes read these and thing that i should replace now"; "make A match my notes so that i can explain that to my TA" | passwords stored as plain SHA-256 message digests (no salt); table mapping each security part to the slides |

Questions I asked the AI to understand the material (no code produced): "what is tls",
the CN syllabus slides (to check which security topics my course covers), and the
approach and deadline planning.

**What I verified myself:** every step was tested before moving on (automated tests,
manual runs of server and clients, the experiments, the tamper and rejection demos,
and a packet capture comparing A1 and A2, and the curious-server run for end-to-end encryption). I can explain each part without the AI.
