# AI usage log (Assignment 2)

AI tool: Claude (Anthropic), used through the Claude app.
The work was done in small steps, one prompt per step. Each entry lists my
prompt word for word, what the AI produced (with the commits), and what I
checked myself.

---

## Step 0: planning

**My prompts:**
1. (Attached the A2 PDF) "okay so i got a assignment 2 on continuation of this with same policy ... You may use AI as you did last time. But you must give credit to it and all the details, like your prompt, etc. ..."
2. Answer to the AI's question on how to build it: "see we have to do it in parts not in single prompt keep steps as small as possible prompts too do not make any assumptions"

**AI output:** a 12-step plan mapping every requirement in the A2 PDF to a step. No code.

---

## Step 1: start A2 from A1 and fix the concurrency bugs

**My prompts:**
1. "have you followed the assignment pdf if so then continue"
2. "no keep pushing with maximum commits for it to be as detailed as i want"

**AI output:** branch `a2` created from my A1 `main`, then:
- `server: add a write lock per client socket`
- `server: send DOWNLOAD_OK header and file bytes under one lock`
- `server: send SEND_INCOMING header and bytes under one lock`
- `server: forget a socket's write lock when the client disconnects`
- `server: mark the user offline before replying LOGOUT_OK`

The write-lock bug was found while preparing the A1 demo (4 clients sending
8 MB files to one user at once: only 1 of 4 arrived intact). The logout bug
showed up as a rare failure of the "allusers lists charlie as offline" test.

**What I checked:** `python tests/test_protocol.py` passes (40 runs in a row).

---

## Step 2: certificate and keys with OpenSSL

**My prompts:**
1. "is the open ssl allowed"
2. "okay then continue"

**AI output:**
- `certs: add the extensions for the server certificate` (`certs/server_ext.cnf`)
- `certs: add key identifiers to the server certificate`
- `certs: add an OpenSSL script to create the CA and server certificate` (`certs/gen_certs.py`)
- `gitignore: keep generated keys and certificates out of git`

Tool choice: OpenSSL (open-source, Apache 2.0). The assignment needs an X.509
certificate for TLS; PuTTYgen only makes SSH key pairs, not certificates.

The first version failed a test: Python 3.13+ verifies certificates strictly and
rejected a CA certificate without `basicConstraints CA:TRUE` / `keyUsage keyCertSign`.
The AI added those extensions and the key identifiers.

**What I checked:** `python certs/gen_certs.py` ends with `server.crt: OK`; a test
TLS connection with Python's `ssl` module works (TLS 1.3) and a connection to an
address that is not in the certificate is rejected.

---

## Step 3: TLS on the server

**My prompt:** "ok next"

**AI output:**
- `server: load the TLS certificate and private key at startup` (`make_tls_context()`, TLS 1.2 minimum)
- `server: wrap every client connection in TLS` (handshake in each client's own thread, 10 s handshake timeout)
- `tests: talk to the server over TLS`

**What I checked:**
- `python tests/test_protocol.py`: all 27 checks pass over TLS (10 runs).
- Stress test: 4 clients each send an 8 MB file to the same user while that user keeps
  sending LIST commands on the same encrypted connection. 4/4 files intact in 5 runs,
  no server errors. The server log shows every connection on TLS 1.3
  (`TLS_AES_256_GCM_SHA384`).

---

## Step 4: TLS and certificate check in the client

**My prompt:** "next"

**AI output:**
- `client: add the TLS settings that trust only our CA` (`make_tls_context()`: only `certs/ca.crt`, certificate required, hostname check, TLS 1.2 minimum)
- `client: connect over TLS and reject untrusted servers` (prints TLS version, cipher, and who the certificate was issued to and by; exits on a bad certificate)
- `client: print a clear message when the server cannot be reached`

**What I checked:**
- Login, LIST, MSG, BROADCAST, upload, download and send all work through the real client over TLS 1.3.
  A 1 MB file uploaded, sent to another user and downloaded arrives byte-for-byte identical (`cmp`).
- Connecting to the server at `127.0.0.2` (an address not in the certificate) is rejected:
  `[!] Server certificate rejected: IP address mismatch, certificate is not valid for '127.0.0.2'`.
- `python tests/test_protocol.py` still passes.

---

## Step 5: demo for rejecting an untrusted certificate

**My prompt:** "next"

**AI output:**
- `certs: add a script that makes an untrusted (rogue) certificate` (`certs/gen_rogue_cert.py`: self-signed, valid names and dates, not signed by our CA)
- `server: add --cert and --key options` (so a fake server can be started with the rogue certificate)
- `tests: check that the client refuses an untrusted server`

OpenSSL 3.0's `req -x509` cannot create an already-expired certificate (`-days 0` is
rejected), so the demo covers two cases of an invalid/untrusted certificate:
not signed by our CA (this step) and issued for a different address (step 4).

**What I checked:** a server started with `--cert certs/rogue.crt --key certs/rogue.key`
is refused by the client (`Server certificate rejected: self-signed certificate`), and the
fake server's log shows `tlsv1 alert unknown ca` with no login received. The new test passes.

---

## Step 6: passwords and authentication

**My input:** answered the AI's question "A1 auto-registers any unknown username... What should
step 6 do?" with **"Add a REGISTER command"**.

**AI output:**
- `server: add salted password hashing helpers` (PBKDF2-HMAC-SHA256, 16-byte random salt, 200,000 iterations, constant-time compare)
- `server: store salted password hashes instead of plaintext` (`users.txt` holds `name:pbkdf2_sha256$...`)
- `server: add a REGISTER command` (errors: USER_EXISTS, BAD_USERNAME, BAD_PASSWORD)
- `client: add a register option before login`
- `tests: register users before logging in` (+ checks that `users.txt` has no plaintext password)
- `server: reject LOGIN for unregistered users` (same AUTH_FAILED reply and same time as a wrong password)
- `server: disconnect after 3 failed logins`
- `client: exit cleanly when the server ends the login after 3 failures`
- `server: send exactly one reply for each LOGIN attempt` (fix: the first version sent two replies on
  the 3rd failure and the client crashed with SSLEOFError)

Passwords are never sent in plaintext because LOGIN/REGISTER only travel inside the TLS
connection (steps 3-4), and never stored in plaintext because of the hashing above.

**What I checked:** all protocol tests pass (5 runs), including: register, duplicate name
rejected, invalid name rejected, no plaintext in users.txt, wrong password rejected, unknown user
rejected, 3rd failed login disconnects. Through the real client: register -> login works; three
wrong passwords end with "Too many failed logins". A known and an unknown username both take
about 140-150 ms to reject.
