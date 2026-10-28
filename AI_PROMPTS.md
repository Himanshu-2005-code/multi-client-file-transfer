# AI usage log (Assignment 2)

AI tool: Claude (Anthropic), used through the Claude app.
The work was done in small steps, one prompt per step. Each entry lists my
prompt word for word, what the AI produced (with the commits), and what I
checked myself.

Each step was first made as several small commits. In step 15 I asked for fewer
commits, so the history was squashed to **one commit per step** ("Step N: ...").
The commit names listed under each step below are the changes inside that step's
commit (they are also listed in the commit message).

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

---

## Step 7: file integrity on upload (message digest)

**My prompt:** "next"

**AI output:**
- `protocol: add a SHA-256 digest helper` (`sha256_hex()` in both copies of `protocol.py`)
- `server: verify the SHA-256 digest of uploaded files`
- `client: send a SHA-256 digest with every upload` (digest computed before sending and shown; result reported)
- `tests: upload with a digest and check that a corrupted upload is rejected`
- `server: require a digest on every upload`
- `server: record each stored file's verified SHA-256` (`server/digests/<file>.sha256`, used by downloads in step 8)
- `tests: also remove server/digests when the test finishes` (fix: cleanup missed this folder)

Protocol change: `UPLOAD|filename|size|sha256` -> `READY` -> bytes -> `UPLOAD_OK|filename`
or `ERROR|INTEGRITY_FAIL` (file not stored). An UPLOAD without a digest gets `ERROR|BAD_ARGS`.

**What I checked:** the digest the client prints for a 100 KB file equals the output of the
standard `sha256sum` tool; the server logs `[integrity] UPLOAD ... OK`; a file with one changed
byte sent with the original's digest is rejected with INTEGRITY_FAIL and not stored. All tests pass.

---

## Step 8: file integrity on download and client-to-client send

**My prompt:** "next"

**AI output:**
- `client: verify the SHA-256 of downloaded files` (file not saved if the check fails)
- `server: send the recorded SHA-256 with every download` (the digest recorded at upload time, so a file changed on the server's disk is detected)
- `tests: check the digest on download and detect a file modified on the server`
- `client: verify the SHA-256 of files received from other users`
- `server: verify and forward the digest of files sent between users` (checked at the server, then again by the receiver)
- `client: send a SHA-256 digest with files sent to other users`
- `tests: check the digest on SEND and that a corrupted send is stopped`
- `server: require a digest on every SEND`

Order of commits: the receiving side learned to accept the new field before the sending side
started sending it, so every commit works on its own.

Protocol changes:
- `DOWNLOAD_OK|filename|size|sha256` + bytes (client recomputes and compares)
- `SEND|target|filename|size|sha256` -> server checks -> `SEND_INCOMING|filename|sender|size|sha256` + bytes (receiver checks)

**What I checked:** upload then download of a 100 KB file: same digest at both ends, identical
file. alice sends bob a 1 MB file: same digest at alice, the server and bob; identical file.
All protocol tests pass (5 runs), including a file modified on the server's disk and a corrupted SEND.

---

## Step 9: tamper demo (intentionally modified file)

**My input:** chose **"Edit the stored file"** when the AI asked how to demonstrate the integrity failure.

**AI output:**
- `demo: add a small text file for the integrity demo` (`demo/integrity_test.txt`)
- `demo: add a script that modifies a stored file on purpose` (`demo/tamper_file.py`, with `--restore`)

**What I checked (demo run):**
1. alice uploads `demo/integrity_test.txt` -> integrity check passed, SHA-256 `4d37e124...`
2. `python demo/tamper_file.py integrity_test.txt` -> first byte `I` becomes `H`, SHA-256 becomes `0b1c34cb...`
3. download -> "Integrity check FAILED", expected `4d37e124...`, received `0b1c34cb...`, file not saved
4. `--restore` then download -> integrity check passed

---

## Step 10: experiments over TLS, and 100 KB / 1 MB / 10 MB secure transfers

**My prompt:** "next"

**AI output:**
- `experiments: add a shared helper to connect over TLS and log in` (`experiments/secure_conn.py`)
- `experiments: run test 1 (RTT) over TLS`
- `experiments: run test 2 (broadcast latency) over TLS`
- `experiments: run test 3 (throughput) over TLS with integrity checks`
- `server: send small messages immediately (TCP_NODELAY)` (fix, see below)
- `experiments: add test 4, secure transfer of 100 KB, 1 MB and 10 MB files`

**Problem found:** after switching to TLS, experiment 2 (broadcast latency) went from ~0.9 ms
to ~31 ms. Measuring single messages showed only the FIRST message after each TLS login took
~42 ms (the rest ~0.2 ms); plain-TCP A1 never did this. Cause: Nagle's algorithm plus delayed
ACKs, triggered by the small TLS records sent right after the handshake. Fix: `TCP_NODELAY` on
the server's sockets. First message ~0.3 ms, experiment 2 back to ~0.9 ms, throughput unchanged.

**What I checked (loopback, after the fix):** test 1 RTT avg ~0.12 ms; test 2 avg ~0.87 ms;
test 3 100 MB x 10 clients ~156 MB/s with 10/10 downloads verified; test 4 all nine transfers
(3 sizes x upload/download/send) PASS the SHA-256 check. Protocol tests pass.

---

## Step 11: README

**My prompt:** "next"

**AI output:** README rewritten for A2 in five commits:
- `readme: rewrite for A2: features, requirements and how to run`
- `readme: document the A2 protocol and security design` (command table, sequence diagrams)
- `readme: add the demos (bad certificate, integrity failure, Wireshark)`
- `readme: add tests, experiment results, problems fixed and limitations`
- `readme: add the AI usage section`

**What I checked:** a packet capture on loopback (Python scapy, standing in for Wireshark),
running the same actions against A1 and A2. A1: the password, a broadcast message and a
file's contents were readable in the capture. A2: 58 packets, none of them readable; the
first bytes `16 03 01` are a TLS handshake record. Every command and error code in the
README's table was taken from the server code.

---

## Step 12: package the submission

**My input:** chose **"Include them"** when the AI asked whether the zip should contain
ready-made certificates and keys.

**AI output:**
- `readme: say that the submission zip includes the certificates`
- `2024261_A2.zip`, built from the `a2` branch with freshly generated certificates
  (CA, server, and the rogue one for the demo), without runtime folders.

**Problem found while testing the zip:** a client session from the unzipped folder sometimes
hung after sending its first command (REGISTER), and the server never received it (3 of 6 starts,
then 3 of 20 in a control run). Thread dumps: the main thread had sent REGISTER and was waiting;
the reader thread was blocked inside an SSL read. Cause: TLS 1.3 session tickets sent right
after the handshake were being processed by the reader thread while the main thread wrote on
the same TLS connection. (An earlier "hang" in step 6 that the AI put down to output
buffering was most likely this same bug.)

- `server: do not send TLS 1.3 session tickets` (`ctx.num_tickets = 0`): 20/20 client starts work.
- `client: exit cleanly on Ctrl+C or end of input at the login prompt` (found in the same testing)
- `readme: ...` problem added to "Problems found and fixed"

**What I checked:** unzipped into an empty folder; the 47 tests pass there using the bundled
certificates (no OpenSSL run); a client registers, logs in, uploads and lists files; test 4 passes;
the TLS concurrency stress test (4 x 8 MB sends to one user while that user sends commands)
passes 5/5.

---

## Step 13: results on my laptop and the report

**My prompts / choices:** "next"; chose **"Full technical report"**; for the results:
**"you can run it on my laptop"**.

**AI output:**
- Ran everything on my laptop (Linux VM on the laptop, Python 3.10) through the Claude desktop
  app: the 47 protocol tests pass; tests 1-4 for A2; tests 1-3 for A1 for comparison.
- **Problem found:** a 1 MB upload took ~43 ms every time while a 10 MB upload took ~22 ms
  and every download ~2 ms. Same Nagle/delayed-ACK effect as in step 10, this time on the
  client's writes (only the server had TCP_NODELAY).
  - `client: send small writes immediately (TCP_NODELAY)` (1 MB upload now ~3 ms)
  - `experiments, tests: use TCP_NODELAY like the real client`
- `readme: use the results measured on my laptop, with A1 for comparison`
- `2024261_A2.pdf`: the technical report (introduction, design, implementation, security
  demos, results, challenges, conclusion, AI usage).

A packet capture could not be run inside the laptop's VM (no capture permission), so the
report uses the loopback capture from step 11; the Wireshark screenshot is mine to add.

---

## Step 14: requirement audit before submission

**My prompt:** "check alll the requirements as i donot wantt o lose marks"

**AI output:** an audit script (not part of the submission) that unzips the submission and checks
every requirement of the A2 PDF and every A1 command with the real client program, plus a packet
capture of the whole run. First result: 34/36. The two gaps, and one extra fix:
- `certs: also make an expired certificate for the rejection demo` ("reject invalid or untrusted
  certificates": until then only untrusted and wrong-address certificates were demonstrated;
  `openssl ca` can set past dates, which `req -x509` cannot)
- `tests: check that the client rejects an expired certificate` (48 checks)
- `client: hide the password while it is typed` (getpass on a terminal)
- `readme: expired-certificate demo, CA key not shipped, 48 checks`
- The zip no longer contains `certs/ca.key`: it is only needed to sign certificates, and anyone
  holding it could make certificates every client trusts.

**What I checked:** the audit on the rebuilt zip (see the final result in the report).

---

## Step 15: one commit per step

**My prompts / choices:** "where can i loose marks" (a list of risks, no code);
"76 commits in one day is too much"; chose **"Squash to one commit per step (Recommended)"**.

**AI output:**
- The history of branch `a2` (and `main`, where `a2` had been merged) rewritten to one commit
  per step, Step 1 to Step 14, each with the date of the last change in that step; the list of
  the original small commits is kept in each commit message. The final files are identical.
- This entry and the note at the top of this log; the README's AI section updated.
- The full detailed history kept as a backup file (not pushed).

**What I checked:** `git diff` between the old and new history is empty; the 48 tests pass.

---

## Step 16: end-to-end encryption of MSG and SEND

**My prompt:** "The end-to-end encryption means that only the intended receiver should be able to
see the decrypted data. If server is only a relay, then it should not be able to see it."

The AI pointed out that A2 did not meet this yet: TLS ends at the server, so the server
decrypted every relayed MSG / BROADCAST / SEND. It asked three questions; my answers: I can
still resubmit; use the **"cryptography package (Recommended)"** (Python's standard library
has no RSA or AES); encrypt **"MSG + SEND (Recommended)"** (the one-to-one relays).

**AI output** (one commit, "Step 16"):
- `client/e2e.py`: each user's RSA-2048 key pair, made by their client on first login
  (private key stays in `client/keys/`); hybrid encryption: random AES-256-GCM key per message
  or file, wrapped with RSA-OAEP (SHA-256) for the receiver; sender, receiver and kind are
  authenticated with the GCM tag; the file name is encrypted too; trust on first use of each
  peer's key (refuse if it changes), with fingerprints to compare in person.
- `server/server.py`: `PUBKEY` (store a user's public key) and `GETKEY` (hand it out);
  logs that an end-to-end message / file was relayed without being readable. The server
  stays standard-library only and never decrypts.
- `client/client.py`: publishes the key at login; `msg` and `send` encrypt for the receiver;
  incoming ones are decrypted (a failure is reported and nothing is saved).
- `demo/curious_server.py`: the real server, printing everything it reads after TLS.
- `tests/test_e2e.py` (20 checks, two real clients); experiment 4's send is end-to-end
  encrypted; README and `requirements.txt` (`cryptography`).

**What I checked:** the curious server's output for a message and a file (only `E2E:` +
base64, and `SEND|bob|E2E|4505|...` with random bytes); `tests/test_e2e.py` and the 48
`tests/test_protocol.py` checks pass in the container and on my laptop; experiment 4 on my
laptop (3 runs, all PASS). Known limits are in the README (first key trusted as given;
messages not signed; BROADCAST and uploads protected by TLS only).

