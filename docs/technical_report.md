# Technical Report — Multi-Client File Transfer

## 1. Introduction

*TODO (write in your own words): what this application does, at a high
level — a TCP server + CLI client supporting login, private/broadcast
messaging, server-stored file upload/download, and direct client-to-client
file transfer relayed through the server, with ≥5 concurrent clients.*

## 2. Design

### 2.1 Architecture

```
                 +--------------------+
                 |       Server       |
                 |  (server/server.py)|
                 |                    |
                 |  accept() loop     |
                 |  1 thread / client |
                 |  active_clients{}  |  <- username -> socket, guarded
                 |                    |     by clients_lock
                 |  server/storage/   |  <- UPLOAD/DOWNLOAD file store
                 +----+----------+----+
                      |          |
        TCP           |          |          TCP
   +------------------+          +------------------+
   |                                                 |
+--v-------------------+                +------------v----------+
|   Client (Alice)      |                |   Client (Bob)        |
| client/client.py      |                | client/client.py      |
|                        |                |                        |
| reader thread: owns    |                | reader thread: owns    |
|   all socket reads;    |                |   all socket reads     |
|   prints MSG/BROADCAST |                |                        |
|   pushes, queues       |                |                        |
|   replies              |                |                        |
|                        |                |                        |
| main thread: input()   |                | main thread: input()   |
|   loop, owns all       |                |   loop                 |
|   socket writes        |                |                        |
+------------------------+                +------------------------+
```

See `docs/protocol_spec.md` for the full wire-format specification.

### 2.2 Key design decisions

- **One thread per client** on the server, coordinated through a single
  `clients_lock`-guarded dict (`active_clients`) mapping username → socket.
  This is what lets `MSG`, `BROADCAST`, and `SEND` look up and write to
  another client's live socket from a different thread.
- **Client read/write split**: a client's background *reader* thread owns
  every `recv()` on the socket (including pulling file bytes off the wire
  for `DOWNLOAD` and `SEND_INCOMING`), while the main thread owns every
  `send()`. Because TCP's two directions are independent, this needs no
  locking around the socket itself, and it lets the client display an
  incoming `MSG`/`BROADCAST`/file push at any time, even while the user is
  mid-typed-command.
- **Length-prefixed binary transfer**: control messages are line-delimited
  text, but file bytes are raw with an exact byte count announced
  beforehand — avoids ambiguity between binary data and the `|`/`\n`
  delimiters used by the text protocol.
- **`SEND` is a live relay, not store-and-forward**: the server pulls the
  file off the sender's socket and immediately pushes it to the target's
  socket without touching disk. Simpler and faster, at the cost of
  requiring the target to be online at send time.

## 3. Implementation

*TODO: describe the socket programming techniques you'd highlight in your
own words — e.g. `SO_REUSEADDR`, blocking sockets + threading (vs.
`select`/`asyncio`), `sendall` vs. `send`, the line-reader implemented
byte-by-byte, thread safety around `active_clients`.*

Source layout:

| Path | Contents |
|---|---|
| `server/server.py` | Server: connection accept loop, per-client thread, command dispatch |
| `server/protocol.py` | Wire-format helpers (identical copy on the client side) |
| `client/client.py` | Interactive CLI client: reader thread + command loop |
| `client/protocol.py` | Wire-format helpers |
| `docs/protocol_spec.md` | Full protocol specification |
| `experiments/test1_rtt.py` | Performance Test 1 (RTT) |
| `experiments/test2_broadcast_latency.py` | Performance Test 2 (broadcast latency to 5 clients) |
| `experiments/test3_throughput.py` | Performance Test 3 (concurrent download throughput) |
| `tests/test_protocol.py` | End-to-end functional test covering every command and error path |

## 4. Experimental Results

All measurements below are from a real run against a live server on
localhost (`127.0.0.1:5050`), one client machine acting as both client and
server (loopback). A real multi-machine network would add real
propagation delay and NIC-level bandwidth limits that loopback doesn't
have, so these numbers represent a best case, not a real-network
prediction.

### Test 1 — RTT (1 client, request/response, 100 repetitions)

```
Test 1: RTT over 100 requests
  min:    0.042 ms
  avg:    0.054 ms
  median: 0.047 ms
  max:    0.212 ms
```

Sub-millisecond RTT is expected on loopback -- there's no physical network
hop, so the time measured here is essentially thread scheduling and
socket syscall overhead, not network latency. The `max` (0.212 ms) being
~4x the `min` is consistent with occasional OS thread-scheduling jitter
rather than anything protocol-related.

### Test 2 — Broadcast latency (server → 5 clients)

```
Test 2: broadcast delivery latency to 5 clients
  avg: 0.685 ms
  min: 0.543 ms
  max: 0.821 ms
```

Latency here is higher than the single-request RTT in Test 1, which makes
sense: a `BROADCAST` requires the server to iterate over 5 sockets and
call `send_line` on each one sequentially (see `handle_broadcast` in
`server/server.py`) before any of the 5 receiver threads can even start
reading their copy, so the last receiver's timestamp includes the fan-out
delay for every client relayed to before it.

### Test 3 — Throughput (10 clients downloading concurrently)

```
1 MB file:
  total transferred: 10.00 MB
  elapsed:           0.035 s
  server throughput: 286.81 MB/s

100 MB file:
  total transferred: 1000.00 MB
  elapsed:           4.107 s
  server throughput: 243.46 MB/s

1000 MB (1 GB) file:
  total transferred: 10000.00 MB
  elapsed:           221.621 s
  server throughput: 45.12 MB/s
```

Throughput drops sharply as file size grows -- from ~287 MB/s at 1 MB to
just ~45 MB/s at 1 GB, roughly a 6x fall-off, not the flat or gently
declining curve you might expect from network overhead alone. The likely
cause is in `handle_download` (`server/server.py`): the server reads the
**entire** file into memory (`data = f.read()`) before sending it in one
`send_exact` call. With 10 clients concurrently downloading a 1 GB file,
that's up to 10 GB held in memory across 10 threads simultaneously,
which pushes the machine into heavy memory pressure/paging well before
the network itself becomes the bottleneck. At 1 MB and 100 MB per client
(10 MB and 1000 MB total resident at once), memory pressure is much less
of a factor, which is consistent with those two runs both staying above
240 MB/s. A straightforward fix would be to stream the file in fixed-size
chunks (e.g. 1 MB at a time) instead of loading it whole, bounding memory
use regardless of file size or client count -- noted here as a known
limitation rather than implemented, since it wasn't required for this
assignment's scope.

## 5. Prompts of AI Use

AI (Claude, via Claude Code) was used to generate individual pieces of code
in small increments, per the assignment's AI policy. Every prompt used is
listed below, in the order the code was produced. Each one produced a
distinct, reviewed chunk that was tested before moving to the next.

1. *"Write a small Python module with wire-format helpers for a TCP app:
   send/receive a `COMMAND|FIELD|FIELD` text line terminated by `\n`, plus
   helpers to send/receive an exact number of raw bytes for file
   payloads."* → `server/protocol.py` / `client/protocol.py`

2. *"Write a multi-threaded TCP server in Python. It should accept
   connections in an infinite loop, spawn a thread per client, keep a
   thread-safe registry of active username→socket, and implement LOGIN
   (check against a simple username:password text file, auto-register
   unknown users, reject already-logged-in usernames), LOGOUT, and LIST
   (return comma-separated active usernames)."* → `server/server.py`
   (skeleton)

3. *"Add MSG <user> <text> (private message forwarded to a specific
   logged-in user, with an error if that user isn't online) and BROADCAST
   <text> (forwarded to every other logged-in user) to the server's
   command dispatch."* → `server/server.py` (messaging)

4. *"Add UPLOAD <filename> <filesize> (client pushes a file to server
   storage: server replies READY, reads exactly filesize bytes, saves it,
   replies UPLOAD_OK) and DOWNLOAD <filename> (server replies DOWNLOAD_OK
   with the size then streams the bytes, or ERROR FILE_NOT_FOUND) to the
   server."* → `server/server.py` (file transfer)

5. *"Add SEND <targetuser> <filename> <filesize> to the server: relay a
   file live from the sending client straight to the target client's
   socket if the target is online (READY, read bytes, push SEND_INCOMING
   header + bytes to target, confirm SEND_OK to sender); if the target
   isn't online, reply ERROR USER_NOT_FOUND."* → `server/server.py`
   (client-to-client relay)

6. *"Write a TCP client with a background reader thread that owns all
   socket reads: it prints incoming MSG/BROADCAST pushes immediately, and
   puts any other line (a reply to a command the main thread just sent)
   onto a queue. The main thread has an interactive loop parsing user
   commands (login, logout, list, msg, broadcast) and blocks on the queue
   for each command's reply."* → `client/client.py` (skeleton)

7. *"Add upload and download commands to the client. Upload: send UPLOAD
   header, wait for READY on the reply queue, then send the file bytes
   and wait for UPLOAD_OK. Download: send DOWNLOAD header; since the
   reader thread also has to pull the raw file bytes off the socket for a
   DOWNLOAD_OK reply, have the reader thread do that read-and-save itself
   before queuing the reply."* → `client/client.py` (file transfer)

8. *"Add a send command to the client (send SEND header with
   target/filename/size, wait for READY, then push the file bytes and
   wait for SEND_OK), and make the reader thread's SEND_INCOMING handler
   actually read the pushed file's bytes and save it to a received/
   folder instead of just printing a placeholder."* → `client/client.py`
   (client-to-client send)

9. *"Write three standalone scripts against the running server: (1) one
   client repeatedly round-trips a LIST request and measures RTT
   (min/avg/max), (2) one sender broadcasts a timestamped message to 5
   already-connected clients and each measures its own receive latency,
   averaged, (3) N clients concurrently DOWNLOAD a file of a given size
   and the script measures aggregate server throughput in MB/s."* →
   `experiments/test1_rtt.py`, `experiments/test2_broadcast_latency.py`,
   `experiments/test3_throughput.py`

10. *"Write a 2–3 page protocol specification document (message format,
    full command/response table, error codes, and sequence diagrams for
    login, private message, upload/download, and client-to-client send)
    describing the COMMAND|FIELD|... protocol I just implemented."* →
    `docs/protocol_spec.md`

11. (Bug investigation, not a generation prompt) Diagnosed a reported
    "disconnected from server" message appearing after a normal `logout`.
    Root cause: the client's reader thread noticed the server closing its
    socket right after `LOGOUT_OK` and misreported it as an unexpected
    drop. Fixed with an `expected_close` flag, set *before* `LOGOUT` is
    sent (not after the reply, which raced against the server's close).
    Also added a try/except around the server's per-command dispatch so
    any future unexpected exception prints a full traceback to the server
    console and reports `ERROR|SERVER_ERROR` to the client, instead of
    silently dropping the connection. → `client/client.py`,
    `server/server.py`

12. *"Add a FILES command to the server (returns comma-separated list of
    filenames currently in server storage) and a matching `files` command
    to the client that displays them."* → `server/server.py`,
    `client/client.py`

13. *"Add an ALLUSERS command to the server that returns every registered
    account (from users.txt) along with whether each one is currently
    online or offline, so it's a proper directory, not just
    currently-connected users like LIST/FILES."* → `server/server.py`,
    `client/client.py`

Each chunk was compiled and run against a live server before moving to the
next (see §6 for the concrete verification done). All code was reviewed
and is understood well enough to be explained command-by-command in the
demo.

## 6. Verification Performed

- `python -m py_compile` on all four source files — no syntax errors.
- `tests/test_protocol.py`: an end-to-end functional test that starts a
  real server subprocess and drives two real client connections through
  every command and every documented error path (login, duplicate
  username, wrong password, list, private message, broadcast, upload,
  download, download of a missing file, client-to-client send, send to an
  offline user, logout) — **22/22 checks passed**.
- All three performance scripts (`experiments/test*.py`) were run
  end-to-end against a live server and produced real measurements (not
  just "it doesn't crash").

*TODO: after your own demo run with 5+ concurrent interactive clients,
note anything you observed (e.g. did LOGOUT during an active BROADCAST
work cleanly? any timing issues?).*

## 7. Challenges

*TODO (write in your own words): problems you personally ran into and how
you solved them — e.g. reasoning about which thread owns socket reads vs.
writes, deciding on the `SEND_INCOMING` push design, testing concurrency,
etc. This section should reflect your own understanding, since you need
to be able to explain it live.*

## 8. Conclusion

*TODO (write in your own words): what you learned about application-layer
protocol design, TCP socket programming, and concurrency from this
assignment.*
