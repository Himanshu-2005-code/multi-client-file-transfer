# Technical Report — Multi-Client File Transfer

## 1. Introduction

The purpose of this project is to build a simple multi-client file
transfer application using TCP sockets in Python. The application follows
a client-server model where multiple clients can connect to one server
and communicate with it using a custom application-layer protocol. The
main aim was to understand how application-layer communication can be
designed on top of TCP and how multiple connections can be handled at the
same time.

The server supports user login, maintains a list of active users, and
processes different commands sent by clients. Users can send private
messages, broadcast messages, upload files to the server, download files
stored on the server, and send a file to another online client through
the server. The server uses a separate thread for each connected client,
which allows multiple clients to stay connected and perform operations
concurrently.

The protocol uses simple text-based control messages in the form of
`COMMAND|FIELD|FIELD`. File contents are handled separately as raw bytes
with the exact file size specified before the transfer. This makes it
possible to use the same TCP connection for both normal commands and file
transfers.

The project was also tested with multiple clients, and performance
experiments were performed for round-trip time, broadcast latency, and
concurrent file downloads. These experiments helped in understanding the
difference between application processing time and actual network delay,
especially when using the local loopback interface.

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

The application was implemented in Python using the built-in TCP socket
and threading libraries. The server creates a TCP socket, binds it to the
selected address and port, and continuously accepts new connections.
Whenever a new client connects, the server creates a separate thread to
handle that client. This prevents one client's activity from blocking the
others.

The server keeps the currently connected users in an `active_clients`
dictionary. Since several client threads can access this shared
dictionary at the same time, a lock is used to protect it. This helps
avoid inconsistent state when users log in, log out, or send messages to
other clients.

The server uses blocking sockets because the application is relatively
small and the assignment requires threading. A thread-per-client approach
was easier to understand and implement than using `select()` or
`asyncio`. Each client connection stays open during the session instead
of creating a new connection for every command.

For sending data, `sendall()` is used so that the complete buffer is sent
before the operation returns. On the receiving side, control messages are
read one byte at a time until a newline is found. This matches the
line-oriented protocol and allows the receiver to know when a control
message is complete.

File transfer uses a different method because file contents are binary
data and cannot safely be treated as text lines. The sender first sends a
control message containing the filename and exact file size. After the
server or receiver sends `READY`, the raw file bytes are transferred. The
receiver then reads exactly the announced number of bytes. This avoids
depending on the TCP connection closing to mark the end of a file.

The client also uses two threads. The main thread handles user input and
sends commands, while a background reader thread performs socket reads.
This is necessary because the client can receive an incoming message or
file from another user even while the user is entering another command.
The reader thread handles unsolicited `MSG`, `BROADCAST`, and
`SEND_INCOMING` messages separately from normal command responses.

The project was kept intentionally simple so that each part of the socket
communication and concurrency model could be understood and tested
independently.

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
  username, wrong password, list, allusers, private message, broadcast,
  upload, download, download of a missing file, files listing,
  client-to-client send, send to an offline user, logout) — **25/25
  checks passed**.
- All three performance scripts (`experiments/test*.py`) were run
  end-to-end against a live server and produced real measurements (not
  just "it doesn't crash").
- During testing with multiple clients connected at once, the server kept
  separate client sessions active simultaneously — commands such as
  `LIST`, messaging, and file operations could be run without any client
  needing to reconnect between operations, consistent with the
  thread-per-client model handling clients independently.
- The logout-handling fix (see prompt log entry 11) was verified directly:
  before the fix, a normal server-side connection close after
  `LOGOUT_OK` was incorrectly reported by the client as an unexpected
  disconnect; after the fix, a clean logout no longer triggers that
  message, while a genuine mid-session drop still does.

*TODO: the automated test above exercises two concurrent clients
end-to-end, but the assignment specifically requires a live demo with 5+
concurrent interactive clients. After running that demo yourself, note
anything you actually observed (e.g. did LOGOUT during an active
BROADCAST work cleanly with 5 clients connected? any timing issues?)
— this can't be filled in until that demo run has actually happened.*

## 7. Challenges

> **Before submitting:** the paragraphs below are a drafted starting
> point, not your own words yet. Read them, make sure you'd actually
> explain it this way if asked live, and rewrite the sentences so they're
> genuinely yours before this goes in the final submission.

One of the main challenges was handling communication when multiple
clients are connected at the same time. The server has to maintain
information about all active users and allow one client thread to send
data to another client's socket. Using a shared `active_clients`
dictionary with a lock made this easier to manage.

Another challenge was deciding how to separate normal protocol messages
from file data. Since TCP provides a continuous byte stream, simply
reading from the socket does not tell the receiver where one application
message ends. The solution was to use newline-terminated control messages
and include an exact byte count for every file transfer. This made the
file boundary clear to the receiver.

Client-side asynchronous messages were another issue. A client cannot
assume that every incoming message is a direct response to the command it
just sent. Another user may send a message, broadcast, or file at any
time. To handle this, the client uses a background reader thread and
distinguishes pushed messages such as `MSG`, `BROADCAST`, and
`SEND_INCOMING` from ordinary command responses.

There was also a logout-related problem during testing. The server
correctly closed the socket after sending `LOGOUT_OK`, but the client
reader thread initially interpreted that close as an unexpected server
disconnection. This was fixed by using an `expected_close` flag so the
client knows that the connection is being closed normally.

The throughput experiment also revealed a limitation in the
implementation. For downloads, the server currently reads the entire file
into memory before sending it. This becomes expensive when ten clients
request a 1 GB file at the same time. The results suggested that memory
pressure was contributing to the large drop in throughput for the 1 GB
experiment. A possible improvement would be to stream the file in
fixed-size chunks instead — this was not implemented, only identified as
a proposed fix, since it wasn't required for this assignment's scope.

## 8. Conclusion

> **Before submitting:** same note as above — rewrite this in your own
> words before it goes in the final submission.

This project gave practical experience with designing and implementing an
application-layer protocol over TCP. Instead of relying only on existing
protocols, the project required defining our own message format,
commands, responses, error conditions, and file-transfer rules.

The implementation also helped in understanding how TCP sockets work in a
real application. In particular, the project showed that TCP provides a
reliable byte stream, but the application still needs its own rules for
identifying messages and file boundaries. The use of newline-delimited
control messages and fixed byte counts for file payloads was one of the
main design decisions.

Another important part of the project was concurrency. Using one thread
for each connected client made it possible to support several clients at
the same time, while the client's reader thread allowed incoming messages
and file transfers to be handled asynchronously.

The performance experiments also showed that network performance is
affected by more than just the protocol itself. In the local loopback
tests, very small RTTs were observed, while larger file transfers exposed
memory and processing limitations in the implementation. Overall, the
project improved my understanding of TCP communication, application-layer
protocol design, file transfer, and concurrent client handling.
