# Application-Layer Protocol Specification

## 1. Overview

This document specifies a custom, text-based, line-oriented application
protocol running on top of TCP. It is used by the multi-client file
transfer system to handle authentication, presence, private/broadcast
messaging, and file transfer (client↔server and client↔client via the
server).

The protocol is connection-oriented: a client opens one TCP connection to
the server, authenticates, and keeps that connection open for the rest of
the session (all messaging and file transfer happen over that same
socket).

## 2. Message Format

Every **control message** is a single line of UTF-8 text, terminated by
`\n`:

```
COMMAND|FIELD1|FIELD2|...
```

- Fields are separated by the `|` character.
- The final field of a message may itself contain `|` characters (used for
  free-text message bodies in `MSG`/`BROADCAST`); every other field must
  not contain `|` or a literal newline.
- Every control message is read using a length-agnostic line reader (read
  byte-by-byte until `\n`), so no message needs to declare its own length.

**File payloads** are the one exception: raw binary bytes cannot safely be
represented as a delimited text line. Whenever a control message announces
a file transfer, it includes an exact byte count as a field. Immediately
after that control line, exactly that many raw bytes follow with **no**
delimiter or framing — the receiver already knows how many bytes to read.

## 3. Commands

| Command | Direction | Format | Purpose |
|---|---|---|---|
| `LOGIN` | C→S | `LOGIN\|username\|password` | Authenticate. Unknown usernames are auto-registered with the given password. |
| `LOGOUT` | C→S | `LOGOUT` | Gracefully end the session; server closes the connection. |
| `LIST` | C→S | `LIST` | Request the list of currently online users. |
| `FILES` | C→S | `FILES` | Request the list of files currently stored on the server (available for `DOWNLOAD`). |
| `MSG` | C→S | `MSG\|username\|text` | Send a private message to one online user. |
| `MSG` | S→C | `MSG\|sender\|text` | Delivery of a private message (pushed to the recipient). |
| `BROADCAST` | C→S | `BROADCAST\|text` | Send a message to every other online user. |
| `BROADCAST` | S→C | `BROADCAST\|sender\|text` | Delivery of a broadcast (pushed to every recipient). |
| `UPLOAD` | C→S | `UPLOAD\|filename\|filesize` | Push a file to server storage. Followed by `filesize` raw bytes once the server replies `READY`. |
| `DOWNLOAD` | C→S | `DOWNLOAD\|filename` | Request a file from server storage. |
| `SEND` | C→S | `SEND\|targetuser\|filename\|filesize` | Send a file directly to another online user, relayed live through the server. Followed by `filesize` raw bytes once the server replies `READY`. |

## 4. Server Responses

| Response | Format | Meaning |
|---|---|---|
| `LOGIN_OK` | `LOGIN_OK\|username` | Login accepted. |
| `LOGOUT_OK` | `LOGOUT_OK` | Logout acknowledged; connection will be closed. |
| `USERS` | `USERS\|name1,name2,...` | Reply to `LIST`. Comma-separated, possibly empty. |
| `FILES` | `FILES\|file1,file2,...` | Reply to `FILES`. Comma-separated, possibly empty. |
| `MSG_OK` | `MSG_OK` | Private message was delivered. |
| `BROADCAST_OK` | `BROADCAST_OK` | Broadcast was relayed to all other online users. |
| `READY` | `READY` | Server is ready to receive the raw file bytes for an `UPLOAD` or `SEND`. |
| `UPLOAD_OK` | `UPLOAD_OK\|filename` | File stored successfully. |
| `DOWNLOAD_OK` | `DOWNLOAD_OK\|filename\|filesize` | Followed immediately by `filesize` raw bytes. |
| `SEND_OK` | `SEND_OK\|filename` | File was relayed to the target user. |
| `SEND_INCOMING` | `SEND_INCOMING\|filename\|sender\|filesize` | **Push**, not a reply: notifies the recipient of an inbound `SEND`. Followed immediately by `filesize` raw bytes. |
| `ERROR` | `ERROR\|CODE` | See §5. |

Note the asymmetry: `MSG`, `BROADCAST`, and `SEND_INCOMING` are the three
message types a client can receive **unsolicited** (not as a direct reply
to a command it just issued) — a client implementation must be able to
tell these apart from ordinary replies (see §7).

## 5. Error Codes

| Code | Sent when |
|---|---|
| `BAD_ARGS` | Wrong number of fields, or a non-integer where a size was expected. |
| `AUTH_FAILED` | Username exists and the password doesn't match. |
| `USER_ALREADY_ONLINE` | That username already has an active session. |
| `NOT_LOGGED_IN` | Any command other than `LOGIN` sent before authenticating. |
| `ALREADY_LOGGED_IN` | `LOGIN` sent on a connection that already authenticated. |
| `UNKNOWN_COMMAND` | Command name not recognized. |
| `USER_NOT_FOUND` | `MSG` or `SEND` target is not currently online. |
| `FILE_NOT_FOUND` | `DOWNLOAD` requested a file that doesn't exist in server storage. |

## 6. Sequence Diagrams

### 6.1 Login

```
Client                          Server
  |--- LOGIN|alice|secret ------->|
  |                                | check credentials, register session
  |<-------- LOGIN_OK|alice -------|
```

### 6.2 Private message

```
Alice                Server                Bob
  |-- MSG|bob|hi --->|                      |
  |                   |-- MSG|alice|hi ---->|   (unsolicited push)
  |<---- MSG_OK ------|                      |
```

### 6.3 Upload / Download

```
Client                          Server
  |-- UPLOAD|f.txt|1024 --------->|
  |<---------- READY -------------|
  |-- <1024 raw bytes> ---------->|
  |<------ UPLOAD_OK|f.txt -------|

Client                          Server
  |-- DOWNLOAD|f.txt ------------>|
  |<-- DOWNLOAD_OK|f.txt|1024 ----|
  |<----- <1024 raw bytes> -------|
```

### 6.4 Client-to-client SEND (relayed live through the server)

```
Alice                    Server                    Bob
  |-- SEND|bob|f|1024 -->|                          |
  |<------ READY --------|                          |
  |-- <1024 raw bytes> ->|                          |
  |                       |-- SEND_INCOMING|f|alice|1024 -->|  (push)
  |                       |------- <1024 raw bytes> ------->|
  |<---- SEND_OK|f -------|                          |
```

The server does not persist `SEND` payloads to disk — it pulls the bytes
off the sender's socket and immediately relays them to the target's
socket. This means the target must be online at the time of the `SEND`
(offline delivery is out of scope for this assignment).

## 7. Distinguishing Pushes from Replies (Client Design Note)

Because a single TCP connection carries both the replies to commands the
client itself issued *and* asynchronous pushes from other users, the
client's read loop must disambiguate by command name: `MSG`, `BROADCAST`,
and `SEND_INCOMING` are always pushes and are handled immediately (printed,
or — for `SEND_INCOMING` — read and saved to disk); every other command
name is treated as the reply to whatever request the client's main thread
is currently waiting on.
