# Multi-Client File Transfer

A TCP-based multi-client file transfer application developed for the Computer Networks course.

## Planned Features

- User authentication
- Multiple simultaneous TCP clients
- File upload and download
- Client-to-client file transfer through the server
- Custom application-layer protocol
- Performance analysis with concurrent clients

## Technology

- Python
- TCP Sockets
- Threading

## Running

Requires only the Python standard library (no `pip install` needed).

**1. Start the server** (defaults to `0.0.0.0:5050`):

```
python server/server.py
```

**2. Start one or more clients** (defaults to `127.0.0.1:5050`), each in
its own terminal:

```
python client/client.py
```

Log in with any username/password — unknown usernames are auto-registered.
Type `help` after logging in for the list of commands (`list`, `files`,
`msg`, `broadcast`, `upload`, `download`, `send`, `logout`). `files` shows
every file currently stored on the server, so you know what's available
before running `download`. Run at least 5 clients at once to demo the
concurrency requirement.

**3. Run the automated protocol test** (starts its own server, no setup
needed):

```
python tests/test_protocol.py
```

**4. Run the performance experiments** against a running server:

```
python experiments/test1_rtt.py 127.0.0.1 5050
python experiments/test2_broadcast_latency.py 127.0.0.1 5050
python experiments/test3_throughput.py 127.0.0.1 5050 1     # 1 MB
python experiments/test3_throughput.py 127.0.0.1 5050 100   # 100 MB
python experiments/test3_throughput.py 127.0.0.1 5050 1000  # 1 GB
```

See `docs/protocol_spec.md` for the full protocol specification and
`docs/technical_report.md` for the report skeleton (fill in the
experimental results and reflection sections with your own run).

# Application-Layer Protocol

## Overview

This project uses a custom text-based application-layer protocol over TCP.

Commands and responses are exchanged between the client and server using a
simple structured format.

## Message Format

Messages use the following format:

COMMAND|FIELD1|FIELD2|...

The `|` character separates different fields in a message.

## Initial Commands

| Command | Purpose |
|---|---|
| LOGIN | Authenticate a user |
| LIST | List currently connected users |
| MSG | Send a message to another user |
| UPLOAD | Upload a file to the server |
| DOWNLOAD | Download a file from the server |
| SEND | Send a file to another user |
| LOGOUT | Disconnect from the server |

## Example

Client:

LOGIN|alice|password123

Server:

LOGIN_OK|alice

## Error Responses

The server can return errors using:

ERROR|INVALID_COMMAND
ERROR|AUTH_FAILED
ERROR|USER_ALREADY_ONLINE
ERROR|FILE_NOT_FOUND
ERROR|USER_NOT_FOUND