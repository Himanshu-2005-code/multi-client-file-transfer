# Multi-Client File Transfer

A TCP-based multi-client file transfer application built for a Computer
Networks course. A multi-threaded server supports concurrent clients
that can authenticate, message each other, and transfer files to and
from the server or directly to another connected client.

## Features

- User authentication (login, auto-registered on first use)
- Multi-threaded server — many simultaneous clients, one thread each
- Private messaging and broadcast messaging
- Upload and download files to/from server storage
- Send a file directly to another online client, relayed through the server
- List online users, list every registered user (online or offline), and list files available on the server
- Custom text-based application-layer protocol over raw TCP sockets
- Performance test scripts for round-trip time, broadcast latency, and concurrent-download throughput

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
Type `help` after logging in for the list of commands (`list`, `allusers`,
`files`, `msg`, `broadcast`, `upload`, `download`, `send`, `logout`).
`list` shows who's online right now; `allusers` shows every registered
account (online or offline); `files` shows what's available to
`download`. Run at least 5 clients at once to demo the
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

## Project Structure

```
server/       TCP server: connection handling, threading, command dispatch
client/       Interactive CLI client
experiments/  Performance test scripts (RTT, broadcast latency, throughput)
tests/        End-to-end protocol test suite
```
