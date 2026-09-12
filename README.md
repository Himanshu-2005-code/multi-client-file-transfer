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