# Mini Packet Analyzer (Assignment 3)

Team: Himanshu (2024261), Divyansh Goel (2024201)

A simplified, command-line packet analyzer in Python, similar to Wireshark. It
captures the packets sent and received by this computer, numbers and timestamps
them, shows a summary list that can be filtered, and opens any packet to show
its IPv4 header, TCP or UDP header, and payload.

The IPv4, TCP and UDP headers are decoded by our own code from the raw bytes
(Python `struct` and bit operations). No packet-decoding library (Scapy,
PyShark, ...) is used; the operating system only hands us the raw bytes.

## Requirements

- Python 3.9 or newer, standard library only.
- Administrator rights: Windows needs an Administrator terminal, macOS and
  Linux need `sudo`. Capturing packets is a privileged operation.
- Capture only on systems and networks you own or are authorized to analyze.

## Project structure

(added as the code is written)

## Running it

(added as the code is written)

## How a packet is decoded

(added as the code is written)

## Use of AI

See [`AI_PROMPTS.md`](AI_PROMPTS.md): every prompt, word for word, and what the
AI produced at each step.
