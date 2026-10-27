"""
Make an UNTRUSTED certificate, to show the client rejecting a fake server.

Creates rogue.key and rogue.crt: a self-signed certificate for localhost /
127.0.0.1. Its names and dates are valid, but it is NOT signed by our CA
(ca.crt), so a client that trusts only our CA must refuse it. This is what an
attacker pretending to be our server (man-in-the-middle) would have.

Run:   python certs/gen_rogue_cert.py
Then:  python server/server.py --cert certs/rogue.crt --key certs/rogue.key
       python client/client.py        -> "Server certificate rejected"
"""

import os

from gen_certs import HERE, KEY_BITS, find_openssl, run


def main():
    openssl = find_openssl()
    print("Self-signed certificate NOT issued by our CA")
    run(openssl, "req", "-x509", "-newkey", f"rsa:{KEY_BITS}", "-nodes",
        "-keyout", "rogue.key", "-out", "rogue.crt", "-days", "365", "-sha256",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
    print(f"\nDone: {os.path.join(HERE, 'rogue.crt')} (untrusted on purpose)")


if __name__ == "__main__":
    main()
