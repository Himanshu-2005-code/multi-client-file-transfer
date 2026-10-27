"""
Generate the certificates and keys for the secure file transfer server.

Uses OpenSSL (open-source command-line tool). Creates, in this folder:

    ca.key       private key of our own Certificate Authority (CA). Keep secret.
    ca.crt       CA certificate. Given to every client: "trust servers signed by this CA".
    server.key   server's private key. Only the server has it.
    server.csr   certificate signing request (intermediate file).
    server.crt   server certificate = server's public key + names, signed by the CA.

Run:   python certs/gen_certs.py                 (localhost / 127.0.0.1 only)
       python certs/gen_certs.py 192.168.1.5     (also valid at a LAN IP)
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DAYS = "365"
KEY_BITS = "2048"


def find_openssl():
    """openssl on PATH, or the copy that ships with Git for Windows."""
    found = shutil.which("openssl")
    if found:
        return found
    for path in (r"C:\Program Files\Git\usr\bin\openssl.exe",
                 r"C:\Program Files (x86)\Git\usr\bin\openssl.exe"):
        if os.path.isfile(path):
            return path
    sys.exit("OpenSSL not found. Install Git for Windows or OpenSSL and try again.")


def run(openssl, *args):
    print("  openssl", " ".join(args))
    subprocess.run([openssl, *args], cwd=HERE, check=True)


def main():
    openssl = find_openssl()
    extra_ips = sys.argv[1:]

    # Extension file for the server certificate, plus any extra IPs.
    ext = os.path.join(HERE, "server_ext.cnf")
    ext_used = ext
    if extra_ips:
        ext_used = os.path.join(HERE, "server_ext_generated.cnf")
        with open(ext, encoding="utf-8") as f:
            text = f.read()
        for n, ip in enumerate(extra_ips, start=2):
            text += f"IP.{n} = {ip}\n"
        with open(ext_used, "w", encoding="utf-8") as f:
            f.write(text)

    print("1. CA private key")
    run(openssl, "genrsa", "-out", "ca.key", KEY_BITS)

    print("2. CA certificate (self-signed: the CA vouches for itself)")
    run(openssl, "req", "-x509", "-new", "-key", "ca.key", "-sha256", "-days", DAYS,
        "-subj", "/CN=CN-A2 Root CA",
        # Mark it as a CA that may sign certificates. Python 3.13+ verifies
        # strictly and rejects a CA certificate without these extensions.
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
        "-out", "ca.crt")

    print("3. Server private key")
    run(openssl, "genrsa", "-out", "server.key", KEY_BITS)

    print("4. Server certificate signing request (CSR)")
    run(openssl, "req", "-new", "-key", "server.key", "-subj", "/CN=localhost",
        "-out", "server.csr")

    print("5. CA signs the CSR -> server certificate")
    run(openssl, "x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
        "-CAcreateserial", "-days", DAYS, "-sha256",
        "-extfile", os.path.basename(ext_used), "-out", "server.crt")

    print("6. Check: server.crt is signed by ca.crt")
    run(openssl, "verify", "-CAfile", "ca.crt", "server.crt")

    if ext_used != ext:
        os.remove(ext_used)
    print("\nDone. Server uses server.crt + server.key; clients use ca.crt.")


if __name__ == "__main__":
    main()
