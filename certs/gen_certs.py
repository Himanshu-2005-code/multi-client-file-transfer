"""
Generate the certificates and keys for the secure file transfer server.

Uses OpenSSL (open-source command-line tool). Creates, in this folder:

    ca.key       private key of our own Certificate Authority (CA). Keep secret.
    ca.crt       CA certificate. Given to every client: "trust servers signed by this CA".
    server.key   server's private key. Only the server has it.
    server.csr   certificate signing request (intermediate file).
    server.crt   server certificate = server's public key + names, signed by the CA.
    expired.crt  the same server certificate but valid only in January 2025, signed by
                 the CA: used to show the client rejecting an expired (invalid) certificate.

Run:   python certs/gen_certs.py                 (localhost / 127.0.0.1 only)
       python certs/gen_certs.py 192.168.1.5     (also valid at a LAN IP)
"""

import os
import shutil
import subprocess
import sys
import tempfile

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

    print("7. Expired certificate for the demo (valid only in January 2025)")
    # 'openssl ca' is the OpenSSL command that can set explicit start/end dates;
    # it needs a small CA database, kept in a temporary folder.
    with tempfile.TemporaryDirectory() as db:
        with open(os.path.join(db, "index.txt"), "w"):
            pass
        with open(os.path.join(db, "serial"), "w") as f:
            f.write("1000\n")
        cnf = os.path.join(db, "ca.cnf")
        unix_db = db.replace("\\", "/")   # OpenSSL config treats '\' as an escape (Windows paths)
        with open(cnf, "w") as f:
            f.write("[ca]\ndefault_ca = d\n[d]\n"
                    f"database = {unix_db}/index.txt\n"
                    f"serial = {unix_db}/serial\n"
                    f"new_certs_dir = {unix_db}\n"
                    "default_md = sha256\npolicy = p\n[p]\ncommonName = supplied\n")
        run(openssl, "ca", "-batch", "-config", cnf, "-cert", "ca.crt", "-keyfile", "ca.key",
            "-in", "server.csr", "-out", "expired.crt", "-notext",
            "-startdate", "20250101000000Z", "-enddate", "20250201000000Z",
            "-extfile", os.path.basename(ext_used))

    if ext_used != ext:
        os.remove(ext_used)
    print("\nDone. Server uses server.crt + server.key; clients use ca.crt.")
    print("ca.key is only needed to sign certificates: keep it private, do not hand it out.")


if __name__ == "__main__":
    main()
