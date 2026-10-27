"""
Integrity demo: deliberately modify a file stored on the server.

This plays the part of an attacker or a disk fault changing a file after
it was uploaded. The server still has the SHA-256 it recorded when the
upload passed its integrity check (server/digests/<name>.sha256), so the
next DOWNLOAD of this file must fail the client's integrity check.

Run (while or after the server runs, from the project folder):
    python demo/tamper_file.py integrity_test.txt
    python demo/tamper_file.py integrity_test.txt --restore   (put the original back)
"""

import argparse
import hashlib
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_DIR = os.path.join(ROOT, "server", "storage")
DIGEST_DIR = os.path.join(ROOT, "server", "digests")
# Originals are kept here (not in storage/, where FILES would list them).
BACKUP_DIR = os.path.join(ROOT, "demo", "backup")


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Modify a file in server/storage on purpose")
    ap.add_argument("filename", help="name of a file uploaded to the server")
    ap.add_argument("--restore", action="store_true", help="put the original file back")
    args = ap.parse_args()

    path = os.path.join(STORAGE_DIR, os.path.basename(args.filename))
    backup = os.path.join(BACKUP_DIR, os.path.basename(path))
    if not os.path.isfile(path):
        sys.exit(f"No such file on the server: {path}. Upload it first.")

    if args.restore:
        if not os.path.isfile(backup):
            sys.exit("No backup to restore (the file was not tampered with by this script).")
        shutil.move(backup, path)
        print(f"Restored the original {os.path.basename(path)}. SHA-256 now: {sha256_file(path)}")
        return

    try:
        with open(os.path.join(DIGEST_DIR, os.path.basename(path) + ".sha256")) as f:
            recorded = f.read().strip()
    except OSError:
        recorded = "(none recorded)"

    before = sha256_file(path)
    if not os.path.isfile(backup):
        os.makedirs(BACKUP_DIR, exist_ok=True)
        shutil.copy2(path, backup)      # keep the original for --restore

    # Flip one bit of the first byte: the smallest possible change
    # (in integrity_test.txt this turns "Integrity" into "Hntegrity").
    with open(path, "r+b") as f:
        first = f.read(1)
        f.seek(0)
        f.write(bytes([first[0] ^ 0x01]))
    after = sha256_file(path)

    print(f"Tampered with server/storage/{os.path.basename(path)} "
          f"(flipped one bit of the first byte: {first!r} -> {bytes([first[0] ^ 0x01])!r})")
    print(f"  recorded at upload : {recorded}")
    print(f"  before tampering   : {before}")
    print(f"  after tampering    : {after}")
    print("Now DOWNLOAD it from a client: the integrity check should FAIL.")


if __name__ == "__main__":
    main()
