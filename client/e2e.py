"""
End-to-end encryption for MSG and SEND (Assignment 2).

TLS protects each client <-> server link, but the server decrypts it: for a
relayed message or file the server would see the plaintext. Here the SENDER's
client encrypts for the RECEIVER's public key, so the server only relays bytes
it cannot decrypt. Only the receiver's private key can open them.

Hybrid encryption (the same idea TLS uses inside):
  1. a fresh random 256-bit AES key for every message / file
  2. data encrypted with AES-256-GCM (confidentiality + an authentication tag:
     any change to the ciphertext makes decryption fail)
  3. the AES key encrypted ("wrapped") with the receiver's RSA-2048 public key,
     RSA-OAEP with SHA-256. RSA can only encrypt a few hundred bytes, so it
     carries the key, and AES carries the data.

Envelope (bytes):  wrapped AES key (256) | nonce (12) | AES-GCM ciphertext + tag (16)
The associated data (authenticated, not encrypted) binds the envelope to its
kind, sender and receiver, so it cannot be replayed as a different kind or to
a different person.

Keys: each user's key pair is made by their client on first login and kept in
client/keys/<user>.key (the private key never leaves the client). The public
key is published to the server with PUBKEY; senders fetch it with GETKEY.
The server could hand out a fake public key, so the client remembers each
peer's key fingerprint the first time (client/keys/<user>.known) and refuses to
encrypt if it ever changes ("trust on first use"), and prints the fingerprint
so two users can compare it in person.

Needs the 'cryptography' package (pip install cryptography). The server does
not: it never encrypts or decrypts these envelopes.
"""

import base64
import hashlib
import os
import struct

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    raise SystemExit("[!] End-to-end encryption needs the 'cryptography' package: "
                     "pip install cryptography")

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
RSA_BITS = 2048
WRAPPED_LEN = RSA_BITS // 8          # 256 bytes
NONCE_LEN = 12

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class E2EError(Exception):
    """Decryption failed: wrong key, or the envelope was changed on the way."""


# ---------------------------------------------------------------- own keys

def load_or_create_private_key(username, keys_dir=KEYS_DIR):
    """This user's RSA private key; created (and saved) the first time."""
    os.makedirs(keys_dir, exist_ok=True)
    path = os.path.join(keys_dir, f"{username}.key")
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return key


def public_key_b64(private_key):
    """Public key as one line of base64 (DER), to send in a PUBKEY message."""
    der = private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode("ascii")


def fingerprint(pub_b64):
    """Short SHA-256 fingerprint of a public key, for comparing by eye."""
    h = hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()[:32]
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


def load_public_key(pub_b64):
    return serialization.load_der_public_key(base64.b64decode(pub_b64))


# ---------------------------------------------------------- peers' keys (TOFU)

def check_known_key(owner, peer, pub_b64, keys_dir=KEYS_DIR):
    """
    Trust on first use. Returns "new" (first time: remembered), "same", or
    "CHANGED" (a different key than before: possibly a fake key from the server).
    """
    os.makedirs(keys_dir, exist_ok=True)
    path = os.path.join(keys_dir, f"{owner}.known")
    fp = fingerprint(pub_b64)
    known = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2:
                    known[parts[0]] = parts[1]
    if peer not in known:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{peer} {fp}\n")
        return "new"
    return "same" if known[peer] == fp else "CHANGED"


# ------------------------------------------------------- encrypt / decrypt

def _aad(kind, sender, receiver):
    return f"{kind}|{sender}|{receiver}".encode("utf-8")


def encrypt(pub_b64, plaintext, kind, sender, receiver):
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext, _aad(kind, sender, receiver))
    wrapped = load_public_key(pub_b64).encrypt(aes_key, _OAEP)
    return wrapped + nonce + ct


def decrypt(private_key, envelope, kind, sender, receiver):
    if len(envelope) < WRAPPED_LEN + NONCE_LEN + 16:
        raise E2EError("envelope too short")
    wrapped = envelope[:WRAPPED_LEN]
    nonce = envelope[WRAPPED_LEN:WRAPPED_LEN + NONCE_LEN]
    ct = envelope[WRAPPED_LEN + NONCE_LEN:]
    try:
        aes_key = private_key.decrypt(wrapped, _OAEP)
        return AESGCM(aes_key).decrypt(nonce, ct, _aad(kind, sender, receiver))
    except (ValueError, InvalidTag):
        raise E2EError("cannot decrypt: not for this key, or modified on the way")


# Messages travel inside a text line, so the envelope is base64 with a marker.
MSG_PREFIX = "E2E:"


def encrypt_message(pub_b64, text, sender, receiver):
    env = encrypt(pub_b64, text.encode("utf-8"), "MSG", sender, receiver)
    return MSG_PREFIX + base64.b64encode(env).decode("ascii")


def decrypt_message(private_key, field, sender, receiver):
    env = base64.b64decode(field[len(MSG_PREFIX):])
    return decrypt(private_key, env, "MSG", sender, receiver).decode("utf-8")


# Files: the file NAME is encrypted too (inside the envelope), so the server
# sees only E2E_FILENAME and the envelope size.
E2E_FILENAME = "E2E"


def encrypt_file(pub_b64, filename, data, sender, receiver):
    name = filename.encode("utf-8")
    inner = struct.pack(">H", len(name)) + name + data
    return encrypt(pub_b64, inner, "SEND", sender, receiver)


def decrypt_file(private_key, envelope, sender, receiver):
    inner = decrypt(private_key, envelope, "SEND", sender, receiver)
    (n,) = struct.unpack(">H", inner[:2])
    name = inner[2:2 + n].decode("utf-8")
    return os.path.basename(name.replace("\\", "/")), inner[2 + n:]
