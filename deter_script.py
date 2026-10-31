#!/usr/bin/env python3
import hashlib, getpass, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s

passphrase = getpass.getpass("Passphrase: ").encode()
salt = input("Salt: ").encode()

# Stretch the passphrase into a 32-byte seed with a memory-hard KDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

seed = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(passphrase)
key = Ed25519PrivateKey.from_private_bytes(seed)

priv = key.private_bytes(s.Encoding.PEM, s.PrivateFormat.OpenSSH, s.NoEncryption())
pub  = key.public_key().public_bytes(s.Encoding.OpenSSH, s.PublicFormat.OpenSSH)

fd = os.open("id_ed25519", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, priv); os.close(fd)
with open("id_ed25519.pub", "wb") as f:
    f.write(pub + b"\n")
