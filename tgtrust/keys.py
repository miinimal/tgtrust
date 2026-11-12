"""Generate issuer secrets for a server.

Usage: python -m tgtrust.keys /path/to/issuer_key.pem
Writes a 3072-bit RSA private key with owner-only permissions and prints the
environment lines to add to the server configuration.
"""

from __future__ import annotations

import os
import secrets
import sys

from cryptography.hazmat.primitives import serialization

from .blind_rsa import generate_key


def write_issuer_key(path: str, bits: int = 3072) -> None:
    if os.path.exists(path):
        raise FileExistsError(f"refusing to overwrite existing key: {path}")
    pem = generate_key(bits).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip())
        return 2
    path = os.path.abspath(argv[1])
    write_issuer_key(path)
    print(f"TGTRUST_ISSUER_KEY_FILE={path}")
    print(f"TGTRUST_PSEUDONYM_KEY={secrets.token_hex(32)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
