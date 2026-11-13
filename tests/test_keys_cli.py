"""tgtrust.keys command line."""

import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tgtrust import keys


def test_usage_without_path(capsys):
    assert keys.main(["keys"]) == 2
    assert "Usage: python -m tgtrust.keys" in capsys.readouterr().out


def test_generates_key_file_and_env_lines(tmp_path, capsys):
    path = str(tmp_path / "issuer.pem")
    assert keys.main(["keys", path]) == 0
    if os.name != "nt":  # Windows has no POSIX file modes
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 3072
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert lines[0] == f"TGTRUST_ISSUER_KEY_FILE={path}"
    assert lines[1].startswith("TGTRUST_PSEUDONYM_KEY=")
    secret = lines[1].split("=", 1)[1]
    assert len(secret) == 64
    int(secret, 16)


def test_refuses_to_overwrite(tmp_path):
    path = str(tmp_path / "issuer.pem")
    keys.main(["keys", path])
    with open(path, "rb") as fh:
        before = fh.read()
    with pytest.raises(FileExistsError):
        keys.main(["keys", path])
    with open(path, "rb") as fh:
        assert fh.read() == before
