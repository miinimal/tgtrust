"""A wrong or missing issuer key file stops the start with one line naming the setting."""
import datetime
import glob
import os
import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from tgtrust.service import Settings, create_app, load_issuer

PREFIX = "cannot load issuer key TGTRUST_ISSUER_KEY_FILE="
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def settings_for(tmp_path, key_path):
    return Settings.from_env({
        "TGTRUST_BOT_ID": "123456",
        "TGTRUST_ISSUER_KEY_FILE": str(key_path),
        "TGTRUST_PSEUDONYM_KEY": os.urandom(32).hex(),
        "TGTRUST_DB_PATH": str(tmp_path / "issued.db"),
        "TGTRUST_REGISTRY_DB_PATH": str(tmp_path / "registry.db"),
        "TGTRUST_DEALS_DB_PATH": str(tmp_path / "deals.db"),
        "TGTRUST_DISPUTES_DB_PATH": str(tmp_path / "disputes.db"),
    })


def pem(key, fmt=serialization.PrivateFormat.PKCS8, enc=None):
    return key.private_bytes(
        serialization.Encoding.PEM, fmt, enc or serialization.NoEncryption())


def rsa_key(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def certificate_pem(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def public_pem(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def encrypted_pem(key):
    return pem(key, enc=serialization.BestAvailableEncryption(b"pw"))


GARBAGE = b"hello SECRET-CONTENT-123"

# name -> (bytes written to the file, reason phrase)
CONTENT_CASES = {
    "empty": (b"", "file is empty"),
    "garbage": (GARBAGE, "not a PEM private key"),
    "public_key": (lambda: public_pem(rsa_key(2048)), "not a PEM private key"),
    "certificate": (lambda: certificate_pem(rsa_key(2048)), "not a PEM private key"),
    "encrypted": (lambda: encrypted_pem(rsa_key(2048)),
                  "key is password-protected; the service needs an unencrypted key"),
    "ec": (lambda: pem(ec.generate_private_key(ec.SECP256R1())),
           "not an RSA key (found ...)"),
    "ed25519": (lambda: pem(ed25519.Ed25519PrivateKey.generate()),
                "not an RSA key (found Ed25519PrivateKey)"),
    "rsa1024": (lambda: pem(rsa_key(1024)), "RSA key is 1024 bits; at least 2048 are required"),
}


def expect_failure(tmp_path, path):
    with pytest.raises(RuntimeError) as info:
        load_issuer(settings_for(tmp_path, path))
    text = str(info.value)
    assert text.startswith(PREFIX)
    assert str(path) in text
    assert "cryptography.io" not in text
    return text


@pytest.mark.parametrize("case", list(CONTENT_CASES))
def test_bad_content(tmp_path, case):
    content, reason = CONTENT_CASES[case]
    if callable(content):
        content = content()
    path = tmp_path / "issuer.pem"
    path.write_bytes(content)
    text = expect_failure(tmp_path, path)
    if case == "ec":
        # the type name differs between cryptography versions; the phrase around it is fixed
        assert "not an RSA key (found " in text and "PrivateKey)" in text
    else:
        assert text == f"{PREFIX}{path}: {reason}"


def test_missing_file(tmp_path):
    path = tmp_path / "nope.pem"
    assert expect_failure(tmp_path, path) == f"{PREFIX}{path}: file not found"


def test_directory(tmp_path):
    path = tmp_path / "adir"
    path.mkdir()
    assert expect_failure(tmp_path, path) == f"{PREFIX}{path}: is a directory"


def test_unreadable_file(tmp_path):
    path = tmp_path / "issuer.pem"
    path.write_bytes(pem(rsa_key(2048)))
    os.chmod(path, 0)
    try:
        try:
            open(path, "rb").close()
        except OSError:
            pass
        else:
            pytest.skip("process can still read a mode-0 file (running as root)")
        text = expect_failure(tmp_path, path)
        assert text == f"{PREFIX}{path}: cannot read file PermissionError"
    finally:
        os.chmod(path, 0o600)


def test_content_never_in_error(tmp_path):
    path = tmp_path / "issuer.pem"
    path.write_bytes(GARBAGE)
    text = expect_failure(tmp_path, path)
    assert "SECRET-CONTENT-123" not in text


def test_rsa_1024_text_names_size(tmp_path):
    path = tmp_path / "issuer.pem"
    path.write_bytes(pem(rsa_key(1024)))
    assert "1024" in expect_failure(tmp_path, path)


@pytest.mark.parametrize("bits", [2048, 3072])
@pytest.mark.parametrize("fmt", [serialization.PrivateFormat.PKCS8,
                                 serialization.PrivateFormat.TraditionalOpenSSL])
def test_good_keys_load(tmp_path, bits, fmt):
    path = tmp_path / "issuer.pem"
    path.write_bytes(pem(rsa_key(bits), fmt))
    assert load_issuer(settings_for(tmp_path, path)) is not None


@pytest.mark.parametrize("fmt", [serialization.PrivateFormat.PKCS8,
                                 serialization.PrivateFormat.TraditionalOpenSSL])
def test_app_on_good_key_answers_health(tmp_path, fmt):
    path = tmp_path / "issuer.pem"
    path.write_bytes(pem(rsa_key(2048), fmt))
    client = TestClient(create_app(settings_for(tmp_path, path)))
    assert client.get("/v1/health").json() == {"status": "ok"}


def test_no_db_file_in_repository_root():
    assert sorted(glob.glob(str(REPO_ROOT / "*.db"))) == []
