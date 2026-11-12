"""The browser blind-signature code (tgtrust/webapp/blindrsa.js) against the Python implementation.

Every check runs the JavaScript under Node and compares bytes with ``tgtrust.blind_rsa`` and
``tgtrust.registry``. Skipped when Node 20+ is not installed."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from tgtrust import blind_rsa
from tgtrust.issuer import CREDENTIAL_PREFIX
from tgtrust.registry import agent_token, bind_message
from tgtrust.service import b64url_encode, key_id

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node is not installed")


@pytest.fixture(scope="module")
def js():
    proc = subprocess.Popen([NODE, str(ROOT / "tests" / "webapp" / "crypto_cli.mjs")], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True, cwd=ROOT)

    def call(**cmd) -> dict:
        proc.stdin.write(json.dumps(cmd) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    yield call
    proc.stdin.close()
    proc.wait(timeout=10)


def pem_of(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.fixture(scope="module")
def key3072():
    return blind_rsa.generate_key(3072)


def test_public_key_parsing_matches(js, issuer_key, key3072):
    for key in (issuer_key, key3072):
        numbers = key.public_key().public_numbers()
        out = js(op="key", pem=pem_of(key))
        assert out["ok"]
        assert int(out["n"], 16) == numbers.n and int(out["e"], 16) == numbers.e
        assert out["bits"] == key.key_size and out["k"] == key.key_size // 8
        assert out["key_id"] == key_id(key.public_key())


@pytest.mark.parametrize("pem", ["", "not a key", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"])
def test_public_key_parsing_rejects_garbage(js, pem):
    assert js(op="key", pem=pem)["ok"] is False


def test_weak_key_is_refused(js):
    weak = blind_rsa.generate_key(1024)
    out = js(op="key", pem=pem_of(weak))
    assert out["ok"] is False and "weak" in out["message"]


def test_encoding_is_byte_identical(js):
    for bits in (2047, 3071, 4095):
        for size in (0, 1, 54, 200):
            message = secrets.token_bytes(size)
            out = js(op="emsa", message=message.hex(), bits=bits)
            assert out["em"] == blind_rsa.emsa_pss_encode(message, bits).hex()


def test_browser_blinds_python_signs_browser_finalizes(js, issuer_key, key3072):
    for key in (issuer_key, key3072):
        pub, pem = key.public_key(), pem_of(key)
        message = CREDENTIAL_PREFIX + secrets.token_bytes(32)
        blinded = js(op="blind", pem=pem, message=message.hex())
        assert blinded["ok"]
        blind_sig = blind_rsa.blind_sign(key, bytes.fromhex(blinded["blinded"]))
        final = js(op="finalize", pem=pem, message=message.hex(), blind_signature=blind_sig.hex(),
                   inverse=blinded["inverse"])
        assert final["ok"]
        signature = bytes.fromhex(final["signature"])
        # the result is an ordinary PSS signature: both the Python library and WebCrypto accept it
        assert blind_rsa.verify(pub, message, signature)
        assert js(op="verify", pem=pem, message=message.hex(), signature=final["signature"])["valid"] is True
        # and it is exactly what the Python holder would have produced (the scheme is deterministic)
        state = blind_rsa.BlindingState(inverse=int(blinded["inverse"], 16))
        assert blind_rsa.finalize(pub, message, blind_sig, state) == signature


def test_fixed_blinding_factor_gives_the_python_bytes(js, issuer_key):
    pub = issuer_key.public_key()
    numbers = pub.public_numbers()
    message = b"fixed factor"
    r = secrets.randbelow(numbers.n - 2) + 2
    out = js(op="blind", pem=pem_of(issuer_key), message=message.hex(), r=f"{r:x}")
    m = int.from_bytes(blind_rsa.emsa_pss_encode(message, pub.key_size - 1), "big")
    expected = (m * pow(r, numbers.e, numbers.n)) % numbers.n
    assert int(out["blinded"], 16) == expected
    assert int(out["inverse"], 16) == pow(r, -1, numbers.n)


def test_blinding_is_random_and_hides_the_message(js, issuer_key):
    pem, message = pem_of(issuer_key), b"same message"
    a = js(op="blind", pem=pem, message=message.hex())
    b = js(op="blind", pem=pem, message=message.hex())
    assert a["blinded"] != b["blinded"] and a["inverse"] != b["inverse"]
    assert a["blinded"] != blind_rsa.emsa_pss_encode(message, issuer_key.key_size - 1).hex()


def test_finalize_refuses_wrong_answers(js, issuer_key):
    pem, message = pem_of(issuer_key), b"one"
    blinded = js(op="blind", pem=pem, message=message.hex())
    good = blind_rsa.blind_sign(issuer_key, bytes.fromhex(blinded["blinded"]))
    other_key = blind_rsa.generate_key(2048)
    bad_answers = [
        bytes(len(good)),                                   # zeros
        good[:-1],                                          # short
        bytes([good[0] ^ 1]) + good[1:],                    # one bit flipped
        b"\xff" * len(good),                                # above the modulus
        blind_rsa.blind_sign(other_key, bytes(255) + b"\x02"),  # signed by another key
    ]
    for answer in bad_answers:
        out = js(op="finalize", pem=pem, message=message.hex(), blind_signature=answer.hex(),
                 inverse=blinded["inverse"])
        assert out["ok"] is False and out["error"] == "BlindRsaError"
    # the right answer for a different message is refused too
    out = js(op="finalize", pem=pem, message=b"two".hex(), blind_signature=good.hex(), inverse=blinded["inverse"])
    assert out["ok"] is False


def test_verify_rejects_other_message_and_other_key(js, issuer_key):
    pem, message = pem_of(issuer_key), b"message"
    blinded, state = blind_rsa.blind(issuer_key.public_key(), message)
    signature = blind_rsa.finalize(issuer_key.public_key(), message, blind_rsa.blind_sign(issuer_key, blinded), state)
    assert js(op="verify", pem=pem, message=message.hex(), signature=signature.hex())["valid"] is True
    assert js(op="verify", pem=pem, message=b"other".hex(), signature=signature.hex())["valid"] is False
    other = pem_of(blind_rsa.generate_key(2048))
    assert js(op="verify", pem=other, message=message.hex(), signature=signature.hex())["valid"] is False


def test_token_and_messages_match_the_registry(js):
    agent, salt, challenge = os.urandom(32), os.urandom(16), os.urandom(32)
    token = agent_token(agent, salt)
    assert js(op="token", agent=agent.hex(), salt=salt.hex())["token"] == token.hex()
    out = js(op="messages", token=token.hex(), challenge=challenge.hex())
    assert out["credential"] == (CREDENTIAL_PREFIX + token).hex()
    assert out["bind"] == bind_message(challenge, token).hex()
    assert js(op="token", agent=agent.hex()[:-2], salt=salt.hex())["ok"] is False


def test_base64url_matches_the_service(js):
    for size in (0, 1, 2, 3, 31, 32, 384):
        data = secrets.token_bytes(size)
        out = js(op="b64", data=data.hex(), text=b64url_encode(data))
        assert out["encoded"] == b64url_encode(data) and out["decoded"] == data.hex()
    assert js(op="b64", data="", text="a+b/")["ok"] is False


def test_modular_arithmetic(js):
    for _ in range(20):
        m = secrets.randbits(256) | 1 | (1 << 255)
        b, e = secrets.randbelow(m - 2) + 2, secrets.randbits(64)
        out = js(op="math", b=str(b), e=str(e), m=str(m))
        if out["ok"]:
            assert int(out["pow"]) == pow(b, e, m) and (int(out["inv"]) * b) % m == 1
        else:  # no inverse exists: Python agrees
            with pytest.raises(ValueError):
                pow(b, -1, m)
