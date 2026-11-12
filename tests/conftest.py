"""Test helpers: a stand-in for Telegram's signing key and init data builder."""

from __future__ import annotations

import base64
import json
import pathlib
from urllib.parse import urlencode

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tgtrust import blind_rsa
from tgtrust.telegram_sig import data_check_string

BOT_ID = 7_000_000_001
NOW = 1_800_000_000


class FakeTelegram:
    """Signs init data exactly as Telegram does, with a local test key."""

    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        raw = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.public_key_hex = raw.hex()

    def init_data(
        self,
        user: dict,
        *,
        bot_id: int = BOT_ID,
        auth_date: int = NOW,
        extra: dict | None = None,
        pad_signature: bool = False,
    ) -> str:
        fields = {
            "auth_date": str(auth_date),
            "query_id": "AAHdF6IQAAAAAN0XohDhrOrc",
            "user": json.dumps(user, separators=(",", ":")),
            "hash": "0" * 64,  # bot-token HMAC; not used by third-party validation
        }
        fields.update(extra or {})
        sig = self._key.sign(data_check_string(bot_id, fields).encode())
        encoded = base64.urlsafe_b64encode(sig).decode()
        fields["signature"] = encoded if pad_signature else encoded.rstrip("=")
        return urlencode(fields)


@pytest.fixture(scope="session", autouse=True)
def no_db_files_in_repo_root():
    """Fail the run if a test left a *.db file in the repository root that was not there at the start."""
    root = pathlib.Path(__file__).resolve().parent.parent
    before = {p.name for p in root.glob("*.db")}
    yield
    left = sorted({p.name for p in root.glob("*.db")} - before)
    assert not left, f"tests left database files in the repository root: {left}"


@pytest.fixture
def telegram() -> FakeTelegram:
    return FakeTelegram()


@pytest.fixture(scope="session")
def issuer_key():
    # 2048 bits keeps the suite fast; production default is 3072.
    return blind_rsa.generate_key(2048)
