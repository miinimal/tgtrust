from urllib.parse import parse_qsl, urlencode

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tgtrust.telegram_sig import TELEGRAM_PUBLIC_KEYS, InitDataError, verify_init_data

from .conftest import BOT_ID, NOW

USER = {"id": 123456789, "first_name": "Test", "is_premium": True}


def verify(telegram, data, **kw):
    kw.setdefault("now", NOW)
    return verify_init_data(data, BOT_ID, public_key_hex=telegram.public_key_hex, **kw)


def test_published_keys_are_valid_ed25519():
    for key_hex in TELEGRAM_PUBLIC_KEYS.values():
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))


def test_valid_init_data(telegram):
    v = verify(telegram, telegram.init_data(USER))
    assert v.user_id == 123456789 and v.is_premium and not v.is_bot


def test_padded_signature_accepted(telegram):
    assert verify(telegram, telegram.init_data(USER, pad_signature=True)).user_id == USER["id"]


def test_tampered_user_rejected(telegram):
    fields = dict(parse_qsl(telegram.init_data(USER)))
    fields["user"] = fields["user"].replace("123456789", "987654321")
    with pytest.raises(InitDataError, match="does not match"):
        verify(telegram, urlencode(fields))


def test_hash_field_is_not_signed(telegram):
    fields = dict(parse_qsl(telegram.init_data(USER)))
    fields["hash"] = "f" * 64
    assert verify(telegram, urlencode(fields)).user_id == USER["id"]


def test_wrong_bot_id_rejected(telegram):
    with pytest.raises(InitDataError):
        verify(telegram, telegram.init_data(USER, bot_id=BOT_ID + 1))


def test_wrong_public_key_rejected(telegram):
    with pytest.raises(InitDataError):
        verify_init_data(telegram.init_data(USER), BOT_ID, now=NOW)  # real Telegram key


def test_expired_rejected(telegram):
    with pytest.raises(InitDataError, match="expired"):
        verify(telegram, telegram.init_data(USER, auth_date=NOW - 901))


def test_future_rejected(telegram):
    with pytest.raises(InitDataError, match="future"):
        verify(telegram, telegram.init_data(USER, auth_date=NOW + 120))


def test_missing_signature_rejected(telegram):
    fields = dict(parse_qsl(telegram.init_data(USER)))
    del fields["signature"]
    with pytest.raises(InitDataError, match="missing"):
        verify(telegram, urlencode(fields))


def test_duplicate_field_rejected(telegram):
    with pytest.raises(InitDataError, match="duplicate"):
        verify(telegram, telegram.init_data(USER) + "&auth_date=1")


def test_unknown_environment():
    with pytest.raises(ValueError):
        verify_init_data("a=b&signature=" + "A" * 86, BOT_ID, environment="staging")
