import os

import pytest

from tgtrust import (
    Credential,
    Holder,
    Issuer,
    IssuanceError,
    IssuerPolicy,
    MemoryIssuedStore,
    SqliteIssuedStore,
    verify_credential,
)

from .conftest import BOT_ID, NOW

ALICE = {"id": 111, "first_name": "Alice", "is_premium": True}
BOB = {"id": 222, "first_name": "Bob"}


def make_issuer(issuer_key, telegram, store=None, **policy):
    return Issuer(
        issuer_key,
        BOT_ID,
        os.urandom(32),
        store or MemoryIssuedStore(),
        policy=IssuerPolicy(**policy),
        telegram_public_key_hex=telegram.public_key_hex,
    )


def obtain(issuer, telegram, user):
    holder = Holder(issuer.public_key)
    req = holder.prepare()
    blind_sig = issuer.issue(telegram.init_data(user), req.blinded_message, now=NOW)
    return holder.finalize(req, blind_sig)


def test_full_flow_issues_verifiable_credential(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    cred = obtain(issuer, telegram, ALICE)
    assert verify_credential(issuer.public_key, cred)


def test_one_credential_per_account(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    obtain(issuer, telegram, ALICE)
    with pytest.raises(IssuanceError) as exc:
        obtain(issuer, telegram, ALICE)
    assert exc.value.code == "already_issued"
    assert verify_credential(issuer.public_key, obtain(issuer, telegram, BOB))


def test_credentials_are_unlinkable_to_account(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    a, b = obtain(issuer, telegram, ALICE), obtain(issuer, telegram, BOB)
    for cred in (a, b):
        assert b"111" not in cred.message and b"222" not in cred.message
    assert a.token != b.token


def test_forged_credential_rejected(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    cred = obtain(issuer, telegram, ALICE)
    assert not verify_credential(issuer.public_key, Credential(os.urandom(32), cred.signature))
    assert not verify_credential(issuer.public_key, Credential(cred.token, b"\x00" * len(cred.signature)))


def test_bot_account_rejected(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    with pytest.raises(IssuanceError) as exc:
        obtain(issuer, telegram, {"id": 5, "first_name": "B", "is_bot": True})
    assert exc.value.code == "bot_account"


def test_premium_policy(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram, require_premium=True)
    with pytest.raises(IssuanceError) as exc:
        obtain(issuer, telegram, BOB)
    assert exc.value.code == "premium_required"
    assert verify_credential(issuer.public_key, obtain(issuer, telegram, ALICE))


def test_forged_init_data_does_not_consume_slot(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    req = Holder(issuer.public_key).prepare()
    forged = telegram.init_data(ALICE).replace("Alice", "Mallory")
    with pytest.raises(IssuanceError) as exc:
        issuer.issue(forged, req.blinded_message, now=NOW)
    assert exc.value.code == "invalid_init_data"
    assert verify_credential(issuer.public_key, obtain(issuer, telegram, ALICE))


def test_malformed_blinded_message_does_not_consume_slot(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    with pytest.raises(IssuanceError) as exc:
        issuer.issue(telegram.init_data(ALICE), b"\x00" * 10, now=NOW)
    assert exc.value.code == "invalid_request"
    assert verify_credential(issuer.public_key, obtain(issuer, telegram, ALICE))


def test_new_epoch_allows_reissue(issuer_key, telegram):
    store, key = MemoryIssuedStore(), os.urandom(32)
    kw = dict(telegram_public_key_hex=telegram.public_key_hex)
    first = Issuer(issuer_key, BOT_ID, key, store, policy=IssuerPolicy(epoch="2026"), **kw)
    obtain(first, telegram, ALICE)
    second = Issuer(issuer_key, BOT_ID, key, store, policy=IssuerPolicy(epoch="2027"), **kw)
    assert verify_credential(second.public_key, obtain(second, telegram, ALICE))


def test_sqlite_store_survives_restart(issuer_key, telegram, tmp_path):
    path, key = str(tmp_path / "issued.db"), os.urandom(32)
    kw = dict(telegram_public_key_hex=telegram.public_key_hex)
    first = Issuer(issuer_key, BOT_ID, key, SqliteIssuedStore(path), **kw)
    obtain(first, telegram, ALICE)
    second = Issuer(issuer_key, BOT_ID, key, SqliteIssuedStore(path), **kw)
    with pytest.raises(IssuanceError):
        obtain(second, telegram, ALICE)


def test_store_never_holds_raw_user_id(issuer_key, telegram, tmp_path):
    path = str(tmp_path / "issued.db")
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), SqliteIssuedStore(path),
                    telegram_public_key_hex=telegram.public_key_hex)
    obtain(issuer, telegram, {"id": 987654321987, "first_name": "Z"})
    with open(path, "rb") as fh:
        assert b"987654321987" not in fh.read()


def test_short_pseudonym_key_rejected(issuer_key):
    with pytest.raises(ValueError):
        Issuer(issuer_key, BOT_ID, b"short", MemoryIssuedStore())


# --- retry of the same blinded request (a holder whose connection dropped mid-issuance) ---


def test_same_request_can_be_retried_and_yields_the_same_credential(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    holder = Holder(issuer.public_key)
    req = holder.prepare()
    first = issuer.issue(telegram.init_data(ALICE), req.blinded_message, now=NOW)
    again = issuer.issue(telegram.init_data(ALICE), req.blinded_message, now=NOW)
    assert first == again
    assert holder.finalize(req, first) == holder.finalize(req, again)


def test_retry_does_not_open_a_second_credential(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    holder = Holder(issuer.public_key)
    req = holder.prepare()
    issuer.issue(telegram.init_data(ALICE), req.blinded_message, now=NOW)
    # a different blinded request from the same account is still refused, before and after a retry
    for _ in range(2):
        with pytest.raises(IssuanceError) as exc:
            issuer.issue(telegram.init_data(ALICE), holder.prepare().blinded_message, now=NOW)
        assert exc.value.code == "already_issued"
        issuer.issue(telegram.init_data(ALICE), req.blinded_message, now=NOW)
    # re-blinding the same token is a different request as well
    with pytest.raises(IssuanceError):
        issuer.issue(telegram.init_data(ALICE), holder.prepare(req.token).blinded_message, now=NOW)


def test_retry_needs_valid_init_data_of_the_same_account(issuer_key, telegram):
    issuer = make_issuer(issuer_key, telegram)
    req = Holder(issuer.public_key).prepare()
    issuer.issue(telegram.init_data(ALICE), req.blinded_message, now=NOW)
    with pytest.raises(IssuanceError) as exc:  # stale init data
        issuer.issue(telegram.init_data(ALICE, auth_date=NOW - 10_000), req.blinded_message, now=NOW)
    assert exc.value.code == "invalid_init_data"
    # another account sending the same bytes simply receives its own (single) credential slot
    issuer.issue(telegram.init_data(BOB), req.blinded_message, now=NOW)
    with pytest.raises(IssuanceError):
        issuer.issue(telegram.init_data(BOB), Holder(issuer.public_key).prepare().blinded_message, now=NOW)


def test_retry_survives_restart(issuer_key, telegram, tmp_path):
    path, key = str(tmp_path / "issued.db"), os.urandom(32)
    kw = dict(telegram_public_key_hex=telegram.public_key_hex)
    first = Issuer(issuer_key, BOT_ID, key, SqliteIssuedStore(path), **kw)
    req = Holder(first.public_key).prepare()
    signature = first.issue(telegram.init_data(ALICE), req.blinded_message, now=NOW)
    second = Issuer(issuer_key, BOT_ID, key, SqliteIssuedStore(path), **kw)
    assert second.issue(telegram.init_data(ALICE), req.blinded_message, now=NOW) == signature
    with pytest.raises(IssuanceError):
        second.issue(telegram.init_data(ALICE), Holder(second.public_key).prepare().blinded_message, now=NOW)


def test_database_from_before_retries_is_upgraded_in_place(issuer_key, telegram, tmp_path):
    import sqlite3

    path, key = str(tmp_path / "issued.db"), os.urandom(32)
    kw = dict(telegram_public_key_hex=telegram.public_key_hex)
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE issued (tag BLOB PRIMARY KEY, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')))")
    probe = Issuer(issuer_key, BOT_ID, key, MemoryIssuedStore(), **kw)
    old.execute("INSERT INTO issued (tag) VALUES (?)", (probe._account_tag(ALICE["id"]),))
    old.commit()
    old.close()

    issuer = Issuer(issuer_key, BOT_ID, key, SqliteIssuedStore(path), **kw)
    # an account recorded without a digest stays closed: nothing can be retried for it
    with pytest.raises(IssuanceError) as exc:
        obtain(issuer, telegram, ALICE)
    assert exc.value.code == "already_issued"
    # new accounts work and can retry
    req = Holder(issuer.public_key).prepare()
    assert issuer.issue(telegram.init_data(BOB), req.blinded_message, now=NOW) == \
        issuer.issue(telegram.init_data(BOB), req.blinded_message, now=NOW)


def test_store_keeps_only_a_digest_of_the_request(issuer_key, telegram, tmp_path):
    path = str(tmp_path / "issued.db")
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), SqliteIssuedStore(path),
                    telegram_public_key_hex=telegram.public_key_hex)
    holder = Holder(issuer.public_key)
    req = holder.prepare()
    cred = holder.finalize(req, issuer.issue(telegram.init_data(ALICE), req.blinded_message, now=NOW))
    with open(path, "rb") as fh:
        raw = fh.read()
    for secret in (req.blinded_message, cred.token, cred.signature):
        assert secret not in raw


def test_concurrent_identical_requests_all_get_the_same_answer(issuer_key, telegram):
    from concurrent.futures import ThreadPoolExecutor

    issuer = make_issuer(issuer_key, telegram)
    holder = Holder(issuer.public_key)
    req, other = holder.prepare(), holder.prepare()
    data = telegram.init_data(ALICE)

    def attempt(blinded):
        try:
            return issuer.issue(data, blinded, now=NOW)
        except IssuanceError as exc:
            return exc.code

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(attempt, [req.blinded_message] * 8 + [other.blinded_message] * 8))
    answers = {r for r in results if isinstance(r, bytes)}
    assert len(answers) == 1  # exactly one request won; every signature released belongs to it
