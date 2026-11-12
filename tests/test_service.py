import os

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from tgtrust import Holder, Issuer, MemoryIssuedStore, verify_credential
from tgtrust.keys import write_issuer_key
from tgtrust.service import RateLimiter, Settings, b64url_encode, create_app

from .conftest import BOT_ID

USER = {"id": 4242, "first_name": "Ann"}


@pytest.fixture
def setup(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    client = TestClient(create_app(issuer=issuer, rate_limit_per_minute=100))
    return client, issuer, telegram


def issue(client, issuer, telegram, user, auth_date=None):
    import time
    holder = Holder(issuer.public_key)
    req = holder.prepare()
    data = telegram.init_data(user, auth_date=auth_date or int(time.time()))
    resp = client.post("/v1/issue", json={
        "init_data": data, "blinded_message": b64url_encode(req.blinded_message)})
    return resp, holder, req


def test_health(setup):
    client, _, _ = setup
    assert client.get("/v1/health").json() == {"status": "ok"}


def test_issuer_info_exposes_only_public_key(setup):
    client, issuer, _ = setup
    info = client.get("/v1/issuer").json()
    assert "PRIVATE" not in info["public_key_pem"]
    loaded = serialization.load_pem_public_key(info["public_key_pem"].encode())
    assert loaded.public_numbers() == issuer.public_key.public_numbers()
    assert len(info["key_id"]) == 16


def test_end_to_end_issue_and_verify(setup):
    client, issuer, telegram = setup
    resp, holder, req = issue(client, issuer, telegram, USER)
    assert resp.status_code == 200
    from tgtrust.service import b64url_decode
    cred = holder.finalize(req, b64url_decode(resp.json()["blind_signature"]))
    assert verify_credential(issuer.public_key, cred)
    check = client.post("/v1/verify", json={
        "token": b64url_encode(cred.token), "signature": b64url_encode(cred.signature)})
    assert check.json()["valid"] is True


def test_second_issue_conflicts(setup):
    client, issuer, telegram = setup
    issue(client, issuer, telegram, USER)
    resp, _, _ = issue(client, issuer, telegram, USER)
    assert resp.status_code == 409 and resp.json()["detail"]["code"] == "already_issued"


def test_forged_init_data_unauthorized(setup):
    client, issuer, telegram = setup
    import time
    req = Holder(issuer.public_key).prepare()
    data = telegram.init_data(USER, auth_date=int(time.time())).replace("Ann", "Eve")
    resp = client.post("/v1/issue", json={
        "init_data": data, "blinded_message": b64url_encode(req.blinded_message)})
    assert resp.status_code == 401


def test_forged_credential_invalid(setup):
    client, _, _ = setup
    resp = client.post("/v1/verify", json={
        "token": b64url_encode(os.urandom(32)), "signature": b64url_encode(os.urandom(256))})
    assert resp.json()["valid"] is False


def test_bad_encoding_rejected(setup):
    client, _, _ = setup
    resp = client.post("/v1/verify", json={"token": "!!!", "signature": "@@"})
    assert resp.status_code == 400


def test_oversized_body_rejected(setup):
    client, _, _ = setup
    resp = client.post("/v1/issue", content=b"x" * 20000,
                       headers={"content-type": "application/json"})
    assert resp.status_code == 413


def test_rate_limit(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    client = TestClient(create_app(issuer=issuer, rate_limit_per_minute=2))
    body = {"token": "AA", "signature": "AA"}
    codes = [client.post("/v1/verify", json=body).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_rate_limiter_window():
    rl = RateLimiter(1)
    assert rl.allow("a", now=0) and not rl.allow("a", now=30) and rl.allow("a", now=61)


def test_rate_limiter_forgets_idle_clients():
    rl = RateLimiter(5)
    for i in range(1000):
        assert rl.allow(f"client-{i}", now=0)
    assert rl.tracked() == 1000
    assert rl.allow("late", now=120)
    assert rl.tracked() == 1


def test_forwarded_for_uses_proxy_entry(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    client = TestClient(create_app(issuer=issuer, rate_limit_per_minute=2, trust_forwarded_for=True))
    body = {"token": "AA", "signature": "AA"}
    # A client rotating a spoofed first entry must not escape its limit: the proxy-added last entry counts.
    codes = [client.post("/v1/verify", json=body, headers={"x-forwarded-for": f"10.0.0.{i}, 203.0.113.7"}).status_code
             for i in range(3)]
    assert codes == [200, 200, 429]
    other = client.post("/v1/verify", json=body, headers={"x-forwarded-for": "203.0.113.8"})
    assert other.status_code == 200


def test_settings_require_secrets():
    with pytest.raises(RuntimeError, match="missing"):
        Settings.from_env({})


def test_app_from_env_and_key_file(tmp_path, telegram):
    key_path = str(tmp_path / "issuer.pem")
    write_issuer_key(key_path, bits=2048)
    assert oct(os.stat(key_path).st_mode & 0o777) == "0o600"
    with pytest.raises(FileExistsError):
        write_issuer_key(key_path)
    settings = Settings.from_env({
        "TGTRUST_BOT_ID": str(BOT_ID),
        "TGTRUST_ISSUER_KEY_FILE": key_path,
        "TGTRUST_PSEUDONYM_KEY": os.urandom(32).hex(),
        "TGTRUST_DB_PATH": str(tmp_path / "issued.db"),
        "TGTRUST_REGISTRY_DB_PATH": str(tmp_path / "registry.db"),
        "TGTRUST_DEALS_DB_PATH": str(tmp_path / "deals.db"),
        "TGTRUST_DISPUTES_DB_PATH": str(tmp_path / "disputes.db"),
    })
    client = TestClient(create_app(settings))
    assert client.get("/v1/health").status_code == 200
