import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from tgtrust import Holder, Issuer, MemoryIssuedStore
from tgtrust.badge import LEVEL_REVOKED, LEVEL_STAKED, LEVEL_UNKNOWN, LEVEL_VERIFIED, badge_text, build_badge, trust_level
from tgtrust.bot import parse_command, reply_for
from tgtrust.registry import AgentRecord, agent_token, bind_message
from tgtrust.service import b64url_decode, b64url_encode, create_app
from tgtrust.stake import StakeInfo, StakeLookupError, StakeReader, parse_get_stake

from .conftest import BOT_ID

CONTRACT = "kQD0dNGo6GJnxq7Dc5HWcEfoBWI8UkUwZ6-w7gpwm8G11z-w"
KEY = "738559c16db0b6b80b73de6094744bd9e802fb7df4657b3f41fdd3c7238228d8"

# exact shapes toncenter returned for the testnet contract on 2026-11-06
STACK_FOUND = [["num", "-0x1"], ["cell", {"bytes": "te6..."}], ["num", "0x1dcd6500"], ["num", "0x0"], ["num", "0x0"]]
STACK_MISSING = [["num", "0x0"], ["list", {"@type": "tvm.list", "elements": []}], ["num", "0x0"], ["num", "0x0"], ["num", "0x0"]]


def fake_fetcher(stack, calls):
    def fetch(url, payload):
        calls.append((url, payload))
        return {"ok": True, "result": {"exit_code": 0, "stack": stack}}

    return fetch


def test_parse_get_stake_found_and_missing():
    info = parse_get_stake(STACK_FOUND, now=1000)
    assert info.found and info.amount == 500_000_000 and not info.withdrawing and info.unlock_at == 0
    assert info.to_dict("testnet", CONTRACT)["amount_gram"] == "0.5"
    missing = parse_get_stake(STACK_MISSING, now=1000)
    assert not missing.found and missing.amount == 0
    with pytest.raises(StakeLookupError):
        parse_get_stake(STACK_FOUND[:3], now=1000)


def test_stake_reader_queries_contract_and_caches():
    calls = []
    clock = [1000.0]
    reader = StakeReader(CONTRACT, "testnet", fetcher=fake_fetcher(STACK_FOUND, calls), cache_seconds=30, clock=lambda: clock[0])
    info = reader.get_stake(KEY.upper())
    assert info.amount == 500_000_000
    assert calls[0][0].startswith("https://testnet.toncenter.com/")
    assert calls[0][1] == {"address": CONTRACT, "method": "get_stake", "stack": [["num", "0x" + KEY]]}
    reader.get_stake(KEY)
    assert len(calls) == 1  # served from cache
    clock[0] += 31
    reader.get_stake(KEY)
    assert len(calls) == 2
    with pytest.raises(ValueError):
        reader.get_stake("zz")


def test_stake_reader_errors():
    def failing(url, payload):
        return {"ok": False, "error": "rate limit"}

    reader = StakeReader(CONTRACT, fetcher=failing)
    with pytest.raises(StakeLookupError):
        reader.get_stake(KEY)

    def exit_code(url, payload):
        return {"ok": True, "result": {"exit_code": 11, "stack": []}}

    with pytest.raises(StakeLookupError):
        StakeReader(CONTRACT, fetcher=exit_code).get_stake(KEY)
    with pytest.raises(ValueError):
        StakeReader(CONTRACT, "devnet")


def test_trust_levels():
    now = 1_800_000_000
    record = AgentRecord(KEY, "kid", now - 10 * 86400, False)
    revoked = AgentRecord(KEY, "kid", now, True)
    staked = StakeInfo(True, 10, 0, False, now)
    leaving = StakeInfo(True, 10, now + 100, True, now)
    empty = StakeInfo(False, 0, 0, False, now)
    assert trust_level(None, staked) == LEVEL_UNKNOWN  # stake without registration proves nothing
    assert trust_level(revoked, staked) == LEVEL_REVOKED
    assert trust_level(record, None) == LEVEL_VERIFIED
    assert trust_level(record, empty) == LEVEL_VERIFIED
    assert trust_level(record, leaving) == LEVEL_VERIFIED
    assert trust_level(record, staked) == LEVEL_STAKED


def test_build_badge_shapes():
    now = 1_800_000_000
    record = AgentRecord(KEY, "kid", now - 3 * 86400, False)
    from tgtrust.badge import StakeSource

    src = StakeSource("testnet", CONTRACT)
    badge = build_badge(KEY, record, StakeInfo(True, 500_000_000, 0, False, now), stake_source=src, now=now)
    assert badge["level"] == LEVEL_STAKED
    assert badge["stake"]["amount_gram"] == "0.5" and badge["stake"]["contract"] == CONTRACT
    assert badge["history"]["days_registered"] == 3 and badge["history"]["deals"] is None
    assert "owner" not in badge["stake"]
    assert "0.5 GRAM" in badge_text(badge)

    failed = build_badge(KEY, record, None, stake_source=src, stake_error="toncenter HTTP 429", now=now)
    assert failed["level"] == LEVEL_VERIFIED and failed["stake"]["error"] == "toncenter HTTP 429"
    assert "lookup failed" in badge_text(failed)

    unconfigured = build_badge(KEY, None, None, stake_source=None, now=now)
    assert unconfigured["level"] == LEVEL_UNKNOWN and unconfigured["stake"] is None
    assert "not checked" in badge_text(unconfigured)


def test_badge_endpoint_end_to_end(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(), telegram_public_key_hex=telegram.public_key_hex)
    calls = []
    reader = StakeReader(CONTRACT, "testnet", fetcher=fake_fetcher(STACK_FOUND, calls), cache_seconds=0)
    client = TestClient(create_app(issuer=issuer, stake_reader=reader, rate_limit_per_minute=100))

    agent_key = Ed25519PrivateKey.generate()
    agent_pub = agent_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    hexkey = agent_pub.hex()

    before = client.get(f"/v1/agents/{hexkey}/badge").json()
    assert before["level"] == LEVEL_UNKNOWN and before["stake"]["found"] is True  # stake alone is not trust

    salt = os.urandom(16)
    holder = Holder(issuer.public_key)
    req = holder.prepare(agent_token(agent_pub, salt))
    init_data = telegram.init_data({"id": 4242, "first_name": "Owner"}, auth_date=int(time.time()))
    resp = client.post("/v1/issue", json={"init_data": init_data, "blinded_message": b64url_encode(req.blinded_message)})
    cred = holder.finalize(req, b64url_decode(resp.json()["blind_signature"]))
    challenge = b64url_decode(client.post("/v1/challenge").json()["challenge"])
    client.post("/v1/register", json={
        "token": b64url_encode(cred.token),
        "signature": b64url_encode(cred.signature),
        "agent_public_key": b64url_encode(agent_pub),
        "salt": b64url_encode(salt),
        "challenge": b64url_encode(challenge),
        "agent_signature": b64url_encode(agent_key.sign(bind_message(challenge, cred.token))),
    })

    after = client.get(f"/v1/agents/{hexkey}/badge").json()
    assert after["level"] == LEVEL_STAKED and after["unique_owner"] is True
    assert after["stake"]["amount_nanogram"] == 500_000_000
    assert client.get("/v1/agents/nothex/badge").status_code == 400


def test_badge_endpoint_without_stake_source(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(), telegram_public_key_hex=telegram.public_key_hex)
    client = TestClient(create_app(issuer=issuer, rate_limit_per_minute=100))
    badge = client.get(f"/v1/agents/{KEY}/badge").json()
    assert badge["level"] == LEVEL_UNKNOWN and badge["stake"] is None


def test_bot_replies():
    assert parse_command("/badge@tgtrust_bot abc") == ("/badge", "abc")
    assert parse_command("hello") is None
    badge = build_badge(KEY, AgentRecord(KEY, "kid", 1_800_000_000, False), StakeInfo(True, 10 ** 9, 0, False, 1_800_000_000),
                        stake_source=None, now=1_800_000_000)
    assert "Level: verified" in reply_for(f"/badge {KEY}", lambda k: badge)
    assert "64 hex" in reply_for("/badge short", lambda k: badge)
    assert "Could not fetch" in reply_for(f"/badge {KEY}", lambda k: (_ for _ in ()).throw(RuntimeError("down")))
    assert "Send /badge" in reply_for("/start", lambda k: badge)
