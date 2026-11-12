import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from tgtrust import Holder, Issuer, MemoryIssuedStore
from tgtrust.deals import DealError, DealLedger, canonical_bytes, order_keys
from tgtrust.registry import Registry, agent_token, bind_message
from tgtrust.service import b64url_decode, b64url_encode, create_app, key_id
from tgtrust.stake import StakeInfo, StakeReader

from .conftest import BOT_ID

NOW = 1_800_000_000


def make_agent():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub


def register(registry: Registry, issuer: Issuer, telegram, pub: bytes, priv: Ed25519PrivateKey, user_id: int):
    salt = os.urandom(16)
    holder = Holder(issuer.public_key)
    req = holder.prepare(agent_token(pub, salt))
    init_data = telegram.init_data({"id": user_id, "first_name": "U"}, auth_date=int(time.time()))
    cred = holder.finalize(req, issuer.issue(init_data, req.blinded_message))
    challenge = registry.new_challenge()
    registry.register(cred, pub, salt, challenge, priv.sign(bind_message(challenge, cred.token)))


@pytest.fixture
def world(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(), telegram_public_key_hex=telegram.public_key_hex)
    registry = Registry(issuer.public_key, key_id(issuer.public_key))
    staked_keys: set[str] = set()
    ledger = DealLedger(registry, stake_check=lambda k: k in staked_keys, clock=lambda: NOW)
    agents = []
    for i in range(3):
        priv, pub = make_agent()
        register(registry, issuer, telegram, pub, priv, 1000 + i)
        agents.append((priv, pub))
    unregistered = make_agent()
    return issuer, registry, ledger, agents, unregistered, staked_keys


def signed_deal(priv_x, pub_x, priv_y, pub_y, amount=10**9, created_at=NOW, deal_id=None, memo=bytes(32)):
    deal_id = deal_id or os.urandom(16)
    key_a, key_b = order_keys(pub_x, pub_y)
    msg = canonical_bytes(deal_id, key_a, key_b, amount, created_at, memo)
    return dict(deal_id=deal_id, key_x=pub_x, key_y=pub_y, amount=amount, created_at=created_at, memo_hash=memo,
                sig_x=priv_x.sign(msg), sig_y=priv_y.sign(msg))


def test_valid_deal_counts_for_both_and_tracks_staked_counterparty(world):
    _, _, ledger, agents, _, staked = world
    (pa, a), (pb, b), (pc, c) = agents
    staked.add(b.hex())
    row = ledger.record(**signed_deal(pa, a, pb, b))
    assert row.to_dict()["staked"][b.hex()] is True
    ledger.record(**signed_deal(pa, a, pc, c, created_at=NOW - 60))
    sa = ledger.stats(a.hex())
    assert (sa.count, sa.with_staked_counterparty, sa.distinct_counterparties) == (2, 1, 2)
    assert sa.first_at == NOW - 60 and sa.last_at == NOW
    sb = ledger.stats(b.hex())
    assert (sb.count, sb.with_staked_counterparty, sb.distinct_counterparties) == (1, 0, 1)
    assert ledger.stats(c.hex()).count == 1
    assert [d.deal_id for d in ledger.deals_of(a.hex())] == [row.deal_id, ledger.deals_of(c.hex())[0].deal_id]


def test_forged_and_one_sided_records_are_rejected(world):
    _, _, ledger, agents, unregistered, _ = world
    (pa, a), (pb, b), _ = agents
    d = signed_deal(pa, a, pb, b)
    # one side signed, other signature is garbage
    with pytest.raises(DealError) as e:
        ledger.record(**{**d, "sig_y": os.urandom(64)})
    assert e.value.code == "bad_signature"
    # both signatures by the same party
    with pytest.raises(DealError) as e:
        ledger.record(**{**d, "sig_y": d["sig_x"]})
    assert e.value.code == "bad_signature"
    # signature over different amount
    other = signed_deal(pa, a, pb, b, amount=5, deal_id=d["deal_id"])
    with pytest.raises(DealError) as e:
        ledger.record(**{**d, "sig_x": other["sig_x"]})
    assert e.value.code == "bad_signature"
    # swapped order of parties must still verify (canonical form)
    assert ledger.record(**signed_deal(pb, b, pa, a)).key_a == min(a, b).hex()


def test_unregistered_same_party_duplicate_and_stale(world):
    _, registry, ledger, agents, (pu, u), _ = world
    (pa, a), (pb, b), _ = agents
    with pytest.raises(DealError) as e:
        ledger.record(**signed_deal(pa, a, pu, u))
    assert e.value.code == "unregistered_party"
    with pytest.raises(DealError) as e:
        ledger.record(os.urandom(16), a, a, 1, NOW, bytes(32), os.urandom(64), os.urandom(64))
    assert e.value.code == "same_party"
    d = signed_deal(pa, a, pb, b)
    ledger.record(**d)
    with pytest.raises(DealError) as e:
        ledger.record(**d)
    assert e.value.code == "duplicate"
    with pytest.raises(DealError) as e:
        ledger.record(**signed_deal(pa, a, pb, b, created_at=NOW - 3601))
    assert e.value.code == "stale"
    # a revoked agent can no longer confirm deals
    registry.revoke(b.hex())
    with pytest.raises(DealError) as e:
        ledger.record(**signed_deal(pa, a, pb, b))
    assert e.value.code == "unregistered_party"
    assert ledger.stats(a.hex()).count == 1


def test_stake_lookup_failure_does_not_block_a_deal(world):
    _, registry, _, agents, _, _ = world
    (pa, a), (pb, b), _ = agents

    def broken(_k):
        raise RuntimeError("toncenter down")

    ledger = DealLedger(registry, stake_check=broken, clock=lambda: NOW)
    row = ledger.record(**signed_deal(pa, a, pb, b))
    assert row.a_staked is False and row.b_staked is False


def test_deals_over_http_and_badge_history(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(), telegram_public_key_hex=telegram.public_key_hex)
    registry = Registry(issuer.public_key, key_id(issuer.public_key))
    found = [["num", "-0x1"], ["cell", {}], ["num", "0x1dcd6500"], ["num", "0x0"], ["num", "0x0"]]
    reader = StakeReader("kQD0", fetcher=lambda u, p: {"ok": True, "result": {"exit_code": 0, "stack": found}}, cache_seconds=0)
    client = TestClient(create_app(issuer=issuer, registry=registry, stake_reader=reader, rate_limit_per_minute=1000))
    (pa, a), (pb, b) = make_agent(), make_agent()
    register(registry, issuer, telegram, a, pa, 1)
    register(registry, issuer, telegram, b, pb, 2)
    d = signed_deal(pa, a, pb, b, created_at=int(time.time()))
    body = {
        "deal_id": b64url_encode(d["deal_id"]), "key_x": b64url_encode(a), "key_y": b64url_encode(b),
        "amount_nanogram": d["amount"], "created_at": d["created_at"],
        "signature_x": b64url_encode(d["sig_x"]), "signature_y": b64url_encode(d["sig_y"]),
    }
    resp = client.post("/v1/deals", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["staked"] == {min(a, b).hex(): True, max(a, b).hex(): True}
    assert client.post("/v1/deals", json=body).status_code == 409
    assert client.post("/v1/deals", json={**body, "signature_y": b64url_encode(os.urandom(64))}).status_code == 403
    assert client.post("/v1/deals", json={**body, "deal_id": "!!"}).status_code == 400

    badge = client.get(f"/v1/agents/{a.hex()}/badge").json()
    assert badge["history"]["deals"] == {"count": 1, "with_staked_counterparty": 1, "distinct_counterparties": 1,
                                          "first_at": d["created_at"], "last_at": d["created_at"]}
    listing = client.get(f"/v1/agents/{b.hex()}/deals?limit=5").json()
    assert listing["stats"]["count"] == 1 and listing["deals"][0]["deal_id"] == d["deal_id"].hex()
    assert client.get("/v1/agents/xyz/deals").status_code == 400
