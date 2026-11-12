import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from tgtrust import Issuer, MemoryIssuedStore
from tgtrust.deals import DealLedger
from tgtrust.disputes import (
    OUTCOME_DISMISSED,
    OUTCOME_UPHELD,
    DisputeBook,
    DisputeError,
    case_bytes,
    derive_case_id,
    is_valid_ton_address,
    verdict_bytes,
)
from tgtrust.registry import Registry
from tgtrust.service import b64url_encode, create_app, key_id

from .conftest import BOT_ID
from .test_deals import NOW, make_agent, register, signed_deal

PAYOUT = "kQDyD0lLwVlP2exSkV4_SeyO9RgVG8ruIWQmZJubcP6k5FdI"


@pytest.fixture
def world(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(), telegram_public_key_hex=telegram.public_key_hex)
    registry = Registry(issuer.public_key, key_id(issuer.public_key))
    deals = DealLedger(registry, clock=lambda: NOW)
    arbiter = Ed25519PrivateKey.generate()
    arbiter_pub = arbiter.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    book = DisputeBook(deals, arbiter_pub, clock=lambda: NOW)
    agents = []
    for i in range(3):
        priv, pub = make_agent()
        register(registry, issuer, telegram, pub, priv, 2000 + i)
        agents.append((priv, pub))
    (pa, a), (pb, b), _ = agents
    deal = deals.record(**signed_deal(pa, a, pb, b))
    return issuer, registry, deals, book, arbiter, agents, deal


def filed(book, deal, priv, claimant, accused, reason=bytes(32), payout=PAYOUT, filed_at=NOW):
    deal_id = bytes.fromhex(deal.deal_id)
    sig = priv.sign(case_bytes(deal_id, claimant, accused, reason, filed_at))
    return book.file(deal_id, claimant, accused, reason, payout, filed_at, sig)


def verdict(arbiter, case_id, outcome, amount, decided_at=NOW):
    return arbiter.sign(verdict_bytes(case_id, outcome, amount, decided_at))


def test_address_check():
    assert is_valid_ton_address(PAYOUT)
    assert is_valid_ton_address("0:" + "ab" * 32)
    assert not is_valid_ton_address("hello")
    assert not is_valid_ton_address("0:zz")


def test_file_and_uphold_produces_slash_payload(world):
    _, _, _, book, arbiter, agents, deal = world
    (pa, a), (pb, b), _ = agents
    case = filed(book, deal, pa, a, b)
    assert case.status == "open" and case.case_id == derive_case_id(bytes.fromhex(deal.deal_id), a)
    assert book.stats(b.hex()).to_dict() == {"filed_against": 1, "upheld_against": 0, "open_against": 1, "filed_by": 0}
    decided = book.decide(case.case_id, OUTCOME_UPHELD, 10**9, NOW, verdict(arbiter, case.case_id, OUTCOME_UPHELD, 10**9))
    assert decided.status == "upheld"
    payload = decided.to_dict()["slash"]
    assert payload == {"agent_key": b.hex(), "amount_nanogram": 10**9, "victim": PAYOUT, "case_id": case.case_id}
    assert book.stats(b.hex()).upheld_against == 1 and book.stats(a.hex()).filed_by == 1
    # the accused can file its own case on the same deal (different claimant -> different case id)
    other = filed(book, deal, pb, b, a)
    assert other.case_id != case.case_id


def test_fake_cases_rejected(world):
    _, _, _, book, arbiter, agents, deal = world
    (pa, a), (pb, b), (pc, c) = agents
    deal_id = bytes.fromhex(deal.deal_id)
    # outsider claims to be a party
    with pytest.raises(DisputeError) as e:
        filed(book, deal, pc, c, b)
    assert e.value.code == "not_a_party"
    # accused is not the other party
    with pytest.raises(DisputeError) as e:
        filed(book, deal, pa, a, c)
    assert e.value.code == "not_a_party"
    # signature by someone else
    with pytest.raises(DisputeError) as e:
        book.file(deal_id, a, b, bytes(32), PAYOUT, NOW, pb.sign(case_bytes(deal_id, a, b, bytes(32), NOW)))
    assert e.value.code == "bad_signature"
    # bad payout address, stale filing
    with pytest.raises(DisputeError) as e:
        filed(book, deal, pa, a, b, payout="nope")
    assert e.value.code == "bad_payout_address"
    with pytest.raises(DisputeError) as e:
        filed(book, deal, pa, a, b, filed_at=NOW - 7200)
    assert e.value.code == "stale"
    # duplicate
    filed(book, deal, pa, a, b)
    with pytest.raises(DisputeError) as e:
        filed(book, deal, pa, a, b)
    assert e.value.code == "duplicate"


def test_fake_and_double_verdicts_rejected(world):
    _, _, deals, book, arbiter, agents, deal = world
    (pa, a), (pb, b), _ = agents
    case = filed(book, deal, pa, a, b)
    impostor = Ed25519PrivateKey.generate()
    with pytest.raises(DisputeError) as e:
        book.decide(case.case_id, OUTCOME_UPHELD, 5, NOW, verdict(impostor, case.case_id, OUTCOME_UPHELD, 5))
    assert e.value.code == "bad_signature"
    # signature over a different amount
    with pytest.raises(DisputeError) as e:
        book.decide(case.case_id, OUTCOME_UPHELD, 5, NOW, verdict(arbiter, case.case_id, OUTCOME_UPHELD, 6))
    assert e.value.code == "bad_signature"
    with pytest.raises(DisputeError) as e:
        book.decide(case.case_id, OUTCOME_UPHELD, 0, NOW, verdict(arbiter, case.case_id, OUTCOME_UPHELD, 0))
    assert e.value.code == "invalid_verdict"
    with pytest.raises(DisputeError) as e:
        book.decide(case.case_id, OUTCOME_DISMISSED, 1, NOW, verdict(arbiter, case.case_id, OUTCOME_DISMISSED, 1))
    assert e.value.code == "invalid_verdict"
    with pytest.raises(DisputeError) as e:
        book.decide(case.case_id + 1, OUTCOME_DISMISSED, 0, NOW, verdict(arbiter, case.case_id + 1, OUTCOME_DISMISSED, 0))
    assert e.value.code == "unknown_case"
    book.decide(case.case_id, OUTCOME_DISMISSED, 0, NOW, verdict(arbiter, case.case_id, OUTCOME_DISMISSED, 0))
    with pytest.raises(DisputeError) as e:
        book.decide(case.case_id, OUTCOME_UPHELD, 5, NOW, verdict(arbiter, case.case_id, OUTCOME_UPHELD, 5))
    assert e.value.code == "already_decided"
    assert book.get(case.case_id).status == "dismissed"
    no_arbiter = DisputeBook(deals, None, clock=lambda: NOW)
    with pytest.raises(DisputeError) as e:
        no_arbiter.decide(1, OUTCOME_DISMISSED, 0, NOW, b"x" * 64)
    assert e.value.code == "no_arbiter"


def test_disputes_over_http(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(), telegram_public_key_hex=telegram.public_key_hex)
    registry = Registry(issuer.public_key, key_id(issuer.public_key))
    deals = DealLedger(registry)
    arbiter = Ed25519PrivateKey.generate()
    arbiter_pub = arbiter.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    book = DisputeBook(deals, arbiter_pub)
    client = TestClient(create_app(issuer=issuer, registry=registry, deals=deals, disputes=book, rate_limit_per_minute=1000))
    (pa, a), (pb, b) = make_agent(), make_agent()
    register(registry, issuer, telegram, a, pa, 1)
    register(registry, issuer, telegram, b, pb, 2)
    now = int(time.time())
    deal = deals.record(**signed_deal(pa, a, pb, b, created_at=now))
    deal_id = bytes.fromhex(deal.deal_id)
    body = {
        "deal_id": b64url_encode(deal_id), "claimant_key": b64url_encode(a), "accused_key": b64url_encode(b),
        "payout_address": PAYOUT, "filed_at": now,
        "claimant_signature": b64url_encode(pa.sign(case_bytes(deal_id, a, b, bytes(32), now))),
    }
    resp = client.post("/v1/disputes", json=body)
    assert resp.status_code == 200, resp.text
    case_id = resp.json()["case_id"]
    assert client.post("/v1/disputes", json=body).status_code == 409
    assert client.get(f"/v1/disputes/{case_id}").json()["status"] == "open"
    badge = client.get(f"/v1/agents/{b.hex()}/badge").json()
    assert badge["history"]["disputes"]["open_against"] == 1
    bad = client.post(f"/v1/disputes/{case_id}/verdict", json={
        "outcome": 1, "slash_amount_nanogram": 7, "decided_at": now, "arbiter_signature": b64url_encode(os.urandom(64))})
    assert bad.status_code == 403
    good = client.post(f"/v1/disputes/{case_id}/verdict", json={
        "outcome": 1, "slash_amount_nanogram": 7, "decided_at": now,
        "arbiter_signature": b64url_encode(arbiter.sign(verdict_bytes(case_id, OUTCOME_UPHELD, 7, now)))})
    assert good.status_code == 200 and good.json()["slash"]["case_id"] == case_id
    assert client.get(f"/v1/agents/{b.hex()}/disputes").json()["stats"]["upheld_against"] == 1
    assert client.get(f"/v1/disputes/{case_id + 1}").status_code == 404
    text_badge = client.get(f"/v1/agents/{b.hex()}/badge").json()
    assert text_badge["history"]["disputes"] == {"filed_against": 1, "upheld_against": 1, "open_against": 0, "filed_by": 0}
