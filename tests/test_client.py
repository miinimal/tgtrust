import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from tgtrust import Issuer, MemoryIssuedStore
from tgtrust.client import AgentIdentity, DealProposal, TgTrustClient, TgTrustError, b64url_encode
from tgtrust.deals import DealLedger
from tgtrust.disputes import OUTCOME_UPHELD, DisputeBook, verdict_bytes
from tgtrust.registry import Registry
from tgtrust.service import create_app, key_id

from .conftest import BOT_ID

PAYOUT = "kQDyD0lLwVlP2exSkV4_SeyO9RgVG8ruIWQmZJubcP6k5FdI"


def transport_over(client: TestClient):
    def send(method, url, body):
        path = url[len("http://t/v1"):]
        resp = client.request(method, "/v1" + path, json=body)
        return resp.status_code, resp.json()

    return send


@pytest.fixture
def setup(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(), telegram_public_key_hex=telegram.public_key_hex)
    registry = Registry(issuer.public_key, key_id(issuer.public_key))
    deals = DealLedger(registry)
    arbiter = Ed25519PrivateKey.generate()
    arbiter_pub = arbiter.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    app = create_app(issuer=issuer, registry=registry, deals=deals, disputes=DisputeBook(deals, arbiter_pub), rate_limit_per_minute=1000)
    tg = TgTrustClient("http://t/v1", transport=transport_over(TestClient(app)))
    return tg, telegram, arbiter


def test_identity_roundtrip():
    a = AgentIdentity.generate()
    b = AgentIdentity.from_bytes(a.private_bytes())
    assert a.hex == b.hex and len(a.public_key) == 32


def test_full_lifecycle_through_client(setup):
    tg, telegram, arbiter = setup
    alice, bob = AgentIdentity.generate(), AgentIdentity.generate()
    for agent, uid in ((alice, 1), (bob, 2)):
        cred, salt = tg.obtain_credential(agent, telegram.init_data({"id": uid, "first_name": "u"}, auth_date=int(time.time())))
        assert tg.register(agent, cred, salt)["unique_owner"] is True
    with pytest.raises(TgTrustError) as e:
        tg.obtain_credential(AgentIdentity.generate(), telegram.init_data({"id": 1, "first_name": "u"}, auth_date=int(time.time())))
    assert e.value.status == 409
    assert tg.badge(bob.hex)["level"] == "verified"

    proposal = TgTrustClient.propose_deal(alice, bob.hex, 10**9)
    wire = proposal.to_dict()
    restored = DealProposal.from_dict(wire)
    assert restored.message == proposal.message
    bob_sig = restored.counter_sign(bob)
    with pytest.raises(ValueError):
        restored.counter_sign(AgentIdentity.generate())  # not the counterparty
    with pytest.raises(ValueError):
        restored.counter_sign(alice)  # proposer cannot counter-sign its own proposal
    tampered = DealProposal.from_dict({**wire, "amount_nanogram": 5})
    with pytest.raises(Exception):
        tampered.counter_sign(bob)  # proposer signature no longer matches
    deal = tg.submit_deal(proposal, bob_sig)
    assert set(deal["parties"]) == {alice.hex, bob.hex}
    assert tg.deals(alice.hex)["stats"]["count"] == 1
    with pytest.raises(TgTrustError) as e:
        tg.submit_deal(proposal, bob_sig)
    assert e.value.code == "duplicate"

    case = tg.file_dispute(bob, bytes.fromhex(deal["deal_id"]), alice.hex, PAYOUT)
    assert case["status"] == "open" and tg.case(case["case_id"])["claimant"] == bob.hex
    now = int(time.time())
    sig = arbiter.sign(verdict_bytes(case["case_id"], OUTCOME_UPHELD, 7, now))
    status, verdict = tg._send("POST", f"{tg.base_url}/disputes/{case['case_id']}/verdict",
                               {"outcome": OUTCOME_UPHELD, "slash_amount_nanogram": 7, "decided_at": now, "arbiter_signature": b64url_encode(sig)})
    assert status == 200 and verdict["slash"]["agent_key"] == alice.hex
    assert tg.badge(alice.hex)["history"]["disputes"]["upheld_against"] == 1
    assert tg.disputes(alice.hex)["stats"]["filed_against"] == 1
