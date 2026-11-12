"""The service survives a restart: all four databases are files, a second app on the same files agrees.

In memory only (lost on restart, by design):
- the per-client rate limiter (``RateLimiter``): a restart resets the one-minute windows. Safe: it only
  throttles floods; every rule that protects the trust signals is enforced by the databases below.
- the stake reader's 30 s cache: a restart means one fresh toncenter read. Safe.
Challenges are NOT in memory: they live in the registry database (single-use, 5-minute expiry).
"""

import os
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from tgtrust import Holder, Issuer, SqliteIssuedStore
from tgtrust.deals import DealLedger, canonical_bytes, order_keys
from tgtrust.disputes import DisputeBook, OUTCOME_UPHELD, case_bytes, verdict_bytes
from tgtrust.registry import Registry, agent_token, bind_message
from tgtrust import service
from tgtrust.service import b64url_decode, b64url_encode, create_app, key_id

from .conftest import BOT_ID

PAYOUT = "kQDyD0lLwVlP2exSkV4_SeyO9RgVG8ruIWQmZJubcP6k5FdI"
PSEUDONYM_KEY = os.urandom(32)


def raw_pub(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Node:
    """One app instance on file-backed databases in ``folder``."""

    def __init__(self, folder, issuer_key, telegram, arbiter_pub):
        issuer = Issuer(issuer_key, BOT_ID, PSEUDONYM_KEY, SqliteIssuedStore(str(folder / "issued.db")),
                        telegram_public_key_hex=telegram.public_key_hex)
        registry = Registry(issuer.public_key, key_id(issuer.public_key), str(folder / "registry.db"))
        deals = DealLedger(registry, str(folder / "deals.db"))
        disputes = DisputeBook(deals, arbiter_pub, str(folder / "disputes.db"))
        self.issuer, self.telegram = issuer, telegram
        self.client = TestClient(create_app(issuer=issuer, registry=registry, deals=deals, disputes=disputes,
                                            rate_limit_per_minute=10_000))

    def credential_for(self, priv, pub, user_id):
        salt = os.urandom(16)
        holder = Holder(self.issuer.public_key)
        req = holder.prepare(agent_token(pub, salt))
        data = self.telegram.init_data({"id": user_id, "first_name": "U"}, auth_date=int(time.time()))
        resp = self.client.post("/v1/issue", json={"init_data": data, "blinded_message": b64url_encode(req.blinded_message)})
        assert resp.status_code == 200, resp.text
        return holder.finalize(req, b64url_decode(resp.json()["blind_signature"])), salt

    def register_body(self, priv, pub, cred, salt, challenge):
        return {
            "token": b64url_encode(cred.token), "signature": b64url_encode(cred.signature),
            "agent_public_key": b64url_encode(pub), "salt": b64url_encode(salt),
            "challenge": b64url_encode(challenge), "agent_signature": b64url_encode(priv.sign(bind_message(challenge, cred.token))),
        }

    def new_challenge(self):
        return b64url_decode(self.client.post("/v1/challenge").json()["challenge"])


class ServiceClock:
    """The clock ``tgtrust.service`` reads (``time.time``), held still until the test moves it.

    Only the service module's ``time`` is replaced, so the test's own ``time.time()`` (Telegram ``auth_date``)
    and the other modules keep the real clock. ``monotonic`` stays real: the rate limiter uses it.
    """

    def __init__(self, monkeypatch):
        self.now = int(time.time())
        monkeypatch.setattr(service, "time", SimpleNamespace(time=lambda: self.now, monotonic=time.monotonic))


def run_journey(tmp_path, issuer_key, telegram):
    """Everything the restart test does on the first instance, up to (not including) the first snapshot."""
    arbiter = Ed25519PrivateKey.generate()
    arbiter_pub = raw_pub(arbiter)
    one = Node(tmp_path, issuer_key, telegram, arbiter_pub)

    # journey on the first instance
    pa, pb = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    a, b = raw_pub(pa), raw_pub(pb)
    cred_a, salt_a = one.credential_for(pa, a, 501)
    cred_b, salt_b = one.credential_for(pb, b, 502)
    used_challenge = one.new_challenge()
    body_a = one.register_body(pa, a, cred_a, salt_a, used_challenge)
    assert one.client.post("/v1/register", json=body_a).status_code == 200
    spare_challenge = one.new_challenge()  # issued, not yet used: must still be honoured after restart
    assert one.client.post("/v1/register", json=one.register_body(pb, b, cred_b, salt_b, one.new_challenge())).status_code == 200

    now = int(time.time())
    deal_id = os.urandom(16)
    key_a, key_b = order_keys(a, b)
    msg = canonical_bytes(deal_id, key_a, key_b, 10**9, now, bytes(32))
    deal_body = {"deal_id": b64url_encode(deal_id), "key_x": b64url_encode(a), "key_y": b64url_encode(b),
                 "amount_nanogram": 10**9, "created_at": now,
                 "signature_x": b64url_encode(pa.sign(msg)), "signature_y": b64url_encode(pb.sign(msg))}
    assert one.client.post("/v1/deals", json=deal_body).status_code == 200

    dispute_body = {"deal_id": b64url_encode(deal_id), "claimant_key": b64url_encode(a), "accused_key": b64url_encode(b),
                    "payout_address": PAYOUT, "filed_at": now,
                    "claimant_signature": b64url_encode(pa.sign(case_bytes(deal_id, a, b, bytes(32), now)))}
    filed = one.client.post("/v1/disputes", json=dispute_body)
    assert filed.status_code == 200, filed.text
    case_id = filed.json()["case_id"]
    verdict_body = {"outcome": 1, "slash_amount_nanogram": 7, "decided_at": now,
                    "arbiter_signature": b64url_encode(arbiter.sign(verdict_bytes(case_id, OUTCOME_UPHELD, 7, now)))}
    assert one.client.post(f"/v1/disputes/{case_id}/verdict", json=verdict_body).status_code == 200

    def snapshot(node):
        c = node.client
        return {
            "agent_a": c.get(f"/v1/agents/{a.hex()}").json(),
            "badge_a": c.get(f"/v1/agents/{a.hex()}/badge").json(),
            "badge_b": c.get(f"/v1/agents/{b.hex()}/badge").json(),
            "deals_a": c.get(f"/v1/agents/{a.hex()}/deals").json(),
            "case": c.get(f"/v1/disputes/{case_id}").json(),
            "disputes_b": c.get(f"/v1/agents/{b.hex()}/disputes").json(),
        }

    return SimpleNamespace(
        arbiter_pub=arbiter_pub, one=one, snapshot=snapshot, pa=pa, a=a, b=b, cred_a=cred_a, salt_a=salt_a,
        used_challenge=used_challenge, spare_challenge=spare_challenge, body_a=body_a, deal_body=deal_body,
        dispute_body=dispute_body, case_id=case_id, verdict_body=verdict_body)


def test_state_survives_restart(tmp_path, issuer_key, telegram, monkeypatch):
    clock = ServiceClock(monkeypatch)  # frozen for the whole test: checked_at cannot differ between snapshots
    j = run_journey(tmp_path, issuer_key, telegram)
    one, snapshot, pa, a = j.one, j.snapshot, j.pa, j.a
    body_a, cred_a, salt_a, used_challenge = j.body_a, j.cred_a, j.salt_a, j.used_challenge
    spare_challenge = j.spare_challenge
    deal_body, dispute_body, verdict_body, case_id = j.deal_body, j.dispute_body, j.verdict_body, j.case_id

    before = snapshot(one)
    assert before["badge_b"]["history"]["disputes"]["upheld_against"] == 1
    assert before["case"]["status"] == "upheld" and before["deals_a"]["stats"]["count"] == 1
    assert before["badge_a"]["checked_at"] == clock.now  # the frozen clock is what the service read

    # restart: a second instance on the same files (the first stays open: SQLite autocommits each write)
    two = Node(tmp_path, issuer_key, telegram, j.arbiter_pub)
    assert snapshot(two) == before

    # one credential per account per epoch still holds
    holder = Holder(two.issuer.public_key)
    req = holder.prepare()
    data = telegram.init_data({"id": 501, "first_name": "U"}, auth_date=int(time.time()))
    again = two.client.post("/v1/issue", json={"init_data": data, "blinded_message": b64url_encode(req.blinded_message)})
    assert again.status_code == 409 and again.json()["detail"]["code"] == "already_issued"

    # a used challenge, a used deal id, a repeated dispute and a second verdict are still refused
    assert two.client.post("/v1/register", json=body_a).status_code in (403, 409)
    reuse = two.register_body(pa, a, cred_a, salt_a, used_challenge)
    assert two.client.post("/v1/register", json=reuse).status_code in (403, 409)
    assert two.client.post("/v1/deals", json=deal_body).status_code == 409
    assert two.client.post("/v1/disputes", json=dispute_body).status_code == 409
    assert two.client.post(f"/v1/disputes/{case_id}/verdict", json=verdict_body).status_code == 409

    # a used challenge cannot register a new agent either (fresh credential, fresh agent, old challenge)
    pc = Ed25519PrivateKey.generate()
    c = raw_pub(pc)
    cred_c, salt_c = two.credential_for(pc, c, 503)
    stale = two.client.post("/v1/register", json=two.register_body(pc, c, cred_c, salt_c, used_challenge))
    assert stale.status_code == 403 and stale.json()["detail"]["code"] == "invalid_challenge"
    # the challenge issued but unused before the restart is still valid, and only once
    ok = two.client.post("/v1/register", json=two.register_body(pc, c, cred_c, salt_c, spare_challenge))
    assert ok.status_code == 200
    assert two.client.get(f"/v1/agents/{c.hex()}").status_code == 200
    assert one.client.get(f"/v1/agents/{c.hex()}").status_code == 200  # both instances see the same files


def test_restart_comparison_ignores_time_passing_between_snapshots(tmp_path, issuer_key, telegram, monkeypatch):
    """Proof of the fix: 2 s pass before the restart. The plain comparison would be red, the frozen one is green."""
    clock = ServiceClock(monkeypatch)
    start = clock.now
    j = run_journey(tmp_path, issuer_key, telegram)
    before = j.snapshot(j.one)
    assert before["badge_a"]["checked_at"] == start

    clock.now = start + 2  # the wall clock moves on while the service restarts
    two = Node(tmp_path, issuer_key, telegram, j.arbiter_pub)
    raw = j.snapshot(two)

    # the old check, snapshot(two) == before, fails for a reason unrelated to the state
    assert raw["badge_a"]["checked_at"] == start + 2 and raw["badge_b"]["checked_at"] == start + 2
    assert raw["badge_a"]["checked_at"] != before["badge_a"]["checked_at"]
    assert raw["badge_b"]["checked_at"] != before["badge_b"]["checked_at"]
    assert raw != before
    # and nothing but checked_at differs
    for name in ("badge_a", "badge_b"):
        assert {k: v for k, v in raw[name].items() if k != "checked_at"} == \
               {k: v for k, v in before[name].items() if k != "checked_at"}
    for name in ("agent_a", "deals_a", "case", "disputes_b"):
        assert raw[name] == before[name]

    # the fixed comparison: the clock the service reads is held at the first snapshot's instant, checked_at and
    # days_registered stay part of what is compared
    clock.now = start
    assert j.snapshot(two) == before


def test_rate_limit_is_memory_only_and_is_not_a_trust_rule(tmp_path, issuer_key, telegram):
    """A restart resets the throttle (documented), but cannot reset any one-time rule: those are in the files."""
    from tgtrust.service import RateLimiter
    limiter = RateLimiter(1)
    assert limiter.allow("x", now=0) and not limiter.allow("x", now=1)
    assert RateLimiter(1).allow("x", now=1)  # a fresh instance forgets: intended, only throttles floods
