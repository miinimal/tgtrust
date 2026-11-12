"""Seeded fuzz of every HTTP endpoint: bad input is answered 4xx with a JSON error, and nothing is stored.

"Error field": every error body is ``{"detail": ...}`` (FastAPI's own field, used by the whole API
since block 3; it is not renamed). Requests are built by corrupting a valid body, so each one is bad.
"""

import json
import os
import random
import sqlite3
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from tgtrust import Holder, Issuer, SqliteIssuedStore
from tgtrust.deals import DealLedger, canonical_bytes, order_keys
from tgtrust.disputes import DisputeBook, case_bytes
from tgtrust.registry import Registry, agent_token, bind_message
from tgtrust.service import MAX_BODY_BYTES, b64url_decode, b64url_encode, create_app, key_id

from .conftest import BOT_ID

SEED = 20261112
PER_ENDPOINT = 40
PAYOUT = "kQDyD0lLwVlP2exSkV4_SeyO9RgVG8ruIWQmZJubcP6k5FdI"

HEX = "0123456789abcdef"
NASTY_STRINGS = [
    "", " ", "\x00", "a\x00b", "\r\n", "\x1b[31mred", "‮evil", "\ud800", "\U0001f600" * 50, "é" * 100,
    "../../etc/passwd", "'; DROP TABLE agents;--", "%00", "{{7*7}}", "A" * 64, "A" * 65, "A" * 200,
    "A" * 5000, "A" * (MAX_BODY_BYTES - 200), "-" * 43, "_" * 44, "====", "AA==AA", "!!!!", "@@", "+/+/", "a b",
]
WRONG_TYPES = [None, True, False, [], {}, [1], {"a": 1}, 1.5, -1.5, "x", 0, -1, 10**30, -(10**30), float("1e300")]
NUMBERS = [-1, -(2**63), 0, 1, 2**31, 2**63 - 1, 2**63, 2**64, 10**30, 10**5, 1.5, -0.5]
BIG_TIMES = [0, 1, 946684800, int(time.time()) - 10**7, int(time.time()) + 10**7, 2**62, 2**63 - 1, 2**63, -1]


def raw_pub(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def count_rows(folder):
    """Rows that must never appear because of a bad request."""
    out = {}
    for db, table in (("issued.db", "issued"), ("registry.db", "agents"), ("deals.db", "deals"), ("disputes.db", "cases")):
        con = sqlite3.connect(str(folder / db))
        try:
            name = con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchone()[0] if table == "issued" else table
            out[table] = con.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        finally:
            con.close()
    return out


@pytest.fixture(scope="module")
def world(tmp_path_factory, issuer_key):
    from .conftest import FakeTelegram
    telegram = FakeTelegram()
    folder = tmp_path_factory.mktemp("fuzz")
    arbiter = Ed25519PrivateKey.generate()
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), SqliteIssuedStore(str(folder / "issued.db")),
                    telegram_public_key_hex=telegram.public_key_hex)
    registry = Registry(issuer.public_key, key_id(issuer.public_key), str(folder / "registry.db"))
    deals = DealLedger(registry, str(folder / "deals.db"))
    disputes = DisputeBook(deals, raw_pub(arbiter), str(folder / "disputes.db"))
    client = TestClient(create_app(issuer=issuer, registry=registry, deals=deals, disputes=disputes,
                                   rate_limit_per_minute=10**7), raise_server_exceptions=False)

    agents = []
    for uid in (801, 802):
        priv = Ed25519PrivateKey.generate()
        pub = raw_pub(priv)
        salt = os.urandom(16)
        holder = Holder(issuer.public_key)
        req = holder.prepare(agent_token(pub, salt))
        data = telegram.init_data({"id": uid, "first_name": "U"}, auth_date=int(time.time()))
        cred = holder.finalize(req, issuer.issue(data, req.blinded_message))
        challenge = registry.new_challenge()
        registry.register(cred, pub, salt, challenge, priv.sign(bind_message(challenge, cred.token)))
        agents.append((priv, pub, cred, salt))
    (pa, a, _, _), (pb, b, _, _) = agents
    now = int(time.time())
    memo, reason = os.urandom(32), os.urandom(32)  # non-zero, so an emptied optional field breaks the signature
    deal_id = os.urandom(16)
    key_a, key_b = order_keys(a, b)
    msg = canonical_bytes(deal_id, key_a, key_b, 10**9, now, memo)
    deals.record(deal_id, a, b, 10**9, now, memo, pa.sign(msg), pb.sign(msg))
    case = disputes.file(deal_id, a, b, reason, PAYOUT, now, pa.sign(case_bytes(deal_id, a, b, reason, now)))

    # a fresh, valid, not yet used issue request and registration request (for corruption)
    fresh_holder = Holder(issuer.public_key)
    fresh_req = fresh_holder.prepare()
    issue_ok = {"init_data": telegram.init_data({"id": 900, "first_name": "F"}, auth_date=now),
                "blinded_message": b64url_encode(fresh_req.blinded_message)}
    pc = Ed25519PrivateKey.generate()
    c = raw_pub(pc)
    salt_c = os.urandom(16)
    h2 = Holder(issuer.public_key)
    r2 = h2.prepare(agent_token(c, salt_c))
    cred_c = h2.finalize(r2, issuer.issue(telegram.init_data({"id": 901, "first_name": "G"}, auth_date=now), r2.blinded_message))
    chal = registry.new_challenge()
    register_ok = {"token": b64url_encode(cred_c.token), "signature": b64url_encode(cred_c.signature),
                   "agent_public_key": b64url_encode(c), "salt": b64url_encode(salt_c),
                   "challenge": b64url_encode(chal), "agent_signature": b64url_encode(pc.sign(bind_message(chal, cred_c.token)))}
    new_deal = os.urandom(16)
    msg2 = canonical_bytes(new_deal, key_a, key_b, 5, now, memo)
    deal_ok = {"deal_id": b64url_encode(new_deal), "key_x": b64url_encode(a), "key_y": b64url_encode(b),
               "amount_nanogram": 5, "created_at": now, "memo_hash": b64url_encode(memo),
               "signature_x": b64url_encode(pa.sign(msg2)),
               "signature_y": b64url_encode(pb.sign(msg2))}
    dispute_ok = {"deal_id": b64url_encode(deal_id), "claimant_key": b64url_encode(b), "accused_key": b64url_encode(a),
                  "reason_hash": b64url_encode(reason), "payout_address": PAYOUT, "filed_at": now,
                  "claimant_signature": b64url_encode(pb.sign(case_bytes(deal_id, b, a, reason, now)))}
    verdict_ok = {"outcome": 1, "slash_amount_nanogram": 7, "decided_at": now,
                  "arbiter_signature": b64url_encode(arbiter.sign(b"x" * 8))}
    return dict(client=client, folder=folder, a=a.hex(), b=b.hex(), case_id=case.case_id, now=now,
                bodies={"/v1/issue": issue_ok, "/v1/register": register_ok, "/v1/deals": deal_ok,
                        "/v1/disputes": dispute_ok, "/v1/verify": {"token": register_ok["token"], "signature": register_ok["signature"]},
                        "verdict": verdict_ok})


def corrupt(rng, body):
    """Return a corrupted copy of ``body``: at least one field is made definitely wrong."""
    out = dict(body)
    keys = list(out)
    for _ in range(rng.randint(1, 3)):
        key = rng.choice(keys)
        kind = rng.choice(["delete", "type", "string", "number", "time", "trunc", "hexkey", "extra", "b64"])
        if kind == "delete":
            out.pop(key, None)
        elif kind == "type":
            out[key] = rng.choice(WRONG_TYPES)
        elif kind == "string":
            out[key] = rng.choice(NASTY_STRINGS)
        elif kind == "number":
            out[key] = rng.choice(NUMBERS)
        elif kind == "time":
            out[key] = rng.choice(BIG_TIMES)
        elif kind == "trunc":
            v = out.get(key)
            out[key] = v[: rng.randint(0, max(0, len(v) - 1))] + "A" if isinstance(v, str) and v else "A"
        elif kind == "hexkey":
            out[key] = "".join(rng.choice(HEX + "zZ") for _ in range(rng.choice([0, 1, 31, 32, 33, 63, 64, 65, 128])))
        elif kind == "b64":
            out[key] = rng.choice(["!!!", "a=b=", "AAAA====", "ééé", "-_-_-_", "A", "AAAAA"])
        else:
            out["extra_" + str(rng.randint(0, 9))] = rng.choice(WRONG_TYPES + NASTY_STRINGS)
    if out == body or all(k.startswith("extra_") or k in body and out[k] == body[k] for k in out) and len(out) >= len(body):
        out[keys[0]] = "\x00bad"  # corruption that happened to be a no-op or only extra fields
    return out


def assert_rejected(resp, request_desc):
    assert 400 <= resp.status_code < 500, f"{request_desc}: got {resp.status_code} {resp.text[:200]}"
    assert resp.headers["content-type"].startswith("application/json"), request_desc
    data = resp.json()
    assert isinstance(data, dict) and "detail" in data, request_desc


def post(client, path, rng, body):
    mode = rng.random()
    if mode < 0.8:
        data = json.dumps(body, ensure_ascii=rng.random() < 0.5, allow_nan=True).encode("utf-8", "surrogatepass")
        return client.post(path, content=data, headers={"content-type": "application/json"})
    if mode < 0.9:
        return client.post(path, json=body)
    return client.post(path, content=json.dumps(body).encode(), headers={"content-type": "text/plain"})


POST_TARGETS = ["/v1/issue", "/v1/verify", "/v1/register", "/v1/deals", "/v1/disputes", "verdict"]


@pytest.mark.parametrize("target", POST_TARGETS)
def test_post_bodies_are_rejected_and_nothing_is_stored(world, target):
    client, folder = world["client"], world["folder"]
    rng = random.Random(f"{SEED}:{target}")
    base = world["bodies"][target]
    before = count_rows(folder)
    sent = 0
    for _ in range(PER_ENDPOINT):
        path = target
        if target == "verdict":
            path = f"/v1/disputes/{world['case_id']}/verdict"
        resp = post(client, path, rng, corrupt(rng, base))
        if target == "/v1/verify" and resp.status_code == 200:
            # verify answers {"valid": false} for well-formed but wrong credentials: not an error, stores nothing
            assert resp.json()["valid"] is False
        else:
            assert_rejected(resp, f"{path} #{sent}")
        sent += 1
    assert sent == PER_ENDPOINT
    assert count_rows(folder) == before


NON_OBJECT_BODIES = [b"", b"null", b"[]", b"[1,2,3]", b"123", b'"str"', b"true", b"{", b'{"a":', b"\xff\xfe\x00",
                     b"{" * 3000 + b"}" * 3000, b"[" * 5000, b'{"a":' + b"9" * 6000 + b"}", b"NaN", b'{"x": NaN}',
                     b'{"init_data": "\\ud800", "blinded_message": "AA"}', b"\x00" * 100]


@pytest.mark.parametrize("path", ["/v1/issue", "/v1/verify", "/v1/register", "/v1/deals", "/v1/disputes"])
def test_non_object_and_garbage_bodies(world, path):
    client, folder = world["client"], world["folder"]
    before = count_rows(folder)
    for body in NON_OBJECT_BODIES:
        assert_rejected(client.post(path, content=body, headers={"content-type": "application/json"}), f"{path} {body[:20]!r}")
    assert count_rows(folder) == before


@pytest.mark.parametrize("path", ["/v1/issue", "/v1/verify", "/v1/register", "/v1/deals", "/v1/disputes",
                                  "/v1/challenge", "/v1/disputes/1/verdict"])
def test_body_over_the_cap_is_413(world, path):
    client, folder = world["client"], world["folder"]
    before = count_rows(folder)
    for size in (MAX_BODY_BYTES + 1, MAX_BODY_BYTES * 4):
        resp = client.post(path, content=b"x" * size, headers={"content-type": "application/json"})
        assert resp.status_code == 413
        assert resp.json() == {"detail": {"code": "body_too_large"}}
    assert count_rows(folder) == before


def test_chunked_body_over_the_cap_is_413(world):
    """No Content-Length (chunked transfer): the cap must still hold."""
    client, folder = world["client"], world["folder"]
    before = count_rows(folder)

    def chunks():
        for _ in range(8):
            yield b"x" * (MAX_BODY_BYTES // 2)

    resp = client.post("/v1/issue", content=chunks(), headers={"content-type": "application/json"})
    assert resp.status_code == 413 and resp.json() == {"detail": {"code": "body_too_large"}}
    assert count_rows(folder) == before


def test_bad_content_length_header(world):
    client = world["client"]
    for value in ("abc", "-5", "1e3", " "):
        try:
            resp = client.post("/v1/verify", content=b"{}", headers={"content-type": "application/json", "content-length": value})
        except Exception:  # noqa: BLE001 - the HTTP client or server refusing a malformed header is also a rejection
            continue
        assert_rejected(resp, f"content-length {value!r}")


BAD_KEYS = ["", "zz", "g" * 64, "a" * 63, "a" * 65, "A" * 200, "%00" * 32, "%ff" * 32, "é" * 64, "..%2f" * 10,
            "0x" + "a" * 62, " " + "a" * 63, "a" * 4000, "a" * 63 + "%0a", "‮" * 64]


@pytest.mark.parametrize("suffix", ["", "/badge", "/deals", "/disputes"])
def test_bad_agent_keys(world, suffix):
    client = world["client"]
    for key in BAD_KEYS:
        resp = client.get(f"/v1/agents/{key}{suffix}")
        assert_rejected(resp, f"GET agents/{key[:20]!r}{suffix}")


@pytest.mark.parametrize("suffix", ["/deals", "/disputes"])
def test_bad_limits(world, suffix):
    client = world["client"]
    for limit in ("abc", "", "1.5", "-1", "0", str(2**70), "1e3", "%00", "NaN", "٣"):
        resp = client.get(f"/v1/agents/{world['a']}{suffix}", params={"limit": limit})
        if resp.status_code == 200:
            assert len(resp.json()["deals" if suffix == "/deals" else "cases"]) <= 100  # clamped, still fine
        else:
            assert_rejected(resp, f"limit={limit!r}")


BAD_CASE_IDS = ["abc", "-1", "0", "1.5", "", "1e3", str(2**63), str(2**63 - 1), str(2**64), str(2**64 - 1), str(10**30),
                str(-(2**70)), "%00", "٣", " 1", "1 ", "0x10", "9" * 5000]


def test_bad_case_ids_on_get_and_verdict(world):
    client, folder = world["client"], world["folder"]
    before = count_rows(folder)
    body = world["bodies"]["verdict"]
    for cid in BAD_CASE_IDS:
        resp = client.get(f"/v1/disputes/{cid}")
        if cid != "":
            assert_rejected(resp, f"GET disputes/{cid[:20]}")
        resp = client.post(f"/v1/disputes/{cid}/verdict", json=body)
        assert_rejected(resp, f"POST disputes/{cid[:20]}/verdict")
    assert count_rows(folder) == before


def test_wrong_methods_and_unknown_paths(world):
    client = world["client"]
    for method, path in [("POST", "/v1/health"), ("POST", "/v1/issuer"), ("GET", "/v1/issue"), ("GET", "/v1/challenge"),
                         ("DELETE", "/v1/deals"), ("PUT", "/v1/register"), ("GET", "/v1/verify"), ("GET", "/v1/nope"),
                         ("GET", "/v1/agents"), ("GET", "/v1/agents/" + "a" * 64 + "/nope"), ("GET", "/"),
                         ("POST", "/v1/health/extra"), ("PATCH", "/v1/disputes/1")]:
        assert_rejected(client.request(method, path), f"{method} {path}")


def test_total_number_of_bad_requests():
    """The task asks for at least 300 generated bad requests in total."""
    generated = PER_ENDPOINT * len(POST_TARGETS)
    fixed = (len(NON_OBJECT_BODIES) * 5 + 14 + 3 + len(BAD_KEYS) * 4 + 20 + len(BAD_CASE_IDS) * 2 + 13)
    assert generated + fixed >= 300


def test_zz_the_uncorrupted_bodies_are_valid(world):
    """Guards the fuzz itself: the bodies it corrupts are accepted when left alone (runs last, changes the stores)."""
    client = world["client"]
    for path in ("/v1/issue", "/v1/register", "/v1/deals", "/v1/disputes"):
        resp = client.post(path, json=world["bodies"][path])
        assert resp.status_code == 200, (path, resp.text)
