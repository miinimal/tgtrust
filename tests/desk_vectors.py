"""Test vectors for the Trust Desk browser verifier (desk/verifier.js), made by the Python implementation.

Run ``python -m tests.desk_vectors`` to write ``desk/tests/vectors.json``. The inputs (keys, cards, credential files,
signed requests, badges, Concordium links) are made once and stored; every expected output is computed here by the
Python code the desk mirrors (``client.agent_key_from_card``, ``client.CredentialFile``, ``issuer.verify_credential``,
``gate.TrustGate``). ``tests/test_desk_vectors.py`` recomputes the expectations from the stored inputs on every run,
so the file cannot drift from the Python behaviour, and ``desk/tests/verifier.test.mjs`` asserts the browser module
gives the same answers.

The issuer keys here are stand-ins made for the vectors; they are not the demo issuer's key.
"""

from __future__ import annotations

import base64
import copy
import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tgtrust import blind_rsa, concordium, gate
from tgtrust.client import AgentIdentity, CredentialFile, agent_key_from_card, b64url_encode
from tgtrust.erc8004 import TGTRUST_EXTENSION_URI
from tgtrust.issuer import Holder, verify_credential
from tgtrust.registry import agent_token
from tgtrust.service import key_id

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "desk" / "tests" / "vectors.json"
NOW = 1794700000
CONCORDIUM_URI = "https://docs.concordium.com/a2a-extensions/concordium-badge/v1"


def _pem(private_key) -> str:
    return private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _agent(seed_hex: str) -> AgentIdentity:
    return AgentIdentity(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)))


def _issuer_public(entry: dict):
    return serialization.load_pem_public_key(entry["public_key_pem"].encode())


def _tier(t: dict) -> gate.Tier:
    return gate.Tier(t["name"], allowed=t["allowed"], prepay=t["prepay"], credit_limit=t["credit_limit"])


def _policy(p: dict) -> gate.Policy:
    return gate.Policy(anonymous=_tier(p["anonymous"]), unknown=_tier(p["unknown"]), verified=_tier(p["verified"]),
                       staked=_tier(p["staked"]),
                       concordium_tier=_tier(p["concordium_tier"]) if p.get("concordium_tier") else None,
                       require_concordium=p.get("require_concordium"),
                       min_stake_nanogram=p["min_stake_nanogram"], max_upheld_disputes=p["max_upheld_disputes"])


# --- expectations: the Python behaviour for each stored input --------------------------------------------------

def expect_card(card) -> dict:
    try:
        return {"key": agent_key_from_card(card), "error": None}
    except ValueError as exc:
        return {"key": None, "error": str(exc)}


def expect_credential(file: dict, issuers: dict, issuer_name: str) -> dict:
    try:
        cf = CredentialFile.from_dict(file)
    except ValueError as exc:
        return {"parsed": False, "error": str(exc), "signature_valid": None, "key_id_matches": None}
    entry = issuers[issuer_name]
    return {"parsed": True, "error": None, "agent": cf.agent_public_key.hex(),
            "signature_valid": verify_credential(_issuer_public(entry), cf.credential),
            "key_id_matches": cf.key_id == entry["key_id"]}


def expect_request(case: dict) -> dict:
    nonces = gate.NonceCache(120)
    for agent, nonce in case.get("seen", []):
        nonces.use(agent, nonce, case["now"])
    g = gate.TrustGate(lambda k: {}, nonces=nonces, clock=lambda: case["now"])
    try:
        agent = g.verify(case["method"], case["path"], case["headers"], base64.b64decode(case["body_b64"]))
        return {"agent": agent, "error": None}
    except gate.GateError as exc:
        return {"agent": None, "error": exc.code}


class _LookupFailed(Exception):
    pass


def expect_decision(case: dict) -> dict:
    def badge_lookup(key):
        if case["badge"] is None:
            raise _LookupFailed("issuer unreachable")
        return copy.deepcopy(case["badge"])

    link = case.get("link")
    link_lookup = (lambda key: concordium.ConcordiumLink(**link)) if link else None
    base = case["issuer_url"]
    g = gate.TrustGate(badge_lookup, _policy(case["policy"]), link_lookup=link_lookup, clock=lambda: case["now"],
                       badge_url=lambda key: f"{base}/agents/{key}/badge")
    decision = g.decide(case["method"], case["path"], case["headers"], base64.b64decode(case["body_b64"]))
    return decision.to_dict()


def replay_fetch(case: dict):
    """A Concordium fetch that answers from the case's stored replies, as the browser test does."""

    def fetch(method, url, body, headers):
        if case.get("http", 200) != 200:
            return case["http"], b"{}"
        if method == "GET":
            return 200, json.dumps(case["replies"]["badge_check"]).encode()
        name = json.loads(body)["params"]["name"]
        return 200, json.dumps(case["replies"][name]).encode()

    return fetch


def expect_link(case: dict) -> dict:
    link = concordium.read_link(case["agent"], concordium.RegistryReader(case["network"], fetch=replay_fetch(case)))
    return {"link": vars(link), "lines": concordium.link_lines(link)}


def expectations(inputs: dict) -> dict:
    return {
        "cards": [expect_card(c["card"]) for c in inputs["cards"]],
        "credentials": [expect_credential(c["file"], inputs["issuers"], c["issuer"]) for c in inputs["credentials"]],
        "requests": [expect_request(r) for r in inputs["requests"]],
        "decisions": [expect_decision(d) for d in inputs["decisions"]],
        "links": [expect_link(c) for c in inputs["links"]],
    }


GOLDEN = ROOT / "tests" / "golden" / "concordium"


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))


def _with_inner(reply: dict, **changes) -> dict:
    reply = copy.deepcopy(reply)
    inner = json.loads(reply["result"]["content"][0]["text"])
    inner.update(changes)
    reply["result"]["content"][0]["text"] = json.dumps(inner)
    return reply


def _make_links(agent_hex: str) -> list[dict]:
    owner = _golden("owner_found")
    account = json.loads(owner["result"]["content"][0]["text"])["owner"]
    verdict = _golden("badgecheck_1166")
    verdict["on_chain"]["owner_account"] = account
    found = {"owner_of_key": owner, "agent_by_external_reference": _golden("extref_found"), "badge_check": verdict}
    base = {"agent": agent_hex, "network": "testnet"}
    other_owner = copy.deepcopy(verdict)
    other_owner["on_chain"]["owner_account"] = "4Mk8CZ3QSgRmvRVfnurx8a1WcLgwyS9dfkJU63eAPJf5JQMDsu"
    invalid = copy.deepcopy(verdict)
    invalid["badge_valid"] = False
    return [
        {"name": "not bound", **base, "replies": {**found, "owner_of_key": _golden("owner_none")}},
        {"name": "bound, badge valid", **base, "replies": found},
        {"name": "bound, badge not valid", **base, "replies": {**found, "badge_check": invalid}},
        {"name": "binding revoked", **base, "replies": {**found, "owner_of_key": _with_inner(owner, status="Revoked")}},
        {"name": "badge owned by another account", **base, "replies": {**found, "badge_check": other_owner}},
        {"name": "bound, no agent", **base, "replies": {**found, "agent_by_external_reference": _golden("extref_none")}},
        {"name": "owner is not an address", **base, "replies": {**found,
                                                                  "owner_of_key": _with_inner(owner, owner="xyz")}},
        {"name": "registry down", **base, "http": 503, "replies": found},
    ]


# --- inputs: made once ------------------------------------------------------------------------------------------

def _make_inputs() -> dict:
    issuers = {}
    signing = {}
    for name in ("main", "other"):
        sk = blind_rsa.generate_key(2048)
        signing[name] = sk
        issuers[name] = {"key_id": key_id(sk.public_key()), "public_key_pem": _pem(sk),
                         "credential_prefix": "tgtrust/v1/credential:", "epoch": f"vectors-{name}"}

    seeds = [secrets.token_hex(32) for _ in range(3)]
    agents = [{"seed_hex": s, "public_hex": _agent(s).hex} for s in seeds]
    alice, bob, carol = agents

    def credential_file(agent_hex: str, issuer: str) -> dict:
        salt = secrets.token_bytes(16)
        token = agent_token(bytes.fromhex(agent_hex), salt)
        holder = Holder(signing[issuer].public_key())
        pending = holder.prepare(token)
        cred = holder.finalize(pending, blind_rsa.blind_sign(signing[issuer], pending.blinded_message))
        return {"format": "tgtrust-credential/v1", "issuer": "https://issuer.example/v1",
                "key_id": issuers[issuer]["key_id"], "epoch": issuers[issuer]["epoch"],
                "agent_public_key": agent_hex, "salt": b64url_encode(salt), "token": b64url_encode(cred.token),
                "signature": b64url_encode(cred.signature)}

    good = credential_file(alice["public_hex"], "main")
    flipped = bytearray(base64.urlsafe_b64decode(good["signature"] + "=="))
    flipped[10] ^= 1
    credentials = [
        {"name": "valid, bound to alice", "issuer": "main", "file": good},
        {"name": "signature from another issuer", "issuer": "main", "file": credential_file(alice["public_hex"], "other")},
        {"name": "checked against the issuer that signed it", "issuer": "other",
         "file": credential_file(bob["public_hex"], "other")},
        {"name": "token not bound to the stated key", "issuer": "main",
         "file": {**good, "agent_public_key": bob["public_hex"]}},
        {"name": "signature altered", "issuer": "main", "file": {**good, "signature": b64url_encode(bytes(flipped))}},
        {"name": "wrong format", "issuer": "main", "file": {**good, "format": "tgtrust-credential/v0"}},
        {"name": "missing salt", "issuer": "main", "file": {k: v for k, v in good.items() if k != "salt"}},
        {"name": "key id of another issuer", "issuer": "main", "file": {**good, "key_id": issuers["other"]["key_id"]}},
    ]

    ext = lambda key: {"uri": TGTRUST_EXTENSION_URI, "params": {"agentKey": key}}  # noqa: E731
    cards = [
        {"name": "A2A extension", "card": {"name": "a", "capabilities": {"extensions": [ext(alice["public_hex"])]}}},
        {"name": "A2A extension, upper case", "card": {"capabilities": {"extensions": [ext(alice["public_hex"].upper())]}}},
        {"name": "ERC-8004 field", "card": {"tgtrust": {"agent_key": bob["public_hex"]}}},
        {"name": "both, same key", "card": {"tgtrust": {"agent_key": bob["public_hex"]},
                                            "capabilities": {"extensions": [ext(bob["public_hex"])]}}},
        {"name": "two different keys", "card": {"tgtrust": {"agent_key": bob["public_hex"]},
                                                "capabilities": {"extensions": [ext(alice["public_hex"])]}}},
        {"name": "no tgtrust key", "card": {"capabilities": {"extensions": [{"uri": CONCORDIUM_URI, "params": {}}]}}},
        {"name": "short key", "card": {"tgtrust": {"agent_key": "abc"}}},
        {"name": "not an object", "card": ["not", "a", "card"]},
        {"name": "extension without params", "card": {"capabilities": {"extensions": [{"uri": TGTRUST_EXTENSION_URI}]}}},
    ]

    def signed(agent: dict, method="POST", path="/v1/answer?q=1", body=b'{"q":1}', now=NOW, nonce="nonce-0123456789abcd"):
        headers = gate.sign_request(_agent(agent["seed_hex"]), method, path, body, now=now, nonce=nonce)
        return {"method": method, "path": path, "body_b64": base64.b64encode(body).decode(), "now": NOW,
                "headers": headers}

    a_req = signed(alice)
    requests = [
        {"name": "valid", **a_req},
        {"name": "no tgtrust headers", **{**a_req, "headers": {}}},
        {"name": "header names in lower case", **{**a_req, "headers": {k.lower(): v for k, v in a_req["headers"].items()}}},
        {"name": "missing signature", **{**a_req, "headers": {k: v for k, v in a_req["headers"].items()
                                                              if k != gate.H_SIG}}},
        {"name": "body changed", **{**a_req, "body_b64": base64.b64encode(b'{"q":2}').decode()}},
        {"name": "path changed", **{**a_req, "path": "/v1/answer?q=2"}},
        {"name": "method changed", **{**a_req, "method": "GET"}},
        {"name": "stale", **{**a_req, "now": NOW + 121}},
        {"name": "edge of the window", **{**a_req, "now": NOW + 120}},
        {"name": "replayed nonce", **a_req, "seen": [[alice["public_hex"], "nonce-0123456789abcd"]]},
        {"name": "agent key upper case", **{**a_req, "headers": {**a_req["headers"],
                                                                gate.H_AGENT: alice["public_hex"].upper()}}},
        {"name": "bad agent key", **{**a_req, "headers": {**a_req["headers"], gate.H_AGENT: "zz" * 32}}},
        {"name": "bad time", **{**a_req, "headers": {**a_req["headers"], gate.H_TIME: "soon"}}},
        {"name": "short nonce", **{**a_req, "headers": {**a_req["headers"], gate.H_NONCE: "short"}}},
        {"name": "GET with empty body", **signed(carol, method="GET", path="/v1/price", body=b"")},
        {"name": "signature of another key", **{**a_req, "headers": {**a_req["headers"],
                                                                    gate.H_AGENT: bob["public_hex"]}}},
        {"name": "signature not base64url", **{**a_req, "headers": {**a_req["headers"], gate.H_SIG: "+/+/"}}},
        {"name": "signature too short", **{**a_req, "headers": {**a_req["headers"], gate.H_SIG: "AAAA"}}},
    ]

    policy = {"anonymous": {"name": "anonymous", "allowed": False, "prepay": True, "credit_limit": 0},
              "unknown": {"name": "unknown", "allowed": True, "prepay": True, "credit_limit": 0},
              "verified": {"name": "verified", "allowed": True, "prepay": True, "credit_limit": 0},
              "staked": {"name": "staked", "allowed": True, "prepay": False, "credit_limit": 1000},
              "concordium_tier": {"name": "staked+concordium", "allowed": True, "prepay": False, "credit_limit": 5000},
              "require_concordium": "testnet", "min_stake_nanogram": 500_000_000, "max_upheld_disputes": 0}
    no_cc = {**policy, "concordium_tier": None, "require_concordium": None}

    def badge(agent, level, *, stake=None, deals=(0, 0), upheld=0, filed=0):
        return {"agent": agent["public_hex"], "level": level, "unique_owner": level in ("verified", "staked"),
                "issuer_key_id": issuers["main"]["key_id"], "registered_at": NOW - 86400,
                "stake": stake, "history": {"registered_at": NOW - 86400, "days_registered": 1,
                                            "deals": {"count": deals[0], "with_staked_counterparty": deals[1],
                                                      "distinct_counterparties": deals[0]},
                                            "disputes": {"filed_against": filed, "upheld_against": upheld,
                                                         "open_against": 0, "filed_by": 0}},
                "checked_at": NOW}

    def stake(amount, withdrawing=False, network="testnet"):
        return {"network": network, "contract": "kQD0dNGo6GJnxq7Dc5HWcEfoBWI8UkUwZ6-w7gpwm8G11z-w", "found": True,
                "amount_nanogram": amount, "amount_gram": str(amount / 1e9), "withdrawing": withdrawing,
                "unlock_at": 0, "checked_at": NOW}

    active = {"network": "testnet", "account": "4Mk8CZ3QSgRmvRVfnurx8a1WcLgwyS9dfkJU63eAPJf5JQMDsu",
              "binding_status": "Active", "badge": "JyP9WrFnp62SuD2Gdquuv", "badge_valid": True, "status": "Active",
              "error": None}
    base = {**a_req, "issuer_url": "https://issuer.example/v1"}
    decisions = [
        {"name": "anonymous", **{**base, "headers": {}}, "policy": policy, "badge": None},
        {"name": "bad signature", **{**base, "body_b64": base64.b64encode(b"x").decode()}, "policy": policy,
         "badge": None},
        {"name": "lookup failed", **base, "policy": no_cc, "badge": None},
        {"name": "malformed badge", **base, "policy": no_cc, "badge": {"level": "superb"}},
        {"name": "badge for another key", **base, "policy": no_cc, "badge": badge(bob, "verified")},
        {"name": "unknown", **base, "policy": no_cc, "badge": badge(alice, "unknown")},
        {"name": "revoked", **base, "policy": no_cc, "badge": badge(alice, "revoked")},
        {"name": "verified", **base, "policy": no_cc, "badge": badge(alice, "verified", deals=(3, 1))},
        {"name": "verified, dispute upheld", **base, "policy": no_cc,
         "badge": badge(alice, "verified", upheld=1, filed=2)},
        {"name": "staked enough", **base, "policy": no_cc, "badge": badge(alice, "staked", stake=stake(500_000_000))},
        {"name": "staked below minimum", **base, "policy": no_cc,
         "badge": badge(alice, "staked", stake=stake(499_999_999))},
        {"name": "staked, withdrawing", **base, "policy": no_cc,
         "badge": badge(alice, "staked", stake=stake(900_000_000, withdrawing=True))},
        {"name": "staked, dispute upheld", **base, "policy": no_cc,
         "badge": badge(alice, "staked", stake=stake(900_000_000), upheld=1)},
        {"name": "staked + Concordium valid", **base, "policy": policy,
         "badge": badge(alice, "staked", stake=stake(900_000_000)), "link": active},
        {"name": "verified + Concordium valid", **base, "policy": policy, "badge": badge(alice, "verified"),
         "link": active},
        {"name": "Concordium badge not valid", **base, "policy": policy,
         "badge": badge(alice, "staked", stake=stake(900_000_000)), "link": {**active, "badge_valid": False}},
        {"name": "Concordium not bound", **base, "policy": policy, "badge": badge(alice, "verified"),
         "link": {"network": "testnet", "account": None, "binding_status": None, "badge": None,
                  "badge_valid": None, "status": None, "error": None}},
        {"name": "Concordium read failed", **base, "policy": policy, "badge": badge(alice, "verified"),
         "link": {"network": "testnet", "account": None, "binding_status": None, "badge": None,
                  "badge_valid": None, "status": None, "error": "registry answered HTTP 503"}},
        {"name": "Concordium revoked binding", **base, "policy": policy, "badge": badge(alice, "verified"),
         "link": {**active, "binding_status": "Revoked"}},
    ]
    return {"note": "Made by tests/desk_vectors.py with the Python implementation; stand-in issuer keys.",
            "issuers": issuers, "agents": agents, "cards": cards, "credentials": credentials,
            "requests": requests, "decisions": decisions, "links": _make_links(alice["public_hex"])}


def main() -> None:
    inputs = _make_inputs()
    data = {**inputs, "expected": expectations(inputs)}
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
