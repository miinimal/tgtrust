"""Trust gate: request signatures, replay, freshness, tiers by level, stake, disputes and Concordium."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tgtrust import gate
from tgtrust.client import AgentIdentity
from tgtrust.concordium import ConcordiumLink

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000

POLICY = gate.Policy(
    anonymous=gate.Tier("anonymous", allowed=False),
    unknown=gate.Tier("unknown", prepay=True),
    verified=gate.Tier("verified", prepay=True),
    staked=gate.Tier("staked", prepay=False, credit_limit=1_000),
    concordium_tier=gate.Tier("staked+concordium", prepay=False, credit_limit=5_000),
    require_concordium="testnet",
    min_stake_nanogram=500_000_000,
    max_upheld_disputes=0,
)


def _badge(key: str, level: str, *, stake: int | None = None, withdrawing: bool = False, upheld: int = 0) -> dict:
    b = json.loads((ROOT / "examples" / "card" / "badge-alice.json").read_text())
    b["agent"] = key
    b["level"] = level
    b["history"]["disputes"]["upheld_against"] = upheld
    if stake is not None:
        b["stake"] = {"network": "testnet", "contract": "kQ…", "found": True, "amount_nanogram": stake,
                      "withdrawing": withdrawing}
    return b


class Clock:
    def __init__(self, t: int = NOW):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _gate(badges: dict, links: dict | None = None, policy: gate.Policy = POLICY, clock: Clock | None = None):
    def lookup(key: str) -> dict:
        if key not in badges:
            raise OSError("issuer unreachable")
        return copy.deepcopy(badges[key])

    def link(key: str) -> ConcordiumLink:
        return (links or {}).get(key) or ConcordiumLink("testnet")

    return gate.TrustGate(lookup, policy, link_lookup=link, clock=clock or Clock())


def _signed(agent, method="POST", path="/v1/answer?q=1", body=b'{"x":1}', **kw):
    kw.setdefault("now", NOW)
    return method, path, gate.sign_request(agent, method, path, body, **kw), body


def test_signed_request_from_staked_agent_gets_credit():
    a = AgentIdentity.generate()
    g = _gate({a.hex: _badge(a.hex, "staked", stake=600_000_000)})
    m, p, headers, body = _signed(a)
    d = g.decide(m, p, headers, body)
    assert d.proven and d.agent == a.hex and d.level == "staked"
    assert d.tier.name == "staked" and d.tier.prepay is False and d.tier.credit_limit == 1_000
    assert any("stake: 600000000 nanogram active on TON testnet" in e for e in d.evidence)


def test_no_headers_is_anonymous_and_policy_can_refuse_it():
    a = AgentIdentity.generate()
    d = _gate({a.hex: _badge(a.hex, "staked", stake=10**9)}).decide("GET", "/x", {}, b"")
    assert d.tier.name == "anonymous" and not d.allowed and d.agent is None and d.error is None


@pytest.mark.parametrize("mutate", [
    lambda m, p, h, b: (m, p, h, b + b" "),            # body changed
    lambda m, p, h, b: (m, p + "&q=2", h, b),           # query changed
    lambda m, p, h, b: ("PUT", p, h, b),                # method changed
    lambda m, p, h, b: (m, p, {**h, gate.H_NONCE: "A" * 20}, b),  # nonce changed
])
def test_any_change_to_the_signed_request_is_rejected(mutate):
    a = AgentIdentity.generate()
    g = _gate({a.hex: _badge(a.hex, "staked", stake=10**9)})
    d = g.decide(*mutate(*_signed(a)))
    assert d.error == "bad_signature" and d.tier.name == "anonymous" and not d.proven


def test_claiming_someone_elses_key_fails():
    victim, attacker = AgentIdentity.generate(), AgentIdentity.generate()
    g = _gate({victim.hex: _badge(victim.hex, "staked", stake=10**9)})
    m, p, headers, body = _signed(attacker)
    headers[gate.H_AGENT] = victim.hex
    d = g.decide(m, p, headers, body)
    assert d.error == "bad_signature" and d.tier.name == "anonymous"


def test_replay_is_rejected_once_seen():
    a = AgentIdentity.generate()
    g = _gate({a.hex: _badge(a.hex, "verified")})
    req = _signed(a)
    assert g.decide(*req).tier.name == "verified"
    again = g.decide(*req)
    assert again.error == "replay" and again.tier.name == "anonymous"


def test_stale_and_future_requests_are_rejected():
    a = AgentIdentity.generate()
    g = _gate({a.hex: _badge(a.hex, "verified")})
    assert g.decide(*_signed(a, now=NOW - 121)).error == "stale"
    assert g.decide(*_signed(a, now=NOW + 121)).error == "stale"
    assert g.decide(*_signed(a, now=NOW - 120)).error is None


@pytest.mark.parametrize("headers,code", [
    ({gate.H_AGENT: "ab"}, "missing_header"),
    ({gate.H_AGENT: "zz" * 32, gate.H_TIME: str(NOW), gate.H_NONCE: "n" * 16, gate.H_SIG: "AA"}, "bad_agent"),
    ({gate.H_AGENT: "ab" * 32, gate.H_TIME: "-5", gate.H_NONCE: "n" * 16, gate.H_SIG: "AA"}, "bad_time"),
    ({gate.H_AGENT: "ab" * 32, gate.H_TIME: str(NOW), gate.H_NONCE: "short", gate.H_SIG: "AA"}, "bad_nonce"),
    ({gate.H_AGENT: "ab" * 32, gate.H_TIME: str(NOW), gate.H_NONCE: "n" * 16, gate.H_SIG: "A+/="}, "bad_signature"),
    ({gate.H_AGENT: "ab" * 32, gate.H_TIME: str(NOW), gate.H_NONCE: "n" * 16, gate.H_SIG: "AAAA"}, "bad_signature"),
])
def test_malformed_headers_have_stable_codes(headers, code):
    d = _gate({}).decide("GET", "/x", headers, b"")
    assert d.error == code and d.tier.name == "anonymous"


def test_header_names_are_case_insensitive():
    a = AgentIdentity.generate()
    m, p, headers, body = _signed(a)
    lower = {k.lower(): v for k, v in headers.items()}
    assert _gate({a.hex: _badge(a.hex, "verified")}).decide(m, p, lower, body).tier.name == "verified"


def test_unknown_revoked_and_lookup_failure_stay_unknown():
    u, r, gone = AgentIdentity.generate(), AgentIdentity.generate(), AgentIdentity.generate()
    g = _gate({u.hex: _badge(u.hex, "unknown"), r.hex: _badge(r.hex, "revoked")})
    assert g.decide(*_signed(u)).tier.name == "unknown"
    assert g.decide(*_signed(r)).tier.name == "unknown"
    d = g.decide(*_signed(gone))
    assert d.tier.name == "unknown" and d.error == "badge_lookup" and d.proven


def test_badge_for_another_key_or_bad_level_is_not_trusted():
    a, b = AgentIdentity.generate(), AgentIdentity.generate()
    g = _gate({a.hex: _badge(b.hex, "staked", stake=10**9)})
    assert g.decide(*_signed(a)).error == "badge_malformed"
    g = _gate({a.hex: {**_badge(a.hex, "staked", stake=10**9), "level": "platinum"}})
    assert g.decide(*_signed(a)).error == "badge_malformed"


def test_small_or_withdrawing_stake_gets_only_the_verified_tier():
    a, w = AgentIdentity.generate(), AgentIdentity.generate()
    g = _gate({a.hex: _badge(a.hex, "staked", stake=100), w.hex: _badge(w.hex, "staked", stake=10**9, withdrawing=True)})
    assert g.decide(*_signed(a)).tier.name == "verified"
    assert g.decide(*_signed(w)).tier.name == "verified"


def test_upheld_dispute_holds_agent_at_unknown():
    a = AgentIdentity.generate()
    d = _gate({a.hex: _badge(a.hex, "staked", stake=10**9, upheld=1)}).decide(*_signed(a))
    assert d.tier.name == "unknown" and any("disputes upheld" in e for e in d.evidence)


def test_valid_concordium_badge_raises_the_tier():
    a = AgentIdentity.generate()
    link = ConcordiumLink("testnet", account="3abc", binding_status="Active", badge="<1,0>", badge_valid=True)
    d = _gate({a.hex: _badge(a.hex, "staked", stake=10**9)}, {a.hex: link}).decide(*_signed(a))
    assert d.tier.name == "staked+concordium" and d.tier.credit_limit == 5_000
    assert d.concordium["account"] == "3abc"


@pytest.mark.parametrize("link", [
    ConcordiumLink("testnet"),
    ConcordiumLink("testnet", account="3abc", binding_status="Revoked"),
    ConcordiumLink("testnet", account="3abc", binding_status="Active", badge="<1,0>", badge_valid=False),
    ConcordiumLink("testnet", account="3abc", binding_status="Active", badge="<1,0>", badge_valid=True,
                   error="badge owner is a different account than the key binding"),
])
def test_concordium_counts_only_when_bound_and_valid(link):
    a = AgentIdentity.generate()
    d = _gate({a.hex: _badge(a.hex, "staked", stake=10**9)}, {a.hex: link}).decide(*_signed(a))
    assert d.tier.name == "staked"
    assert any(e.startswith("Concordium: not counted") for e in d.evidence)


def test_x402_extra_describes_the_decision():
    a = AgentIdentity.generate()
    d = _gate({a.hex: _badge(a.hex, "verified")}).decide(*_signed(a))
    extra = gate.x402_extra(d, issuer_url="https://trust.example.org/v1")
    assert extra["tier"] == {"name": "verified", "allowed": True, "prepay": True, "creditLimit": "0"}
    assert extra["headers"] == list(gate.HEADERS) and extra["scheme"] == "tgtrust-req/v1"
    json.dumps(extra)


def test_x402_v2_extension_carries_info_and_schema():
    a = AgentIdentity.generate()
    d = _gate({a.hex: _badge(a.hex, "staked", stake=10**9)}).decide(*_signed(a))
    ext = gate.x402_extension(d, issuer_url="https://trust.example.org/v1")
    assert list(ext) == ["tgtrust"] and set(ext["tgtrust"]) == {"info", "schema"}
    assert ext["tgtrust"]["info"] == gate.x402_extra(d, issuer_url="https://trust.example.org/v1")
    assert set(ext["tgtrust"]["schema"]["required"]) <= set(ext["tgtrust"]["info"])
    json.dumps(ext)
    for info in (ext["tgtrust"]["info"], gate.x402_extension(_gate({}).decide("GET", "/", {}, b""))["tgtrust"]["info"]):
        schema = gate.EXTENSION_SCHEMA
        assert set(schema["required"]) <= set(info) and set(info) <= set(schema["properties"])
        assert info["scheme"] == schema["properties"]["scheme"]["const"]
        assert set(schema["properties"]["tier"]["required"]) == set(info["tier"])
        assert info["tier"]["creditLimit"].isdigit()
        assert info["agent"] is None or len(info["agent"]) == 64


def test_nonce_cache_forgets_old_entries_and_stays_bounded():
    c = gate.NonceCache(window_seconds=10, max_entries=3)
    assert c.use("a", "n1", 0) and not c.use("a", "n1", 5)
    assert c.use("a", "n1", 25)  # older than two windows: forgotten
    for i in range(10):
        c.use("a", f"x{i}", 30)
    assert len(c._seen) <= 3


def test_request_message_is_fixed_bytes():
    msg = gate.request_message("POST", "/v1/a?b=1", 1700000000, "abcdefghijklmnop", b"{}")
    assert msg == (b"tgtrust-req/v1\nPOST\n/v1/a?b=1\n1700000000\nabcdefghijklmnop\n"
                   b"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
    with pytest.raises(gate.GateError):
        gate.request_message("POST", "/a\nb", 1, "abcdefghijklmnop", b"")
