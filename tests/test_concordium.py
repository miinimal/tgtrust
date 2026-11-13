"""Concordium Agent Registry link. Golden replies were recorded from the hosted registry service on 2026-11-13
(tests/golden/concordium); no test touches the network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tgtrust import concordium as ccd
from tgtrust.client import AgentIdentity

GOLDEN = Path(__file__).parent / "golden" / "concordium"
ACCOUNT = "45GYzCjNUQurQEN8TRmWDjdYhfKJgrusZ6jUGs373NamwjmRh6"   # owner of testnet agent 1166
KEY = "ab" * 32


def golden(name: str) -> dict:
    return json.loads((GOLDEN / f"{name}.json").read_text())


def tool_text(name: str):
    return json.loads(golden(name)["result"]["content"][0]["text"])


@pytest.mark.parametrize("network", ["testnet", "mainnet"])
def test_canonical_bytes_match_the_registry_byte_for_byte(network):
    expected = tool_text(f"canon_{network}")["bytes_hex"]
    assert ccd.canonical_bytes(ACCOUNT, KEY, network).hex() == expected


def test_account_address_is_checked():
    assert len(ccd.account_bytes(ACCOUNT)) == 32
    broken = ACCOUNT[:-1] + ("7" if ACCOUNT[-1] != "7" else "8")
    with pytest.raises(ValueError, match="checksum"):
        ccd.account_bytes(broken)
    for bad in ["", "0OIl" * 12, "abc"]:
        with pytest.raises(ValueError):
            ccd.account_bytes(bad)


def test_binding_request_is_signed_by_the_agent_key():
    agent = AgentIdentity.generate()
    req = ccd.binding_request(agent, ACCOUNT, "testnet")
    assert req["external_key"] == {"namespace": "tgtrust:v1", "key_type": "ed25519", "public_key_hex": agent.hex}
    assert req["proof"]["scheme"] == "solana-ed25519" and req["sender"] == ACCOUNT
    Ed25519PublicKey.from_public_bytes(agent.public_key).verify(
        bytes.fromhex(req["proof"]["signature_hex"]), ccd.canonical_bytes(ACCOUNT, agent.hex, "testnet"))
    # a signature for testnet is not valid for mainnet (genesis hash and contract differ)
    assert ccd.canonical_bytes(ACCOUNT, agent.hex, "testnet") != ccd.canonical_bytes(ACCOUNT, agent.hex, "mainnet")


class FakeRegistry:
    """Replays recorded replies; `bound` decides whether our key has a binding."""

    def __init__(self, bound: bool, *, status: str = "Active", badge_owner: str = ACCOUNT, http: int = 200):
        self.bound, self.status, self.badge_owner, self.http = bound, status, badge_owner, http
        self.calls = []

    def __call__(self, method, url, body, headers):
        if self.http != 200:
            return self.http, b"{}"
        if method == "GET":
            self.calls.append(("badge-check", url))
            verdict = golden("badgecheck_1166")
            verdict["on_chain"]["owner_account"] = self.badge_owner
            return 200, json.dumps(verdict).encode()
        call = json.loads(body)
        assert headers["Accept"] == "application/json, text/event-stream"
        name, args = call["params"]["name"], call["params"]["arguments"]
        self.calls.append((name, args))
        assert args["network"] == "testnet"
        if name == "owner_of_key":
            reply = golden("owner_found" if self.bound else "owner_none")
            if self.bound:
                inner = json.loads(reply["result"]["content"][0]["text"])
                inner["status"] = self.status
                reply["result"]["content"][0]["text"] = json.dumps(inner)
        elif name == "agent_by_external_reference":
            assert args["external_reference"]["key"]["namespace"] == "tgtrust:v1"
            assert args["external_reference"]["contract_address"] == {"index": 12801, "subindex": 0}
            reply = golden("extref_found" if self.bound else "extref_none")
        else:
            raise AssertionError(name)
        return 200, json.dumps(reply).encode()


def test_unbound_key():
    link = ccd.read_link(KEY, ccd.RegistryReader("testnet", fetch=FakeRegistry(bound=False)))
    assert link.account is None and link.error is None
    assert ccd.link_lines(link) == ["Concordium: this key is not bound to any Concordium account "
                                    "[source: Concordium testnet Agent Registry, CIS-8 / CIS-8004]"]


def test_bound_key_with_valid_badge():
    fake = FakeRegistry(bound=True)
    link = ccd.read_link(KEY, ccd.RegistryReader("testnet", fetch=fake))
    assert (link.account, link.binding_status, link.badge, link.badge_valid, link.status) == (
        ACCOUNT, "Active", "JyP9WZqZqhYXTLTYqJYcT", True, "Active")
    text = "\n".join(ccd.link_lines(link))
    assert "key bound to account 45GYzC…mRh6" in text and "the person is not disclosed" in text
    assert "Concordium badge: JyP9WZqZqhYXTLTYqJYcT, valid (status Active)" in text
    assert fake.calls[-1] == ("badge-check", ccd.BADGE_CHECK_URL + "JyP9WZqZqhYXTLTYqJYcT?network=testnet")


def test_badge_owned_by_another_account_is_not_valid():
    link = ccd.read_link(KEY, ccd.RegistryReader("testnet", fetch=FakeRegistry(bound=True, badge_owner="x")))
    assert link.badge_valid is False and "different account" in link.error


def test_revoked_binding_is_not_used():
    link = ccd.read_link(KEY, ccd.RegistryReader("testnet", fetch=FakeRegistry(bound=True, status="Revoked")))
    assert link.badge is None
    assert ccd.link_lines(link)[0].startswith("Concordium: binding to account 45GYzC…mRh6 is Revoked, not active")


def test_registry_down_is_unknown_not_unbound():
    link = ccd.read_link(KEY, ccd.RegistryReader("testnet", fetch=FakeRegistry(bound=True, http=503)))
    assert link.account is None and "HTTP 503" in link.error
    assert ccd.link_lines(link)[0].startswith("Concordium: unknown, the read failed (registry answered HTTP 503)")


def test_tool_error_is_reported():
    def fetch(method, url, body, headers):
        return 200, json.dumps({"result": {"content": [{"type": "text", "text": "config error: x"}],
                                           "isError": True}}).encode()
    with pytest.raises(ccd.ConcordiumError, match="config error"):
        ccd.RegistryReader("testnet", fetch=fetch).owner_of_key(KEY)


def test_unknown_network_refused():
    with pytest.raises(ValueError):
        ccd.RegistryReader("devnet")


class BadgeRegistry(FakeRegistry):
    """Testnet agent 1166 as recorded, with its external reference set to `ref_key` under `namespace`."""

    def __init__(self, ref_key: str, *, namespace: str = "tgtrust:v1", badge_status: str = "Active", **kw):
        super().__init__(bound=True, **kw)
        self.ref_key, self.namespace, self.badge_status = ref_key, namespace, badge_status

    def __call__(self, method, url, body, headers):
        if method == "POST" and json.loads(body)["params"]["name"] == "get_badge_json":
            reply = golden("getbadge_1166")
            inner = json.loads(reply["result"]["content"][0]["text"])
            inner["status"] = self.badge_status
            inner["extension"]["params"]["externalReference"].update(
                namespace=self.namespace, keyType="ed25519", publicKey=self.ref_key)
            reply["result"]["content"][0]["text"] = json.dumps(inner)
            return 200, json.dumps(reply).encode()
        return super().__call__(method, url, body, headers)


def test_verified_badge_accepts_only_this_key():
    reader = ccd.RegistryReader("testnet", fetch=BadgeRegistry(KEY))
    got = ccd.verified_badge(KEY, "JyP9WZqZqhYXTLTYqJYcT", reader)
    assert got["registrations_entry"] == {"agentId": 1166, "agentRegistry": "ccd:4221332d34e1694168c2a0c0b3fd0f27:12802.0"}
    assert got["extension"]["uri"] == ccd.BADGE_EXTENSION_URI and got["owner_account"] == ACCOUNT
    for fake, why in [(BadgeRegistry("cd" * 32), "not this tgtrust key"),
                      (BadgeRegistry(KEY, namespace="eip155:1"), "not this tgtrust key"),
                      (BadgeRegistry(KEY, badge_status="Revoked"), "not Active"),
                      (BadgeRegistry(KEY, status="Revoked"), "no active CIS-8 binding")]:
        with pytest.raises(ccd.ConcordiumError, match=why):
            ccd.verified_badge(KEY, "JyP9WZqZqhYXTLTYqJYcT", ccd.RegistryReader("testnet", fetch=fake))


def test_export_with_concordium_badge(monkeypatch, tmp_path, capsys):
    from tgtrust import erc8004
    examples = Path(__file__).parent.parent / "examples" / "erc8004"
    badge = json.loads((examples / "badge-registered.json").read_text())
    monkeypatch.setattr(erc8004, "concordium_fetch", BadgeRegistry(badge["agent"]))
    args = ["--badge", str(examples / "badge-registered.json"), "--profile", str(examples / "profile.json"),
            "--concordium-badge", "JyP9WZqZqhYXTLTYqJYcT"]
    assert erc8004.main(args) == 0
    card = json.loads(capsys.readouterr().out)
    assert card["registrations"] == [{"agentId": 1166, "agentRegistry": "ccd:4221332d34e1694168c2a0c0b3fd0f27:12802.0"}]
    uris = [e["uri"] for e in card["capabilities"]["extensions"]]
    assert uris == [ccd.BADGE_EXTENSION_URI, erc8004.TGTRUST_EXTENSION_URI]
    assert card["capabilities"]["extensions"][1]["params"]["agentKey"] == badge["agent"]
    # a badge bound to another key is refused, and nothing is written
    monkeypatch.setattr(erc8004, "concordium_fetch", BadgeRegistry("cd" * 32))
    assert erc8004.main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "concordium_badge_rejected" in captured.err
