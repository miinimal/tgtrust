"""Agent-side command line and file formats that pair with the holder Mini App."""

from __future__ import annotations

import json
import os
import stat
import time

import pytest
from fastapi.testclient import TestClient

from tgtrust import Issuer, MemoryIssuedStore
from tgtrust.client import (AgentIdentity, CredentialFile, TgTrustClient, _cli, b64url_encode, read_agent_key,
                            register_from_file)
from tgtrust.service import create_app

from .conftest import BOT_ID

USER = {"id": 31337, "first_name": "Cy"}


@pytest.fixture
def world(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    http = TestClient(create_app(issuer=issuer, rate_limit_per_minute=1000))

    def transport(method, url, body):
        resp = http.request(method, url.replace("http://issuer", ""), json=body)
        return resp.status_code, resp.json()

    return TgTrustClient("http://issuer/v1", transport=transport), transport, telegram


def package_for(client, telegram, agent, user=USER) -> dict:
    """What the Mini App hands over: here produced by the Python holder, same format."""
    credential, salt = client.obtain_credential(agent, telegram.init_data(user, auth_date=int(time.time())))
    return {"format": "tgtrust-credential/v1", "issuer": "http://issuer/v1", "key_id": client.issuer_info()["key_id"],
            "epoch": "v1", "agent_public_key": agent.hex, "salt": b64url_encode(salt),
            "token": b64url_encode(credential.token), "signature": b64url_encode(credential.signature)}


def test_new_key_then_register(world, tmp_path, capsys):
    client, transport, telegram = world
    key_file, cred_file = tmp_path / "agent.key", tmp_path / "credential.json"
    assert _cli(["new-key", "--out", str(key_file)]) == 0
    out = capsys.readouterr().out
    agent = read_agent_key(str(key_file))
    assert f"Public key: {agent.hex}" in out and agent.private_bytes().hex() not in out
    if os.name != "nt":  # Windows has no POSIX file modes
        assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    assert _cli(["new-key", "--out", str(key_file)]) == 1  # never overwrites a key
    assert read_agent_key(str(key_file)).hex == agent.hex

    cred_file.write_text(json.dumps(package_for(client, telegram, agent)))
    assert _cli(["register", "--credential", str(cred_file), "--key-file", str(key_file)], transport=transport) == 0
    assert f"Registered: agent {agent.hex}" in capsys.readouterr().out
    assert client.badge(agent.hex)["unique_owner"] is True
    # a second registration is refused by the registry and reported, not raised
    assert _cli(["register", "--credential", str(cred_file), "--key-file", str(key_file)], transport=transport) == 1
    assert "409 already_registered" in capsys.readouterr().out


def test_agent_file_carries_key_and_credential(world, tmp_path, capsys):
    client, transport, telegram = world
    agent = AgentIdentity.generate()
    path = tmp_path / "agent.json"
    path.write_text(json.dumps({"format": "tgtrust-agent/v1", "agent_public_key": agent.hex,
                                "agent_private_key": agent.private_bytes().hex(),
                                "credential": package_for(client, telegram, agent)}))
    assert AgentIdentity.from_agent_file(str(path)).hex == agent.hex
    assert _cli(["register", "--credential", str(path)], transport=transport) == 0
    assert agent.private_bytes().hex() not in capsys.readouterr().out


def test_credential_for_another_key_is_refused_before_any_request(world, tmp_path):
    client, transport, telegram = world
    path = tmp_path / "credential.json"
    path.write_text(json.dumps(package_for(client, telegram, AgentIdentity.generate())))
    calls = []

    def counting(method, url, body):
        calls.append(url)
        return transport(method, url, body)

    with pytest.raises(ValueError, match="different agent key"):
        register_from_file(str(path), AgentIdentity.generate(), transport=counting)
    assert calls == []


@pytest.mark.parametrize("damage", [
    lambda p: p.update(format="other/v1"),
    lambda p: p.pop("salt"),
    lambda p: p.update(agent_public_key="zz"),
    lambda p: p.update(agent_public_key=AgentIdentity.generate().hex),  # token no longer bound to the key
    lambda p: p.update(salt=b64url_encode(os.urandom(16))),
    lambda p: p.update(token=b64url_encode(os.urandom(32))),
])
def test_damaged_credential_files_are_rejected(world, damage):
    client, _, telegram = world
    package = package_for(client, telegram, AgentIdentity.generate())
    damage(package)
    with pytest.raises(ValueError):
        CredentialFile.from_dict(package)


def test_forged_signature_and_changed_issuer_are_caught(world, tmp_path, capsys):
    client, transport, telegram = world
    agent = AgentIdentity.generate()
    key_file = tmp_path / "agent.key"
    key_file.write_text(agent.private_bytes().hex())
    good = package_for(client, telegram, agent)

    forged = dict(good, signature=b64url_encode(os.urandom(256)))
    (tmp_path / "forged.json").write_text(json.dumps(forged))
    assert _cli(["register", "--credential", str(tmp_path / "forged.json"), "--key-file", str(key_file)],
                transport=transport) == 1
    assert "does not verify" in capsys.readouterr().out

    rotated = dict(good, key_id="0" * 16)
    (tmp_path / "rotated.json").write_text(json.dumps(rotated))
    assert _cli(["register", "--credential", str(tmp_path / "rotated.json"), "--key-file", str(key_file)],
                transport=transport) == 1
    assert "issuer key changed" in capsys.readouterr().out

    for bad in ("missing.json",):
        assert _cli(["register", "--credential", str(tmp_path / bad), "--key-file", str(key_file)], transport=transport) == 1
    (tmp_path / "junk.json").write_text("[1, 2")
    assert _cli(["register", "--credential", str(tmp_path / "junk.json"), "--key-file", str(key_file)], transport=transport) == 1
    # nothing above registered the agent
    assert client.badge(agent.hex)["unique_owner"] is False


def test_inconsistent_agent_file(tmp_path):
    a, b = AgentIdentity.generate(), AgentIdentity.generate()
    path = tmp_path / "agent.json"
    path.write_text(json.dumps({"format": "tgtrust-agent/v1", "agent_public_key": a.hex,
                                "agent_private_key": b.private_bytes().hex()}))
    with pytest.raises(ValueError, match="inconsistent"):
        AgentIdentity.from_agent_file(str(path))
    path.write_text(json.dumps({"format": "tgtrust-credential/v1"}))
    with pytest.raises(ValueError):
        AgentIdentity.from_agent_file(str(path))


def test_check_prints_card_and_gates_on_level(world, tmp_path, capsys, monkeypatch):
    client, transport, telegram = world
    stranger = AgentIdentity.generate()
    assert _cli(["check", "--agent", stranger.hex, "--url", "http://issuer/v1"], transport=transport) == 2
    assert "not registered" in capsys.readouterr().out

    agent = AgentIdentity.generate()
    monkeypatch.setenv("TGTRUST_ISSUER_URL", "http://issuer/v1")
    client.register(agent, *client.obtain_credential(agent, telegram.init_data({"id": 4242}, auth_date=int(time.time()))))
    assert _cli(["check", "--agent", agent.hex.upper()], transport=transport) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"AGENT CARD {agent.hex[:8]}") and "Badge level: verified" in out
    assert _cli(["check", "--agent", agent.hex, "--json"], transport=transport) == 0
    assert json.loads(capsys.readouterr().out)["level"] == "verified"


def test_check_rejects_bad_input(world, capsys, monkeypatch):
    _, transport, _ = world
    monkeypatch.delenv("TGTRUST_ISSUER_URL", raising=False)
    assert _cli(["check", "--agent", "zz", "--url", "http://issuer/v1"], transport=transport) == 1
    assert "64-character hex" in capsys.readouterr().out
    assert _cli(["check", "--agent", "ab" * 32], transport=transport) == 1
    assert "TGTRUST_ISSUER_URL" in capsys.readouterr().out


def test_concordium_bind_prints_a_signed_request(tmp_path, capsys):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from tgtrust import concordium
    account = "45GYzCjNUQurQEN8TRmWDjdYhfKJgrusZ6jUGs373NamwjmRh6"
    key_file = tmp_path / "agent.key"
    assert _cli(["new-key", "--out", str(key_file)]) == 0
    capsys.readouterr()
    assert _cli(["concordium-bind", "--key-file", str(key_file), "--account", account]) == 0
    captured = capsys.readouterr()
    request = json.loads(captured.out)
    agent = read_agent_key(str(key_file))
    assert request["sender"] == account and request["network"] == "testnet"
    Ed25519PublicKey.from_public_bytes(agent.public_key).verify(
        bytes.fromhex(request["proof"]["signature_hex"]), concordium.canonical_bytes(account, agent.hex, "testnet"))
    assert agent.private_bytes().hex() not in captured.out + captured.err
    assert "build_cis8_register" in captured.err
    assert _cli(["concordium-bind", "--key-file", str(key_file), "--account", "nope"]) == 1


def test_check_with_concordium_adds_registry_lines(world, capsys, monkeypatch):
    import tgtrust.client as client_mod
    from tests.test_concordium import FakeRegistry
    _, transport, _ = world
    monkeypatch.setattr(client_mod, "concordium_fetch", FakeRegistry(bound=False))
    stranger = AgentIdentity.generate()
    assert _cli(["check", "--agent", stranger.hex, "--url", "http://issuer/v1", "--concordium", "testnet"],
                transport=transport) == 2
    assert "Concordium: this key is not bound to any Concordium account" in capsys.readouterr().out
    monkeypatch.setattr(client_mod, "concordium_fetch", FakeRegistry(bound=True))
    assert _cli(["check", "--agent", stranger.hex, "--url", "http://issuer/v1", "--concordium", "testnet", "--json"],
                transport=transport) == 2
    assert json.loads(capsys.readouterr().out)["concordium"]["badge_valid"] is True


def _card_with(key: str, *, file_key: str | None = None) -> dict:
    from tgtrust.erc8004 import TGTRUST_EXTENSION_URI
    card = {"name": "demo", "capabilities": {"extensions": [
        {"uri": "https://example.org/other", "params": {"agentKey": "00" * 32}},
        {"uri": TGTRUST_EXTENSION_URI, "required": False, "params": {"agentKey": key, "level": "verified"}}]}}
    if file_key is not None:
        card["tgtrust"] = {"agent_key": file_key}
    return card


def test_check_card_reads_the_key_from_a_card(world, tmp_path, capsys, monkeypatch):
    import tgtrust.client as client_mod
    client, transport, telegram = world
    agent = AgentIdentity.generate()
    client.register(agent, *client.obtain_credential(agent, telegram.init_data({"id": 5151}, auth_date=int(time.time()))))

    path = tmp_path / "agent-card.json"
    path.write_text(json.dumps(_card_with(agent.hex.upper(), file_key=agent.hex)))
    assert _cli(["check", "--card", str(path), "--url", "http://issuer/v1"], transport=transport) == 0
    out = capsys.readouterr().out
    assert f"names agent key {agent.hex}" in out and "only a claim" in out and "Badge level: verified" in out

    fetched = []
    monkeypatch.setattr(client_mod, "card_fetch", lambda url: fetched.append(url) or json.dumps(
        _card_with(agent.hex)).encode())
    assert _cli(["check", "--card", "https://agent.example", "--url", "http://issuer/v1", "--json"],
                transport=transport) == 0
    assert fetched == ["https://agent.example/.well-known/agent-card.json"]
    assert json.loads(capsys.readouterr().out)["card_note"].startswith("Card https://agent.example names")


@pytest.mark.parametrize("card, why", [
    ({"name": "no key"}, "no tgtrust agent key"),
    (_card_with("zz"), "not 64 hex"),
    (_card_with("ab" * 32, file_key="cd" * 32), "two different"),
    ([1, 2], "not a JSON object"),
])
def test_check_card_refuses_cards_without_one_clear_key(world, tmp_path, capsys, card, why):
    _, transport, _ = world
    path = tmp_path / "card.json"
    path.write_text(json.dumps(card))
    assert _cli(["check", "--card", str(path), "--url", "http://issuer/v1"], transport=transport) == 1
    assert why in capsys.readouterr().out


def test_check_card_url_must_be_https_and_agent_or_card_not_both(world, capsys):
    _, transport, _ = world
    assert _cli(["check", "--card", "http://agent.example", "--url", "http://issuer/v1"], transport=transport) == 1
    assert "https://" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        _cli(["check", "--card", "x.json", "--agent", "ab" * 32, "--url", "http://issuer/v1"], transport=transport)
