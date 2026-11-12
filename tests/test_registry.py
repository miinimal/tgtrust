import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tgtrust import Holder, Issuer, MemoryIssuedStore
from tgtrust.registry import (
    CHALLENGE_TTL_SECONDS,
    Registry,
    RegistrationError,
    agent_token,
    bind_message,
)

from .conftest import BOT_ID, NOW


class Agent:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.salt = os.urandom(16)

    @property
    def token(self):
        return agent_token(self.public, self.salt)


@pytest.fixture
def env(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    return issuer, Registry(issuer.public_key, "kid0"), telegram


def credential_for(issuer, telegram, agent, user_id):
    holder = Holder(issuer.public_key)
    req = holder.prepare(agent.token)
    sig = issuer.issue(telegram.init_data({"id": user_id, "first_name": "U"}),
                       req.blinded_message, now=NOW)
    return holder.finalize(req, sig)


def register(registry, cred, agent, *, signer=None, now=NOW):
    ch = registry.new_challenge(now=now)
    sig = (signer or agent.key).sign(bind_message(ch, cred.token))
    return registry.register(cred, agent.public, agent.salt, ch, sig, now=now)


def test_register_and_badge(env):
    issuer, registry, telegram = env
    agent = Agent()
    record = register(registry, credential_for(issuer, telegram, agent, 1), agent)
    badge = registry.lookup(agent.public.hex()).badge()
    assert badge["unique_owner"] and badge["issuer_key_id"] == "kid0"
    assert record.agent_public_key == agent.public.hex()


def test_unknown_agent_has_no_badge(env):
    _, registry, _ = env
    assert registry.lookup(Agent().public.hex()) is None


def test_stolen_credential_useless_for_other_agent(env):
    issuer, registry, telegram = env
    owner, thief = Agent(), Agent()
    cred = credential_for(issuer, telegram, owner, 2)
    ch = registry.new_challenge(now=NOW)
    with pytest.raises(RegistrationError) as exc:
        registry.register(cred, thief.public, owner.salt, ch,
                          thief.key.sign(bind_message(ch, cred.token)), now=NOW)
    assert exc.value.code == "token_mismatch"


def test_agent_must_prove_key_possession(env):
    issuer, registry, telegram = env
    agent = Agent()
    cred = credential_for(issuer, telegram, agent, 3)
    with pytest.raises(RegistrationError) as exc:
        register(registry, cred, agent, signer=Ed25519PrivateKey.generate())
    assert exc.value.code == "invalid_agent_signature"


def test_credential_registers_only_once(env):
    issuer, registry, telegram = env
    agent = Agent()
    cred = credential_for(issuer, telegram, agent, 4)
    register(registry, cred, agent)
    with pytest.raises(RegistrationError) as exc:
        register(registry, cred, agent)
    assert exc.value.code == "already_registered"


def test_challenge_single_use_and_expiry(env):
    issuer, registry, telegram = env
    agent = Agent()
    cred = credential_for(issuer, telegram, agent, 5)
    ch = registry.new_challenge(now=NOW)
    sig = agent.key.sign(bind_message(ch, cred.token))
    with pytest.raises(RegistrationError) as exc:
        registry.register(cred, agent.public, agent.salt, ch, sig, now=NOW + CHALLENGE_TTL_SECONDS + 1)
    assert exc.value.code == "invalid_challenge"
    forged = os.urandom(32)
    with pytest.raises(RegistrationError):
        registry.register(cred, agent.public, agent.salt, forged,
                          agent.key.sign(bind_message(forged, cred.token)), now=NOW)


def test_forged_credential_rejected(env):
    from tgtrust import Credential
    _, registry, _ = env
    agent = Agent()
    fake = Credential(agent.token, os.urandom(256))
    with pytest.raises(RegistrationError) as exc:
        register(registry, fake, agent)
    assert exc.value.code == "invalid_credential"


def test_revocation_clears_badge(env):
    issuer, registry, telegram = env
    agent = Agent()
    register(registry, credential_for(issuer, telegram, agent, 6), agent)
    assert registry.revoke(agent.public.hex())
    assert registry.lookup(agent.public.hex()).badge()["unique_owner"] is False


def test_registry_never_stores_token_or_account(env, tmp_path):
    issuer, _, telegram = env
    path = str(tmp_path / "reg.db")
    registry = Registry(issuer.public_key, "kid0", path)
    agent = Agent()
    cred = credential_for(issuer, telegram, agent, 99887766)
    register(registry, cred, agent)
    data = open(path, "rb").read()
    assert cred.token not in data and b"99887766" not in data
