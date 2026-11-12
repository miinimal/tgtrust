import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from tgtrust import Holder, Issuer, MemoryIssuedStore
from tgtrust.registry import agent_token, bind_message
from tgtrust.service import b64url_decode, b64url_encode, create_app

from .conftest import BOT_ID


def test_full_agent_journey_over_http(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    client = TestClient(create_app(issuer=issuer, rate_limit_per_minute=100))

    agent_key = Ed25519PrivateKey.generate()
    agent_pub = agent_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    salt = os.urandom(16)

    assert client.get(f"/v1/agents/{agent_pub.hex()}").status_code == 404

    holder = Holder(issuer.public_key)
    req = holder.prepare(agent_token(agent_pub, salt))
    init_data = telegram.init_data({"id": 31337, "first_name": "Owner"}, auth_date=int(time.time()))
    resp = client.post("/v1/issue", json={
        "init_data": init_data, "blinded_message": b64url_encode(req.blinded_message)})
    assert resp.status_code == 200
    cred = holder.finalize(req, b64url_decode(resp.json()["blind_signature"]))

    challenge = b64url_decode(client.post("/v1/challenge").json()["challenge"])
    body = {
        "token": b64url_encode(cred.token),
        "signature": b64url_encode(cred.signature),
        "agent_public_key": b64url_encode(agent_pub),
        "salt": b64url_encode(salt),
        "challenge": b64url_encode(challenge),
        "agent_signature": b64url_encode(agent_key.sign(bind_message(challenge, cred.token))),
    }
    badge = client.post("/v1/register", json=body).json()
    assert badge["unique_owner"] is True

    assert client.get(f"/v1/agents/{agent_pub.hex()}").json()["unique_owner"] is True
    assert client.post("/v1/register", json=body).status_code == 403  # challenge already used
    assert client.get("/v1/agents/zz").status_code == 400
