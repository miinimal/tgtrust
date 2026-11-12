"""Two agents, full lifecycle, against a local issuer started in this process.

    python examples/two_agents.py

Uses a stand-in for Telegram's signing key (the issuer accepts init data signed by it), so no
Telegram account is needed to see the flow. Against a real issuer, `init_data` comes from the
issuer's Mini App and everything else is identical.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.conftest import BOT_ID, FakeTelegram
from tgtrust import Issuer, MemoryIssuedStore, blind_rsa
from tgtrust.badge import TELEGRAM_CHECK_LABEL, TELEGRAM_CHECK_SCOPE
from tgtrust.client import AgentIdentity, DealProposal, TgTrustClient, TgTrustError
from tgtrust.deals import DealLedger
from tgtrust.disputes import OUTCOME_UPHELD, DisputeBook, verdict_bytes
from tgtrust.registry import Registry
from tgtrust.service import b64url_encode, create_app, key_id

PORT = 8791
PAYOUT = "kQDyD0lLwVlP2exSkV4_SeyO9RgVG8ruIWQmZJubcP6k5FdI"


def start_issuer(telegram: FakeTelegram, arbiter_pub: bytes) -> TgTrustClient:
    issuer = Issuer(blind_rsa.generate_key(2048), BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    registry = Registry(issuer.public_key, key_id(issuer.public_key))
    deals = DealLedger(registry)
    app = create_app(issuer=issuer, registry=registry, deals=deals,
                     disputes=DisputeBook(deals, arbiter_pub), rate_limit_per_minute=1000)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    client = TgTrustClient(f"http://127.0.0.1:{PORT}/v1")
    for _ in range(50):
        try:
            client.issuer_info()
            return client
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("issuer did not start")


def main() -> None:
    telegram = FakeTelegram()
    arbiter = Ed25519PrivateKey.generate()
    arbiter_pub = arbiter.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    tg = start_issuer(telegram, arbiter_pub)

    # 1. two owners, two agents
    alice, bob = AgentIdentity.generate(), AgentIdentity.generate()
    for name, agent, user_id in (("alice", alice, 101), ("bob", bob, 202)):
        init_data = telegram.init_data({"id": user_id, "first_name": name}, auth_date=int(time.time()))
        cred, salt = tg.obtain_credential(agent, init_data)
        badge = tg.register(agent, cred, salt)
        check = "passed" if badge["unique_owner"] else "not passed"
        print(f"{name}: registered, {TELEGRAM_CHECK_LABEL} {check} ({TELEGRAM_CHECK_SCOPE}), key={agent.hex[:16]}…")

    # the same Telegram account cannot back a second agent
    try:
        tg.obtain_credential(AgentIdentity.generate(), telegram.init_data({"id": 101, "first_name": "x"}, auth_date=int(time.time())))
    except TgTrustError as exc:
        print(f"second agent for alice's account refused: {exc.code}")

    # 2. bob checks alice before dealing
    print("bob sees alice:", tg.badge(alice.hex)["level"])

    # 3. a deal: alice proposes, bob counter-signs (the proposal travels as JSON between the two bots)
    proposal = TgTrustClient.propose_deal(alice, bob.hex, amount_nanogram=2_000_000_000)
    wire = proposal.to_dict()
    bob_sig = DealProposal.from_dict(wire).counter_sign(bob)
    deal = tg.submit_deal(proposal, bob_sig)
    print("deal recorded:", deal["deal_id"][:16] + "…", "parties:", len(deal["parties"]))
    print("alice history:", tg.badge(alice.hex)["history"]["deals"])

    # 4. bob is unhappy: files a case, the arbiter upholds it
    case = tg.file_dispute(bob, bytes.fromhex(deal["deal_id"]), alice.hex, PAYOUT)
    print("case filed:", case["case_id"], case["status"])
    now = int(time.time())
    sig = arbiter.sign(verdict_bytes(case["case_id"], OUTCOME_UPHELD, 500_000_000, now))
    status, verdict = tg._send("POST", f"{tg.base_url}/disputes/{case['case_id']}/verdict", {
        "outcome": OUTCOME_UPHELD, "slash_amount_nanogram": 500_000_000, "decided_at": now, "arbiter_signature": b64url_encode(sig)})
    print("verdict:", verdict["status"], "-> on-chain Slash fields:", verdict["slash"])
    print("alice badge now:", tg.badge(alice.hex)["history"]["disputes"])


if __name__ == "__main__":
    main()
