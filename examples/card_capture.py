"""Capture one two-signature demo deal and the badges of both parties (local registry and ledger only).

    python examples/card_capture.py

Same client flow as examples/two_agents.py: two agents register through the issuer (stand-in for
Telegram's signing key), alice proposes a deal, bob verifies and counter-signs, the ledger checks both
signatures and records it. Nothing leaves 127.0.0.1 and nothing is written on chain.

Output in examples/card/: badge-alice.json, badge-bob.json, deal.json, card.txt, README.md. All of it is
a demo record, local ledger. The ledger keeps only memo_hash; deal.json carries the description whose
SHA-256 is that hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn

from tests.conftest import BOT_ID, FakeTelegram
from tgtrust import Issuer, MemoryIssuedStore, blind_rsa
from tgtrust.badge import card_text
from tgtrust.client import AgentIdentity, DealProposal, TgTrustClient
from tgtrust.deals import DealLedger
from tgtrust.registry import Registry
from tgtrust.service import create_app, key_id

PORT = 8793
OUT = ROOT / "examples" / "card"
NOTE = "demo record, local ledger"
DESCRIPTION = "Demo task: alice summarises a 3-page text for bob (demo data, no real work)"


def dump(name: str, data: dict) -> None:
    (OUT / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def main() -> None:
    telegram = FakeTelegram()
    issuer = Issuer(blind_rsa.generate_key(2048), BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    registry = Registry(issuer.public_key, key_id(issuer.public_key))
    app = create_app(issuer=issuer, registry=registry, deals=DealLedger(registry), rate_limit_per_minute=1000)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    tg = TgTrustClient(f"http://127.0.0.1:{PORT}/v1")
    for _ in range(50):
        try:
            tg.issuer_info()
            break
        except Exception:
            time.sleep(0.1)

    alice, bob = AgentIdentity.generate(), AgentIdentity.generate()
    for name, agent, user_id in (("alice", alice, 101), ("bob", bob, 202)):
        init_data = telegram.init_data({"id": user_id, "first_name": name}, auth_date=int(time.time()))
        cred, salt = tg.obtain_credential(agent, init_data)
        tg.register(agent, cred, salt)

    memo = hashlib.sha256(DESCRIPTION.encode()).digest()
    proposal = TgTrustClient.propose_deal(alice, bob.hex, amount_nanogram=0, memo_hash=memo)
    bob_sig = DealProposal.from_dict(proposal.to_dict()).counter_sign(bob)
    tg.submit_deal(proposal, bob_sig)

    OUT.mkdir(parents=True, exist_ok=True)
    badge_alice, badge_bob = tg.badge(alice.hex), tg.badge(bob.hex)
    dump("badge-alice.json", badge_alice)
    dump("badge-bob.json", badge_bob)
    deal = tg.deals(alice.hex, limit=1)["deals"][0]
    dump("deal.json", {**deal, "description": DESCRIPTION, "note": NOTE})
    card = card_text(badge_alice, {**deal, "note": NOTE}, counterparty_badge=badge_bob, description=DESCRIPTION)
    (OUT / "card.txt").write_text(card + "\n")
    (OUT / "README.md").write_text(
        f"# {NOTE.capitalize()}\n\nEverything in this folder is a {NOTE}: two demo agents, a stand-in for "
        "Telegram's signing key, an in-process issuer and ledger. Not a public deployment, no network writes, "
        "nothing on chain. Regenerate with `python examples/card_capture.py`.\n")
    print(card)


if __name__ == "__main__":
    main()
