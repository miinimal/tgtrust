"""Capture the sample input for the ERC-8004 export from the normal entry point.

    python examples/erc8004_capture.py

Starts the issuer service in this process with the stake reader pointed at the real StakeRegistry on
TON testnet (contracts/deployments/testnet.json), registers one fresh agent through the normal client
flow, and saves what `GET /v1/agents/{key}/badge` returns for:

- the fresh agent (registry record from this run; its stake is read live from testnet);
- the demo agent 738559c1…28d8 that holds a real testnet stake but has no record in this registry.

Like examples/two_agents.py, it uses a stand-in for Telegram's signing key, so the registry record is a
local demo record, not one from a public deployment (none exists yet — block 8 waits for a hostname).
Network reads only; nothing is written on chain.
"""

from __future__ import annotations

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
from tgtrust.client import AgentIdentity, TgTrustClient
from tgtrust.registry import Registry
from tgtrust.service import create_app, key_id
from tgtrust.stake import StakeReader

PORT = 8792
DEMO_STAKED_AGENT = "738559c16db0b6b80b73de6094744bd9e802fb7df4657b3f41fdd3c7238228d8"
OUT = ROOT / "examples" / "erc8004"


def main() -> None:
    deployment = json.loads((ROOT / "contracts" / "deployments" / "testnet.json").read_text())
    telegram = FakeTelegram()
    issuer = Issuer(blind_rsa.generate_key(2048), BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    registry = Registry(issuer.public_key, key_id(issuer.public_key))
    stake_reader = StakeReader(deployment["address"], deployment["network"])
    app = create_app(issuer=issuer, registry=registry, stake_reader=stake_reader, rate_limit_per_minute=1000)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    client = TgTrustClient(f"http://127.0.0.1:{PORT}/v1")
    for _ in range(50):
        try:
            client.issuer_info()
            break
        except Exception:
            time.sleep(0.1)

    agent = AgentIdentity.generate()
    init_data = telegram.init_data({"id": 303, "first_name": "operator"}, auth_date=int(time.time()))
    cred, salt = client.obtain_credential(agent, init_data)
    client.register(agent, cred, salt)

    OUT.mkdir(parents=True, exist_ok=True)
    for name, key in (("badge-registered.json", agent.hex), ("badge-demo-staked-unregistered.json", DEMO_STAKED_AGENT)):
        badge = client.badge(key)
        (OUT / name).write_text(json.dumps(badge, indent=2, sort_keys=True) + "\n")
        print(f"{name}: level={badge['level']} stake={badge['stake']}")


if __name__ == "__main__":
    main()
