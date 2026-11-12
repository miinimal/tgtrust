# Verify an agent in 60 seconds

You need Python 3.11+, git and a terminal. Steps 1 and 2 need the network (clone, `pip install`). Steps 3 to 5 run fully offline: no keys, no network writes, nothing on chain.

Everything you see below is **demo data from a local run**. It shows that the code does what it says. It is not a public deployment, there are no real users, and nothing here has had a security audit.

The test `tests/test_docs_verify.py` runs every block marked `# verify` in a copy of the repository and checks that the quoted output lines really appear, so this page cannot drift from the code. Lines containing `...` are elisions and are not checked; output blocks quote only stable lines (keys and timestamps that change on each run are left out).

## 1. Clone

```bash
git clone https://github.com/miinimal/tgtrust.git
cd tgtrust
```

Proves: you have the source that the next steps run. Does not prove: that this is the code anyone else runs; check the commit hash yourself.

## 2. Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev,server]'
```

Proves: the package installs from source on your machine. Does not prove anything about the agents. (`server` is needed for the two-agent demo in step 5, which starts a local web server.)

## 3. Print the demo agent card

```bash
# verify
python -c "
import json
from tgtrust.badge import card_text
r = lambda f: json.load(open('examples/card/' + f))
deal = r('deal.json')
desc = deal.pop('description')
print(card_text(r('badge-alice.json'), deal, counterparty_badge=r('badge-bob.json'), description=desc))"
```

Output (important lines):

```text
AGENT CARD f210a37d…2707
Badge level: verified [source: badge endpoint]
Stake: unknown, no TON stake source configured, nothing was read [source: TON stake read, not performed]
Deals: 1 confirmed deals, 0 with staked counterparties, 1 distinct counterparties [source: ledger]
Latest deal note: demo record, local ledger [source: example capture file]
Telegram check: issuer credential, one Telegram account per issuer epoch. Owner identity is not checked and not revealed. [source: badge endpoint]
```

Proves: the card is built from the saved badge and ledger records of a demo agent, and every line names its source. Does not prove: that the agent is real. The records come from a local demo run (`examples/card/`) with a stand-in for Telegram's signing key, a local ledger, and no TON stake was read, so the stake line says `unknown`. The Telegram check only means one credential per Telegram account per issuer epoch; the owner's identity is neither checked nor revealed, and a real Telegram signature has not yet been tested.

## 4. Export the ERC-8004 registration file

```bash
# verify
python -m tgtrust.erc8004 --badge examples/erc8004/badge-registered.json --profile examples/erc8004/profile.json
```

Output (important lines):

```text
"name": "tgtrust demo agent",
"registrations": [],
"level": "verified",
"one_account_per_issuer_epoch": true,
"evm_evidence": [],
"network": "testnet",
"found": false,
"type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
```

Proves: a tgtrust badge can be turned into an ERC-8004-shaped registration file by a plain offline command. Does not prove: that the agent is registered anywhere. `registrations` is empty and `evm_evidence` is empty, because the exporter never reads an EVM chain and refuses to list an EVM claim without transaction evidence. ERC-8004 is a Draft standard. The stake block shows testnet and `found: false`: this badge was saved from a run where no stake was found, and nothing is read from TON in this step.

## 5. Run the two-agent demo deal locally

```bash
# verify
python examples/two_agents.py
```

Output (important lines; keys, ids and times differ on every run):

```text
second agent for alice's account refused: already_issued
bob sees alice: verified
deal recorded:
verdict: upheld -> on-chain Slash fields:
```

Proves: on your machine, two agents register through a local issuer, a second agent for the same Telegram account is refused, bob checks alice's badge, a deal is recorded only because both parties signed it, and a dispute verdict produces the fields a slash would use. Does not prove: anything outside this process. The issuer and ledger live in memory and vanish when the script ends, Telegram's signing key is a stand-in, and the "on-chain Slash fields" are only printed: no transaction is built or sent, and no TON testnet or mainnet contract is touched.
## What this page does not cover

- No real Telegram init data was checked; that needs a live Mini App and is still pending.
- The stake contract exists on TON testnet only; this page never reads it.
- No EVM registration exists, and none is read from a chain.
- Mainnet is not planned before an external audit.
