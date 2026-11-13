# Submission: Concordium Trusted Agents (Encode)

Draft. Final submissions close on 2026-12-09. Every claim below points to code or a document in this repository;
the "Still open" list says what is not done yet.

## One line

tgtrust lets a paid agent API decide how far to trust an unknown AI agent, from evidence the agent cannot fake:
an identified Concordium account bound to the agent's key, a Telegram-checked credential, Gram at stake that an
arbiter can slash, and a signed deal and dispute record. The owner's identity is never revealed.

## The problem

An API that sells to agents has to decide on every request: does this caller pay first, or may it use the service
on credit? Today the answer is an allowlist or "always prepay". Reputation scores are cheap to farm; identity
checks expose the owner.

## What we built

| Piece | Where | State |
| --- | --- | --- |
| Concordium link: bind the agent's Ed25519 key to a Concordium account through CIS-8 (`tgtrust:v1`, `ed25519`, proof scheme `solana-ed25519`) | `tgtrust/concordium.py`, `python -m tgtrust.client concordium-bind`, docs/CONCORDIUM.md | canonical bytes match the registry's own tool on testnet and mainnet (`tests/golden/concordium`) |
| Check another agent from its A2A card (`/.well-known/agent-card.json`) or ERC-8004 file | `python -m tgtrust.client check --card <host or file>` | tested; a card is treated as a claim, a signed request proves the key |
| Check another agent with its Concordium binding and "Verified by Concordium" badge | `python -m tgtrust.client check --concordium testnet` | reads tested against the live testnet registry service |
| ERC-8004 / A2A agent card with the Concordium badge and the tgtrust extension | `python -m tgtrust.erc8004 --concordium-badge …`, docs/ERC8004_EXPORT.md | tested with recorded registry replies |
| Trust gate for paid agent APIs: signed requests, tiers by level, stake, disputes and Concordium badge; x402 v2 extension `tgtrust` | `tgtrust/gate.py`, docs/TRUST_GATE.md | tested |
| Paid API example: refused, prepay with x402 `402` (Base Sepolia token or native Gram on TON testnet), credit by stake | `examples/paid_api.py` | runs offline with demo badges |
| Agent payment on Concordium: a tgtrust-priced call settled with x402 `exact` on Concordium testnet; the agent signs a sponsored CCD transfer, the facilitator pays the fee | `examples/concordium_x402/` (`@x402/concordium`) | two recorded runs 2026-11-13, CCDExplorer `5f476b83…` (sponsored transfer, Success) |
| MCP server for any MCP client (`tgtrust_check_agent`, `tgtrust_concordium_link`) | `python -m tgtrust.mcp_server` | tested, read-only |
| OpenClaw / ClawHub skill | `skills/tgtrust/SKILL.md` | tested locally, not yet published |
| Telegram-checked credential (RFC 9474 blind signature), stake contract on TON testnet, deals, disputes | README "How it works" | done; a real Telegram-signed string verified 2026-11-12 (docs/REAL_TELEGRAM_CHECK.md) |

## How Concordium is used

Concordium answers the question tgtrust cannot answer alone: does an identified person control this agent?
A Concordium account is opened only with an identity from an identity provider, so a CIS-8 binding from that
account to the agent key says "an identified person stands behind this key" without saying who.

The trust gate counts that evidence only when it is real: the CIS-8 binding is Active, and the CIS-8004 agent of
the same account carries this exact key as its external reference and passes the registry's badge check (owner,
active status, card hash). Then the caller reaches the highest tier, for example a larger credit limit. Anything
less (no binding, a revoked binding, a failed read) is listed in the decision's evidence and not counted.

## Try it

```bash
git clone https://github.com/miinimal/tgtrust && cd tgtrust
pip install -e '.[dev,server]'
pytest -q
python examples/paid_api.py
python examples/two_agents.py
```

Then docs/VERIFY_IN_60_SECONDS.md and docs/CONCORDIUM.md.

## Path to production

1. Public issuer on testnet with the Telegram Mini App (runbook in `deploy/`).
2. First real CIS-8 binding and CIS-8004 agent on Concordium testnet, card hosted at its `agent_uri`.
3. Skill on ClawHub and the MCP server listed, so agents can check each other where they already run.
4. External audit of the stake contract and an arbiter multisig before any mainnet stake (README "Security
   notes").
5. Issuer path B: a zero-knowledge proof of Telegram's signature instead of a trusted issuer.

## Limits we state openly

- The Telegram check means one Telegram account per issuer epoch, not a checked person; Concordium adds the
  identified person.
- The issuer is a single trusted party in this phase.
- The stake is on TON testnet.
- Co-signed deals prove that a deal record exists, not that the work was done well.

## Still open before 2026-12-09

- [x] A tgtrust key bound on Concordium testnet and its CIS-8004 agent registered (token id 1181,
  examples/concordium/README.md).
- [x] The same key bound on Concordium mainnet to an identity-verified account, agent 5136 with a valid badge
  (examples/concordium/README.md).
- [x] Public issuer URL in the skill and in this file: demo issuer `https://minimal.tailee59dc.ts.net/v1`
  (testnet, test policy, single machine, may be offline). Bot and Mini App: https://t.me/tgtrust_agents_bot
  (`/card <key>`, "Get credential").
- [x] The Concordium-bound demo agent `dbc55639…ee26` holds a Telegram credential: `check --concordium mainnet`
  shows level `verified`, the CIS-8 binding and a valid badge, and exits 0.
- [x] Demo video recorded (62 s, real outputs; attached to the release when the entry is submitted).
- [ ] Fill the submission form (the Encode page asks for a description, the repository, a video of up to
  3 minutes, a CCDExplorer link and the path to production; no separate AI disclosure rule found on that page,
  the description states AI tool use anyway).
