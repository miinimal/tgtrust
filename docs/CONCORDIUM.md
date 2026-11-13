# Concordium Agent Registry link

Concordium's Agent Registry (read 2026-11-13: docs.concordium.com, Technical reference > Agent Registry) gives an
agent an on-chain entry (CIS-8004, a CIS-2 token whose address is the "Verified by Concordium" badge) and records
proven bindings between a Concordium account and an external key (CIS-8). Concordium accounts are opened only with
an identity from an identity provider, so an account stands for an identified person without disclosing who.

tgtrust and Concordium answer different questions about the same agent:

| Question | Answered by |
| --- | --- |
| Does an identified person control this agent? | Concordium: CIS-8 binding of the agent key to an account |
| Is this one Telegram account per issuer epoch? | tgtrust credential |
| What does the agent lose if it cheats? | tgtrust: TON stake, slashed by arbiter verdict |
| What has it done before? | tgtrust: co-signed deals, dispute record |

## How the link works

tgtrust agent keys are Ed25519. CIS-8 accepts them as key type `ed25519` with proof scheme `solana-ed25519` (the
key signs the canonical bytes directly). tgtrust uses the namespace `tgtrust:v1`.

The canonical bytes are built locally (`tgtrust/concordium.py`) and are tested byte for byte against the
registry's own `build_cis8_canonical_bytes` tool on testnet and mainnet (`tests/golden/concordium`).

### Bind your agent key (owner, once)

You need a Concordium account (Concordium Wallet with an identity; on testnet the identity and the CCD for fees
are free).

```bash
python -m tgtrust.client concordium-bind --key-file agent.key --account <your Concordium account> --network testnet
```

This prints the arguments for the registry tool `build_cis8_register`, already signed by the agent key. Pass them
to the registry (MCP service `https://agent-registry-mcp.concordium.com/mcp`, or the Agent Registry DApp), then sign
and submit the returned transaction from your Concordium account. tgtrust never sees a Concordium key and sends
nothing itself.

### Check another agent

```bash
python -m tgtrust.client check --agent <their key> --url <issuer>/v1 --concordium testnet
```

Adds to the trust card, each line with its source:

- `Concordium: key bound to account …` (the binding is active), or `not bound`, or `unknown, the read failed`;
- `Concordium badge: <token address>, valid` when the bound account's CIS-8004 agent carries this key as its
  external reference and the registry's badge check passes (owner, active status, card hash).

The exit code still reflects the tgtrust level only; the Concordium lines are additional evidence.

The other agent's card can stand in for its key: `check --card https://their-host` reads
`/.well-known/agent-card.json` (A2A), or pass a card URL or file. The key is taken from the tgtrust A2A extension
below and from the ERC-8004 file's `tgtrust.agent_key`; a card that names none, a malformed one or two different
keys is refused. A card is only a claim by its host; a signed request (docs/TRUST_GATE.md) proves the key.

### One card for ERC-8004, A2A and Concordium

Once your agent is registered in CIS-8004 with this key as its CIS-8 external reference, export the card:

```bash
python -m tgtrust.erc8004 --badge badge.json --profile profile.json \
  --concordium-badge <badge token address> --concordium-network testnet -o agent-card.json
```

The export reads the badge from the chain (`get_badge_json`, `owner_of_key`) and accepts it only if the agent is
Active, its external reference is exactly this tgtrust key (`tgtrust:v1`, `ed25519`), and the key's binding is
Active and owned by the same account. Then the card gets:

- `registrations`: the CIS-8004 entry (`agentId`, `agentRegistry` as CAIP-10), a real chain read;
- `capabilities.extensions`: the Concordium badge extension and the tgtrust extension below.

Host the file at the agent's `agent_uri` and set its SHA-256 on chain (`build_set_agent_uri`), as Concordium's badge
check compares the served bytes with `metadata_hash`.

## A2A extension v1

URI `https://github.com/miinimal/tgtrust/blob/main/docs/CONCORDIUM.md#a2a-extension-v1`, `required: false`.

| Param | Meaning |
| --- | --- |
| `agentKey` | the tgtrust agent key, 64 hex characters (the same key as the CIS-8 binding) |
| `level` | tgtrust badge level when the card was made: `unknown`, `revoked`, `verified`, `staked` |
| `badgeUrl` | optional; the live tgtrust badge endpoint. Read it for current values, the card is a snapshot |

## Status (2026-11-13)

- Canonical bytes: match the registry on testnet and mainnet.
- Reads (`owner_of_key`, `agent_by_external_reference`, badge check): work against the live testnet service.
- Card export with a verified badge: tested with recorded registry replies.
- A tgtrust key is bound on testnet and its CIS-8004 agent is registered (token id 1181, badge
  `JyP9WrFnp62SuD2Gdquuv`), 2026-11-13: examples/concordium/README.md has the transactions and the card.
