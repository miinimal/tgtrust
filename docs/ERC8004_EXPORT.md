# ERC-8004 export (task D6.4)

`tgtrust.erc8004` turns a trust badge into an ERC-8004 **agent registration file**, so a tgtrust agent can be
listed by EVM identity registries that implement ERC-8004 «Trustless Agents».

Spec: https://eips.ethereum.org/EIPS/eip-8004 — status **Draft**, created 2025-08-13, read in full on 2026-11-11.
The spec has no "last updated" date; re-read it before relying on a field.

## Run it

```
pip install -e '.[dev]'
python -m tgtrust.erc8004 --badge examples/erc8004/badge-registered.json --profile examples/erc8004/profile.json
```

Expected output: exactly `examples/erc8004/expected-registration.json` (the test
`test_sample_reproduces_expected_file` checks this byte for byte). Errors exit with code 2 and print
`error <code>: <message>`.

Options: `--evm evm.json` (list of EVM registrations with evidence), `--badge-url URL` (adds the public badge
endpoint as a service), `-o file`.

## Where the sample input comes from

`python examples/erc8004_capture.py` starts the normal service (`create_app`) with the stake reader on the real
StakeRegistry on TON testnet (`contracts/deployments/testnet.json`), registers one fresh agent through the
normal client flow and saves the response of `GET /v1/agents/{key}/badge`:

- `badge-registered.json` — the fresh agent. Its registry record comes from this local run (stand-in Telegram
  key, as in `examples/two_agents.py`; no public tgtrust deployment exists yet). Its stake was read live from
  testnet: none (`found: false`).
- `badge-demo-staked-unregistered.json` — the demo agent `738559c1…28d8`, which holds a real 0.4 GRAM stake
  on testnet but has no record in this registry. The export refuses it (`not_registered`): a stake alone does
  not prove that one person stands behind the agent.

Captured 2026-11-11 (badge `checked_at` 1794437072).

## Field sources

| Registration field | Source | Rule |
|---|---|---|
| `type` | constant | `https://eips.ethereum.org/EIPS/eip-8004#registration-v1` |
| `name`, `description`, `image` | operator profile | required, non-empty (spec: mandatory, ERC-721 compatible) |
| `services` | operator profile (+ `--badge-url`) | each needs `name` and `endpoint`; `version` optional |
| `x402Support` | operator profile | boolean, default `false` |
| `active` | badge `level` | `false` only for `revoked` |
| `registrations` | — | always `[]` until a real chain read exists. EVM entries from `--evm` (`chainId`, `identityRegistry`, `agentId`, `txHash`) are claims and go only to `tgtrust.evm_evidence` |
| `supportedTrust` | badge `level` | `["crypto-economic"]` only when the badge says `staked` (live, checked, not withdrawing); otherwise empty |
| `tgtrust` (extension, not part of ERC-8004) | badge | agent key, level, `one_account_per_issuer_epoch`, issuer key id, registration time, stake view (network, contract, amount, checked time), badge time, EVM evidence, spec status |

Meaning of `one_account_per_issuer_epoch` (the Telegram check, `tgtrust.badge.TELEGRAM_CHECK_SCOPE`): issuer credential, one Telegram account per issuer epoch.
It does not prove one distinct human or who the operator is (one person can hold
several Telegram accounts), and tests use a stand-in for Telegram's key. Profile texts should say exactly that.

### Legacy field name `unique_owner`

The badge JSON and the registry record keep the key `unique_owner`. It is part of the stored and served format,
and saved example files depend on it, so it is not renamed. Its exact meaning is the Telegram check above, and
nothing more: `true` when the agent has a registry record that is not revoked, `false` otherwise. It is not one human
and not a known operator. The export does not carry this key; it writes `one_account_per_issuer_epoch` instead.

Every `evm_evidence[]` entry has `status: "claimed_not_read_from_chain"` and `verifiedOnChain: false`: the
transaction hash is supplied by the operator and this tool does not read the EVM chain, so such an entry never
appears in `registrations`. The CLI prints a warning to stderr when any is present (stdout stays pure JSON). Proof of registration is a chain read (`ownerOf(agentId)`, `tokenURI(agentId)`
resolving to this file) — not implemented yet.

No reputation entries and no `ownerVerified` tag are produced: in ERC-8004 that tag means endpoint ownership,
and feedback must be submitted by the client itself (independent review R-1111-01, 2026-11-11).

Never exported: the owner's Telegram identity (the registry never has it) and the stake owner wallet (the
badge does not carry it).

## What is not covered

- **No EVM registration exists yet.** The sample has `registrations: []`. Minting an agent id on an EVM
  identity registry is a network write and needs its own decision.
- **Reputation feedback is not exported.** ERC-8004 feedback needs `clientAddress` as an EVM account
  (`eip155:{chainId}:{address}`) and is submitted by the client, not by the agent (`giveFeedback` refuses the
  owner). tgtrust deals are signed by Ed25519 agent keys, so there is no EVM client address to put there.
- **No hosting of the file.** ERC-8004 points to the file by URI; publishing it (and the optional
  `/.well-known/agent-registration.json` domain check) waits for a public deployment (block 8).
- The `tgtrust` extension field is extra data. ERC-8004 does not define it; readers that ignore unknown fields
  lose nothing else.
