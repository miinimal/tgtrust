# Signed action log, anchored on Concordium

A trust card says who stands behind an agent. When something goes wrong, the next question is what the agent
actually did, and that answer is only worth something if the operator cannot rewrite it afterwards.
`tgtrust.actionlog` gives an agent a record of its own actions with three properties:

- **Signed by the agent key.** Every entry is signed with the same Ed25519 key as the agent's tgtrust credential
  and its Concordium CIS-8 binding, so the record belongs to that agent and, through the binding, to an
  identity-verified Concordium account. The person is not named.
- **Chained.** Every entry carries the hash of the entry before it. Removing, reordering, repeating or editing an
  entry breaks the chain at that entry, and the verifier says which one.
- **Anchored on Concordium.** The hash of the latest entry is registered on chain in a `RegisterData`
  transaction. The block time is set by the chain, so the entries existed no later than that block, and a later
  rewrite of the log no longer matches. The verifier checks the log against every anchor the account ever
  registered for that agent: a rewritten log can be anchored again, but the earlier anchor stays and disagrees.

Only the SHA-256 of each input and output goes into the log. The content stays with the operator, who can later
prove that a given request or answer is the one logged (`--find`), without publishing everything else.

This supports the kind of record keeping the EU AI Act asks of high-risk AI systems (Article 12: events logged
automatically over the system's lifetime, for traceability). It is a building block, not a compliance claim.

## Use

```bash
python -m tgtrust.actionlog append agent-log.jsonl --key-file agent.key --kind tool.call \
  --input "GET /paid?q=weather" --output "402 Payment Required"
python -m tgtrust.actionlog anchor-data agent-log.jsonl          # hex bytes to register on Concordium
cd examples/action_log && npm install && node anchor.mjs register <hex>   # RegisterData on testnet
python -m tgtrust.actionlog verify agent-log.jsonl --anchor-account <account that anchored>
```

`verify` checks every signature, the numbering, the time order and the chain, then reads the account's anchors
from Concordium (wallet proxy) and checks each one. Exit code 0 only when all of it holds. In code:

```python
from tgtrust.actionlog import ActionLog
log = ActionLog(agent)                       # agent: tgtrust.client.AgentIdentity
log.append("payment", request_bytes, settle_result_bytes)
```

## Format

One JSON object per line:

```json
{"v":1,"agent":"<hex32>","seq":0,"time":1794612000,"kind":"tool.call","input":"<sha256>","output":"<sha256>",
 "prev":"<hex32>","sig":"<base64url, 64 bytes>"}
```

Signed bytes: `"tgtrust/v1/action:" || agent(32) || seq(u64 BE) || time(u64 BE) || len(kind)(u8) || kind ||
input(32) || output(32) || prev(32)`. Entry hash: `sha256(signed bytes || sig)`. `prev` of entry 0 is 32 zero
bytes. Anchor data, 86 bytes: `"tgtrust-log/v1" || agent(32) || seq(u64 BE) || entry hash(32)`.

## Recorded run (Concordium testnet, 2026-11-13)

`examples/action_log/demo-log.jsonl` is three actions of the demo agent `dbc55639…ee26` (the same key that is bound
on testnet and mainnet): the 402 reply, the x402 payment on Concordium and the answer. Its head was anchored by the
agent's payment account `34vXzU…4S4P`:
https://ccdexplorer.io/testnet/transaction/3c4c112e733a110e0cce1b758fd717a4b21ca1efdb021f5268fd17d40a6feaf9

```text
$ python -m tgtrust.actionlog verify examples/action_log/demo-log.jsonl \
    --anchor-account 34vXzUxLshXWmn4U2wf33AZi1eWuxKi36J7CouJEMiuC4ohS4P
log: 3 entries by agent dbc55639…ee26, signatures and chain valid, head 29e75b43…9d2f
entries 0..2 match the Concordium anchor in transaction 3c4c112e…eaf9
all 1 anchors by 34vXzU…4S4P agree with the log [source: Concordium testnet]
```

Changing the kind of entry 2 from `answer` to `refusal` makes `verify` fail with
`entry 2 is not signed by the agent key`.

## Limits

- The log proves what the agent key signed, not that the agent's work was correct, and not that every action was
  logged: an operator can leave actions out before signing them. Anchoring often narrows that window; a counterparty
  that keeps the entry hash it was given can later show it is missing.
- Entries after the latest anchor can still be rewritten until the next anchor.
- Which account's anchors count is the verifier's choice. Use the agent's CIS-8004 payment wallet or the account its
  key is bound to, so an outsider cannot add confusing anchors.
- Reading anchors trusts Concordium's wallet proxy; `examples/action_log/anchor.mjs read <tx>` reads the same data
  straight from a node over gRPC.
