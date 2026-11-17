# Anchor an agent's action log on Concordium

`anchor.mjs` writes the head of a tgtrust action log to Concordium testnet as a `RegisterData` transaction and
reads it back from a node. The log format, the checks and a recorded run are in `docs/ACTION_LOG.md`.

```bash
npm install
CCD_ADDRESS=<account> CCD_KEY=<its signing key> node anchor.mjs register "$(python -m tgtrust.actionlog anchor-data log.jsonl)"
node anchor.mjs read <transaction hash>
```

`CCD_ACCOUNTS_FILE` (the same JSON as in `examples/concordium_x402`) can replace the two key variables; the `agent`
entry is used unless `CCD_ACCOUNT_ROLE` says otherwise. A `RegisterData` transaction costs a network fee only.

`demo-log.jsonl` is the demo agent's log anchored in transaction
`3c4c112e733a110e0cce1b758fd717a4b21ca1efdb021f5268fd17d40a6feaf9` on testnet.
