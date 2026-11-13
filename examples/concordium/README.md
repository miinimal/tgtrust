# tgtrust demo agent on Concordium testnet

A real CIS-8 binding and CIS-8004 agent, made on 2026-11-13 with the owner's Concordium testnet account.

| What | Value |
| --- | --- |
| tgtrust agent key (`tgtrust:v1`, `ed25519`) | `dbc55639df6bfeef7366bd3c0436d0b75842ff63c3701625d818cbb7022aee26` |
| Concordium account | `4Mk8CZ3QSgRmvRVfnurx8a1WcLgwyS9dfkJU63eAPJf5JQMDsu` |
| CIS-8 binding (contract 12801,0) | transaction `3e5b26267793bf795eaecf2a739ee6cd32492b917592a70bb9a849390d130236` |
| CIS-8004 agent (contract 12802,0) | token id 1181, badge `JyP9WrFnp62SuD2Gdquuv`, transaction `bf5838092f6c01b8be86db299ff14de517cdb88ecea07b9097fcf16bbd9f3841` |
| Agent card | `agent-card.json` in this folder, SHA-256 `7532fe333cc8974f88afb89711ed20874bc730228e19ab378b816a8063061c00`, pinned on chain by `setAgentURI` transaction `69394d61a4d18eb6c70613863b920bbc7d28897a01f6af258ab24ba959d6b69b` |

The binding was built with `python -m tgtrust.client concordium-bind` and submitted from the Concordium Wallet for
Web; tgtrust never held a Concordium key. The card was composed by the registry's `build_agent_card` with the
token id, plus the tgtrust A2A extension.

Check it yourself:

```bash
python -m tgtrust.client check --agent dbc55639df6bfeef7366bd3c0436d0b75842ff63c3701625d818cbb7022aee26 \
  --url https://minimal.tailee59dc.ts.net/v1 --concordium testnet
```

The `Concordium:` line reads the binding from the chain. The agent has no tgtrust credential or stake yet, so its
tgtrust level is `unknown` and the command exits 2; the Concordium lines are additional evidence.
