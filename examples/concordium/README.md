# tgtrust demo agent on Concordium

A real CIS-8 binding and CIS-8004 agent for one tgtrust agent key, made on 2026-11-13 on testnet and on mainnet.

## Testnet

| What | Value |
| --- | --- |
| tgtrust agent key (`tgtrust:v1`, `ed25519`) | `dbc55639df6bfeef7366bd3c0436d0b75842ff63c3701625d818cbb7022aee26` |
| Concordium account | `4Mk8CZ3QSgRmvRVfnurx8a1WcLgwyS9dfkJU63eAPJf5JQMDsu` |
| CIS-8 binding (contract 12801,0) | transaction `3e5b26267793bf795eaecf2a739ee6cd32492b917592a70bb9a849390d130236` |
| CIS-8004 agent (contract 12802,0) | token id 1181, badge `JyP9WrFnp62SuD2Gdquuv`, transaction `bf5838092f6c01b8be86db299ff14de517cdb88ecea07b9097fcf16bbd9f3841` |
| Agent card | `agent-card.json` in this folder, SHA-256 `7532fe333cc8974f88afb89711ed20874bc730228e19ab378b816a8063061c00`, pinned on chain by `setAgentURI` transaction `69394d61a4d18eb6c70613863b920bbc7d28897a01f6af258ab24ba959d6b69b` |

## Mainnet

The same agent key is also bound on Concordium **mainnet** to the owner's identity-verified account (real identity
provider check), 2026-11-13.

| What | Value |
| --- | --- |
| Concordium mainnet account | `44y1gKpe8BztZNtcij8DZoxpe4dG756Y9Vj39wx5YitDen2vwG` |
| CIS-8 binding (contract 10081,0) | transaction `523ef4f1d395defda0e931f92bb5e6406a6bd5e3c984495f0daefd17eae7940c` |
| CIS-8004 agent (contract 10082,0) | token id 5136, badge `Mf22ooPJoTuWLJPahtmvD`, transaction `51d76f2d50be990d3d7c3bd3d20f8257918aa2430af8e8a96ef98b7a343779c6` |
| Agent card | `agent-card-mainnet.json`, SHA-256 `9fe2f7ed153cacf1980e125ec64ef0c9020aa24ac8fe77b262b1772d2742aef2`, pinned by `setAgentURI` transaction `2be0d75edc32e8980010374299c8122dc84c26ad938c24c4a13445b3485cc5ac` |

tgtrust's own stake contract and issuer stay on testnets; only the Concordium link is on mainnet.

## How it was made

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
