# Agent payment on Concordium: x402, priced by tgtrust

`pay.mjs` runs one paid call end to end on Concordium testnet:

1. The API reads the caller's tgtrust badge from the issuer. `verified` must prepay, `staked` would run on credit,
   anything else is refused (the trust gate's tiers, docs/TRUST_GATE.md).
2. It answers with x402 v2 `PaymentRequirements`, `exact` scheme on Concordium (`ccd:4221332d34e1694168c2a0c0b3fd0f27`),
   asset `CCD`, `extra.feePayer` = the facilitator's sponsor account.
3. The agent signs a V1 sponsored CCD transfer with its own account key (sender signature only).
4. The facilitator (`@x402/concordium`) verifies it, adds the sponsor signature, submits it and waits for
   finalization. The agent pays the price; the sponsor pays the network fee.

## Run

```bash
cd examples/concordium_x402
npm install
CCD_AGENT_ADDRESS=<agent account> CCD_AGENT_KEY=<agent signing key> \
CCD_SPONSOR_ADDRESS=<sponsor account> CCD_SPONSOR_KEY=<sponsor signing key> \
CCD_PAY_TO=<API's receiving account> TGTRUST_AGENT_KEY=<agent's tgtrust key> npm run pay
```

`CCD_ACCOUNTS_FILE` can point to a JSON file `{"agent": {"address", "signingKey"}, "sponsor": {...}}` instead of the
four key variables. `TGTRUST_ISSUER_URL` defaults to the demo issuer. Testnet accounts and CCD are free (faucet).

## Recorded run (2026-11-13)

The Telegram-verified demo agent `dbc55639…ee26` (also bound to an identity-verified Concordium mainnet account, see
`examples/concordium/README.md`) paid 0.5 CCD:

```text
tgtrust level verified: prepay 0.5 CCD on Concordium testnet
verify: {"isValid":true,"payer":"34vXzUxLshXWmn4U2wf33AZi1eWuxKi36J7CouJEMiuC4ohS4P"}
settle: {"success":true,"network":"ccd:4221332d34e1694168c2a0c0b3fd0f27","transaction":"5f476b836ec1cc6602e955e59187add24dec9ea0344516e623c80bad726dc2fe",...}
```

CCDExplorer shows a sponsored transfer of 0.5 CCD from the agent's account to the API's account, the fee paid by the
sponsor: https://ccdexplorer.io/testnet/transaction/5f476b836ec1cc6602e955e59187add24dec9ea0344516e623c80bad726dc2fe

## Limits

The paying account is a plain testnet account; linking it to the tgtrust agent key (for example through CIS-8 or
the agent's `agentWallet` on CIS-8004) is the next step, so the gate could require that the payer is the agent
it priced. Facilitator and API run in one process here; in production the API calls the facilitator's
`/verify` and `/settle`.
