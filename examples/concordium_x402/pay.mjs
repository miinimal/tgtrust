// End-to-end x402 payment on Concordium testnet, priced by tgtrust:
// the API reads the caller's tgtrust badge, a "verified" agent must prepay, the agent signs a CCD transfer,
// the facilitator sponsors the fee, settles it and waits for finalization.
import { readFileSync } from "node:fs";
import { AccountAddress, buildBasicAccountSigner } from "@concordium/web-sdk";
import {
  CCD_ASSET_IDENTIFIER, CONCORDIUM_TESTNET_CAIP2, getExplorerTxUrl, toConcordiumFacilitatorSigner,
} from "@x402/concordium";
import { ExactConcordiumScheme as Client } from "@x402/concordium/exact/client";
import { ExactConcordiumScheme as Facilitator } from "@x402/concordium/exact/facilitator";

const env = (name, fallback) => process.env[name] ?? fallback ?? (() => { throw new Error(`set ${name}`); })();
const accounts = process.env.CCD_ACCOUNTS_FILE ? JSON.parse(readFileSync(process.env.CCD_ACCOUNTS_FILE, "utf8")) : {};
const agent = { address: env("CCD_AGENT_ADDRESS", accounts.agent?.address), key: env("CCD_AGENT_KEY", accounts.agent?.signingKey) };
const sponsor = { address: env("CCD_SPONSOR_ADDRESS", accounts.sponsor?.address), key: env("CCD_SPONSOR_KEY", accounts.sponsor?.signingKey) };
const payTo = env("CCD_PAY_TO");
const issuer = env("TGTRUST_ISSUER_URL", "https://minimal.tailee59dc.ts.net/v1");
const agentKey = env("TGTRUST_AGENT_KEY");
const grpc = { host: "grpc.testnet.concordium.com", port: 20000, useTls: true, network: CONCORDIUM_TESTNET_CAIP2 };

// 1. The API reads the caller's evidence and decides the tier (tgtrust badge levels).
const badge = await (await fetch(`${issuer}/agents/${agentKey}/badge`)).json();
const PRICE = { verified: "500000", staked: null };  // microCCD; staked agents run on credit in the trust gate
if (!(badge.level in PRICE)) { console.log(`tgtrust level ${badge.level}: refused`); process.exit(1); }
if (PRICE[badge.level] === null) { console.log("tgtrust level staked: served on credit"); process.exit(0); }
console.log(`tgtrust level ${badge.level}: prepay ${Number(PRICE[badge.level]) / 1e6} CCD on Concordium testnet`);

// 2. 402: x402 v2 PaymentRequirements, exact scheme on Concordium, fee sponsored by the facilitator.
const facilitator = new Facilitator({ signer: toConcordiumFacilitatorSigner(sponsor.address, sponsor.key, grpc) });
const requirements = {
  scheme: "exact", network: CONCORDIUM_TESTNET_CAIP2, amount: PRICE[badge.level], asset: CCD_ASSET_IDENTIFIER,
  payTo, maxTimeoutSeconds: 60, extra: { ...facilitator.getExtra(CONCORDIUM_TESTNET_CAIP2) },
};
console.log("402 accepts:", JSON.stringify(requirements));

// 3. The agent signs a sponsored V1 transfer (sender signature only).
const client = new Client({ accountAddress: AccountAddress.fromBase58(agent.address), signer: buildBasicAccountSigner(agent.key) },
  { grpcUrl: `${grpc.host}:${grpc.port}`, useTls: true });
const result = await client.createPaymentPayload(2, requirements);
const paymentPayload = { x402Version: 2, resource: { url: "https://api.example/paid", description: "paid call", mimeType: "application/json" },
  accepted: requirements, payload: result.payload };

// 4. The facilitator verifies (9 rules), adds the sponsor signature, submits and waits for finalization.
const verified = await facilitator.verify(paymentPayload, requirements);
console.log("verify:", JSON.stringify(verified));
if (!verified.isValid) process.exit(1);
const settled = await facilitator.settle(paymentPayload, requirements);
console.log("settle:", JSON.stringify(settled));
if (settled.success) console.log("explorer:", getExplorerTxUrl(CONCORDIUM_TESTNET_CAIP2, settled.transaction));
