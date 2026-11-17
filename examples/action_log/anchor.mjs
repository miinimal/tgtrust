// Anchor a tgtrust action log head on Concordium (RegisterData), or read an anchor back.
//   node anchor.mjs register <hex data>   -> submits, waits for finalization, prints tx hash, block, block time
//   node anchor.mjs read <tx hash>        -> prints the registered data and the block time of that transaction
import { readFileSync } from "node:fs";
import { credentials } from "@grpc/grpc-js";
import {
  AccountAddress, AccountTransactionType, DataBlob, TransactionExpiry, TransactionHash,
  buildBasicAccountSigner, signTransaction,
} from "@concordium/web-sdk";
import { ConcordiumGRPCNodeClient } from "@concordium/web-sdk/nodejs";

const [cmd, arg] = process.argv.slice(2);
const host = process.env.CCD_GRPC_HOST ?? "grpc.testnet.concordium.com";
const client = new ConcordiumGRPCNodeClient(host, 20000, credentials.createSsl());

async function read(hash) {
  const status = await client.waitForTransactionFinalization(TransactionHash.fromHexString(hash));
  const summary = status.summary;
  if (summary.type !== "accountTransaction" || summary.transactionType !== "registerData") {
    throw new Error(`transaction ${hash} is not a RegisterData transaction`);
  }
  const raw = summary.dataRegistered.data;  // the SDK gives the registered bytes as a hex string
  const data = typeof raw === "string" ? raw.toLowerCase() : Buffer.from(raw).toString("hex");
  const block = await client.getBlockInfo(status.blockHash);
  return { tx: hash, sender: summary.sender.address, block: status.blockHash.toString(),
           blockTime: Math.floor(block.blockSlotTime.getTime() / 1000), data };
}

if (cmd === "register") {
  const file = process.env.CCD_ACCOUNTS_FILE ? JSON.parse(readFileSync(process.env.CCD_ACCOUNTS_FILE, "utf8")) : {};
  const role = process.env.CCD_ACCOUNT_ROLE ?? "agent";
  const address = process.env.CCD_ADDRESS ?? file[role]?.address;
  const key = process.env.CCD_KEY ?? file[role]?.signingKey;
  if (!address || !key || !/^[0-9a-f]+$/.test(arg ?? "")) throw new Error("set CCD_ACCOUNTS_FILE or CCD_ADDRESS/CCD_KEY, and pass the hex data");
  const sender = AccountAddress.fromBase58(address);
  const nonce = (await client.getNextAccountNonce(sender)).nonce;
  const tx = {
    type: AccountTransactionType.RegisterData,
    header: { expiry: TransactionExpiry.futureMinutes(10), nonce, sender },
    payload: { data: new DataBlob(Buffer.from(arg, "hex")) },
  };
  const hash = await client.sendAccountTransaction(tx, await signTransaction(tx, buildBasicAccountSigner(key)));
  console.log(JSON.stringify(await read(TransactionHash.toHexString(hash))));
} else if (cmd === "read") {
  console.log(JSON.stringify(await read(arg)));
} else {
  console.log("usage: node anchor.mjs register <hex> | read <tx hash>");
  process.exit(2);
}
