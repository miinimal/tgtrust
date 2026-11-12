// Test bridge: runs tgtrust/webapp/blindrsa.js under Node and answers one JSON command per line.
// Used by tests/test_webapp_crypto.py to compare the browser code with the Python implementation.
import { createInterface } from "node:readline";
import * as lib from "../../tgtrust/webapp/blindrsa.js";

const hex = lib.toHex;
const bytes = lib.fromHex;

async function run(cmd) {
  switch (cmd.op) {
    case "emsa":
      return { em: hex(await lib.emsaPssEncode(bytes(cmd.message), cmd.bits)) };
    case "key": {
      const key = lib.parsePublicKey(cmd.pem);
      return { n: key.n.toString(16), e: key.e.toString(16), bits: key.bits, k: key.k, key_id: await lib.keyId(key) };
    }
    case "blind": {
      const key = lib.parsePublicKey(cmd.pem);
      const options = cmd.r ? { r: BigInt("0x" + cmd.r) } : {};
      const out = await lib.blind(key, bytes(cmd.message), options);
      return { blinded: hex(out.blindedMessage), inverse: out.inverse.toString(16) };
    }
    case "finalize": {
      const key = lib.parsePublicKey(cmd.pem);
      const sig = await lib.finalize(key, bytes(cmd.message), bytes(cmd.blind_signature), BigInt("0x" + cmd.inverse));
      return { signature: hex(sig) };
    }
    case "verify": {
      const key = lib.parsePublicKey(cmd.pem);
      return { valid: await lib.verify(key, bytes(cmd.message), bytes(cmd.signature)) };
    }
    case "token":
      return { token: hex(await lib.agentToken(bytes(cmd.agent), bytes(cmd.salt))) };
    case "messages":
      return {
        credential: hex(lib.credentialMessage(bytes(cmd.token))),
        bind: hex(lib.bindMessage(bytes(cmd.challenge), bytes(cmd.token))),
      };
    case "b64":
      return { encoded: lib.b64urlEncode(bytes(cmd.data)), decoded: hex(lib.b64urlDecode(cmd.text)) };
    case "math":
      return {
        pow: lib.modPow(BigInt(cmd.b), BigInt(cmd.e), BigInt(cmd.m)).toString(),
        inv: lib.modInverse(BigInt(cmd.b), BigInt(cmd.m)).toString(),
      };
    default:
      throw new Error("unknown op");
  }
}

for await (const line of createInterface({ input: process.stdin })) {
  if (!line.trim()) continue;
  let answer;
  try {
    answer = { ok: true, ...(await run(JSON.parse(line))) };
  } catch (err) {
    answer = { ok: false, error: err.constructor.name, message: String(err.message) };
  }
  process.stdout.write(JSON.stringify(answer) + "\n");
}
