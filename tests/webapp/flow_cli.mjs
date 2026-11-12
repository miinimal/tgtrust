// Test bridge: runs the holder flow (tgtrust/webapp/holder-core.js) under Node against a live service.
// One JSON command per line; state (the saved record) lives in an in-memory storage between commands,
// exactly like localStorage does between page loads.
import { createInterface } from "node:readline";
import * as core from "../../tgtrust/webapp/holder-core.js";

const store = new Map();
const storage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => { store.set(k, String(v)); },
  removeItem: (k) => { store.delete(k); },
};

let dropNextIssueAnswer = false;
function fetchWith(base) {
  return async (url, init) => {
    const response = await fetch(url, init);
    if (dropNextIssueAnswer && url.endsWith("/issue")) {
      dropNextIssueAnswer = false;
      throw new TypeError("connection lost after the request was served");
    }
    return response;
  };
}

async function run(cmd) {
  const api = core.createApi(cmd.base, fetchWith(cmd.base));
  switch (cmd.op) {
    case "issuer": {
      const issuer = await core.loadIssuer(api);
      return { key_id: issuer.keyId, epoch: issuer.epoch, require_premium: issuer.requirePremium };
    }
    case "prepare": {
      const issuer = await core.loadIssuer(api);
      let agent, seed = null;
      if (cmd.agent) agent = core.parseAgentPublicKey(cmd.agent);
      else ({ publicKey: agent, seed } = await core.generateAgentKey());
      const record = await core.prepareRequest(issuer, agent, { seed });
      core.savePending(storage, record);
      return { record };
    }
    case "issue": {
      const issuer = await core.loadIssuer(api);
      const pending = core.loadPending(storage);
      dropNextIssueAnswer = cmd.drop_answer === true;
      const blindSignature = await core.requestBlindSignature(api, cmd.init_data, pending);
      const done = await core.completeCredential(issuer, pending, blindSignature);
      core.savePending(storage, done);
      return { record: done, package: core.credentialPackage(cmd.base, done) };
    }
    case "register": {
      const done = await core.registerAgent(api, core.loadPending(storage));
      core.savePending(storage, done);
      return { record: done };
    }
    case "pending":
      return { record: core.loadPending(storage) };
    case "put":
      store.set(core.PENDING_KEY, cmd.raw);
      return { record: core.loadPending(storage) };
    case "clear":
      core.clearPending(storage);
      return { record: core.loadPending(storage) };
    case "ed25519":
      return { supported: await core.ed25519Supported() };
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
    answer = { ok: false, error: err.constructor.name, code: err.code || null, status: err.status || 0, message: String(err.message) };
  }
  process.stdout.write(JSON.stringify(answer) + "\n");
}
