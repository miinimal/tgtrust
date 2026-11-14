// Trust Desk's site actions through the real runtime: registry, tool table, delegation and receipts, with a
// scripted model in place of an LLM. Proves "Call an internal agent and a grounded capability (a registered
// local site action)" (spec section 6) without a network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { ActionRegistry } from "../runtime/actions.js";
import { AgentNetwork } from "../runtime/kernel.js";
import { buildToolTable, dispatchToolCall, runAgent } from "../runtime/runner.js";
import { TraceBus } from "../runtime/trace.js";
import { ScriptedModel } from "./scripted_model.mjs";
import { App } from "../app.js";
import { registerActions } from "../site-actions.js";
import { DESK_POLICY } from "../verifier.js";

const BASE = "http://localhost:8080";
const SCOPE = { base: BASE, network: "trust_desk" };
const vectors = JSON.parse(await readFile(new URL("./vectors.json", import.meta.url), "utf8"));
const config = JSON.parse(await readFile(new URL("../trust_desk.network.json", import.meta.url), "utf8"));
const manifest = JSON.parse(await readFile(new URL("../agent-manifest.json", import.meta.url), "utf8"));
const network = new AgentNetwork(config, "trust_desk");
const DEMO_KEY = "dbc55639df6bfeef7366bd3c0436d0b75842ff63c3701625d818cbb7022aee26";

// Every outside request the desk makes goes through this fetch, so a test can see each one.
const requests = [];
let answer = async () => [503, "{}"];
App.desk.fetchImpl = async (method, url, body, headers) => {
  requests.push({ method, url, body, headers });
  return answer(method, url, body, headers);
};

async function registry() {
  const r = new ActionRegistry();
  await registerActions({ register: r.register.bind(r, SCOPE) });
  return r;
}

function context(reg, model) {
  return { network, manifest, actions: reg, baseOrigin: BASE, displayOrigin: new URL(BASE).host, trace: new TraceBus(),
    isTop: true, frontMan: network.findFrontMan(), history: [], llm: model, confirmWebsiteActions: async () => false };
}

test("every agentTools name is registered, local-only and read-only", async () => {
  const reg = await registry();
  const entries = reg.catalog(SCOPE);
  for (const name of manifest.actions.agentTools) {
    const entry = entries.find((e) => e.name === name);
    assert.ok(entry, name);
    assert.equal(entry.effect, "read", name);
    assert.equal(entry.availability, "local-only", name);
  }
  assert.equal(entries.length, manifest.actions.agentTools.length);
});

test("the front agent delegates to evidence_checker, which calls website_check_agent", async () => {
  requests.length = 0;
  App.desk.setLiveAllowed(false);
  App.desk.load({ card: JSON.stringify(vectors.cards[0].card) });
  const key = vectors.agents[0].public_hex;
  const model = new ScriptedModel([
    { tool: "evidence_checker", arguments: { request: `Check ${key}` } },
    { tool: "website_check_agent", arguments: { agentKey: key } },
    { text: "Card: claim. Proof: absent." },
    { text: "The card names this key; it is only a claim." },
  ]);
  const reg = await registry();
  const result = await runAgent(context(reg, model), "trust_desk", `Check agent ${key}`, null, []);
  assert.match(result.text, /only a claim/);
  // Call 0: the front agent is offered its specialists and the site tools.
  assert.ok(model.toolNames(0).includes("evidence_checker"));
  assert.ok(model.toolNames(0).includes("limit_advisor"));
  // Call 2: the specialist got the site action's receipt.
  const [receipt] = model.toolResults(2);
  assert.equal(receipt.status, "succeeded");
  assert.equal(receipt.result.ok, true);
  assert.equal(receipt.result.key, key);
  assert.equal(receipt.result.state, "partial");
  assert.equal(receipt.result.checks.find((c) => c.name === "Agent card").state, "claim");
  assert.match(receipt.result.live, /live lookup unavailable/);
  assert.equal(requests.length, 0, "no outside request while live lookups are off");
});

test("limit_advisor gets the tier from website_recommend_limit", async () => {
  const key = vectors.agents[0].public_hex;
  const reg = await registry();
  const model = new ScriptedModel([{ tool: "website_recommend_limit", arguments: { agentKey: key } }, { text: "Tier anonymous." }]);
  await runAgent(context(reg, model), "limit_advisor", key, null, []);
  const [receipt] = model.toolResults(1);
  assert.equal(receipt.status, "succeeded");
  assert.equal(receipt.result.tier.name, "anonymous");
  assert.equal(receipt.result.tier.allowed, false);
  assert.equal(receipt.result.policy.minStakeGram, DESK_POLICY.min_stake_nanogram / 1e9);
});

test("a malformed key never runs: the schema refuses it, and a non-hex key is a refusal", async () => {
  const reg = await registry();
  const ctx = context(reg, new ScriptedModel([]));
  const spec = network.getAgentSpec("trust_desk");
  const table = await buildToolTable(ctx, spec, [], null);
  const tool = table.toolByName.get("website_check_agent");
  // The runner turns this throw into "Error from tool 'website_check_agent': Invalid arguments.agentKey."
  await assert.rejects(dispatchToolCall(ctx, tool, { agentKey: "abc" }, null, []), /Invalid arguments\.agentKey/);
  const nonHex = await dispatchToolCall(ctx, tool, { agentKey: "z".repeat(64) }, null, []);
  assert.equal(nonHex.status, "succeeded");
  assert.equal(nonHex.result.ok, false);
  assert.equal(nonHex.result.field, "agentKey");
});

test("live lookups contact only the listed origins, and an offline issuer reads as unavailable", async () => {
  requests.length = 0;
  App.desk.setLiveAllowed(true);
  answer = async (method, url) => {
    if (url.startsWith("https://minimal.tailee59dc.ts.net/")) throw new TypeError("Failed to fetch");
    return [200, JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "null" }], isError: false } })];
  };
  const r = await App.desk.checkForAgent(DEMO_KEY);
  const allowed = App.desk.liveOrigins().map((o) => o.origin);
  assert.ok(requests.length >= 2);
  for (const req of requests) assert.ok(allowed.includes(new URL(req.url).origin), req.url);
  for (const req of requests) assert.equal(JSON.stringify(req).includes("Authorization"), false);
  const reg = r.checks.find((c) => c.name === "Registration");
  assert.equal(reg.state, "unavailable");
  assert.match(reg.text, /^live lookup unavailable: the result uses signed data only \(Failed to fetch\)/);
  const ccd = r.checks.find((c) => c.name === "Concordium");
  assert.equal(ccd.state, "absent");
  assert.match(ccd.text, /not bound to any Concordium account/);
  App.desk.setLiveAllowed(false);
});

test("get_desk reports the live-lookup choice, the origins and what the site cannot do", async () => {
  const state = App.desk.getState();
  assert.equal(state.liveLookups, "off");
  assert.deepEqual(state.liveOrigins.map((o) => o.origin),
    ["https://minimal.tailee59dc.ts.net", "https://agent-registry-mcp.concordium.com"]);
  assert.ok(state.cannotDo.includes("move or hold money"));
  assert.equal(state.challenge.scheme, "tgtrust-req/v1");
});

test("a demo agent made in this browser proves its key, and is partial without registration", async () => {
  const loaded = await App.desk.makeDemoAgent();
  assert.equal(loaded.ok, true);
  const r = await App.desk.check(loaded.key);
  assert.equal(r.checks.find((c) => c.id === "proof").state, "pass");
  assert.equal(r.state, "partial");
  assert.equal(r.tier.tier.name, "unknown", "proven key, badge not read: the gate's unknown tier");
});

test("unreadable input is refused without changing the desk", async () => {
  const before = App.desk.getState().currentKey;
  assert.deepEqual(App.desk.load({ card: "{not json" }), { ok: false, field: "card", reason: "The agent card is not valid JSON" });
  assert.equal(App.desk.load({ key: "12" }).field, "key");
  assert.equal(App.desk.load({ proof: "[1]", key: DEMO_KEY }).field, "proof");
  assert.equal(App.desk.getState().currentKey, before);
});
