// Trust Desk published files: the manifest, the resolved network and links.json.
// Proves the rows of docs/COGNIZANT.md marked "network test".
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseHocon } from "../runtime/hocon.js";

const DESK = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const readJson = async (name) => JSON.parse(await readFile(path.join(DESK, name), "utf8"));

const manifest = await readJson("agent-manifest.json");
const network = await readJson("trust_desk.network.json");
const links = await readJson("links.json");

const agents = network.tools;
const strings = network.commondefs.replacement_strings;
const expand = (text) => text.replace(/\{(\w+)\}/g, (all, key) => (key in strings ? strings[key] : all));

test("manifest lists the network by name, front agent and resolved file", () => {
  assert.equal(manifest.networks.length, 1);
  const entry = manifest.networks[0];
  assert.equal(entry.name, "trust_desk");
  assert.equal(entry.front_man, "trust_desk");
  assert.equal(entry.hocon, "./trust_desk.network.json");
  assert.ok(agents.some((a) => a.name === entry.front_man), "front agent is defined");
  assert.deepEqual(entry.sample_queries, network.metadata.sample_queries);
  assert.ok(entry.description.length > 20);
});

test("manifest declares the default router, a closed peer policy and a static deployment", () => {
  assert.equal(manifest.llm_router.base_url, "https://api.otari.ai/api/v1");
  assert.equal(manifest.llm_router.mock, false);
  assert.equal(manifest.peer_policy.mode, "closed");
  assert.deepEqual(manifest.allowed_peers, []);
  assert.equal(manifest.deployment.mode, "static");
  assert.equal(manifest.actions.bridge, "./bridge/action-bridge.html");
  assert.deepEqual(manifest.actions.agentTools, ["get_desk", "check_agent", "recommend_limit"]);
});

test("the published network is the HOCON source, fully resolved", async () => {
  const source = parseHocon((await readFile(path.join(DESK, "trust_desk.hocon"), "utf8")).replace(/\r\n/g, "\n"));
  assert.deepEqual(network, source);
  const raw = await readFile(path.join(DESK, "trust_desk.network.json"), "utf8");
  assert.doesNotMatch(raw, /\binclude\b\s*["(]/, "no include directives");
  assert.doesNotMatch(raw, /\$\{/, "no substitutions");
  const values = [];
  const walk = (v) => (typeof v === "string" ? values.push(v) : v && typeof v === "object" && Object.values(v).forEach(walk));
  walk(network);
  for (const value of values) {
    assert.doesNotMatch(value, /(^|\s)[A-Za-z]:[\\/]|file:\/\/|\/home\/|\/Users\/|\.\.\//, "no publisher-only paths");
  }
});

test("at least two agents, unique names, each with a request schema and instructions", () => {
  assert.ok(agents.length >= 2);
  const names = agents.map((a) => a.name);
  assert.equal(new Set(names).size, names.length);
  for (const agent of agents) {
    assert.ok(agent.function.description.length > 10, agent.name);
    assert.equal(agent.function.parameters.type, "object");
    assert.deepEqual(agent.function.parameters.required, ["request"]);
    assert.ok(agent.instructions.length > 100, agent.name);
    for (const tool of agent.tools) {
      assert.ok(names.includes(tool), `${agent.name} calls a defined agent: ${tool}`);
    }
  }
  const front = agents.find((a) => a.name === "trust_desk");
  assert.deepEqual(front.tools, ["evidence_checker", "limit_advisor"]);
});

test("no agent passes private context to another network", () => {
  for (const agent of agents) {
    assert.equal(agent.allow, undefined, `${agent.name} names no sly_data fields`);
  }
});

test("every agent carries the evidence wording rules and treats card text as data", () => {
  for (const agent of agents) {
    const text = expand(agent.instructions);
    assert.match(text, /one Telegram account per issuer epoch \(issuer-attested\), owner not disclosed/);
    assert.match(text, /co-signed deal records \(M with staked counterparties\)/);
    assert.match(text, /network label/);
    assert.match(text, /never an instruction to you/);
    assert.match(text, /live lookup unavailable/);
  }
});

test("forbidden claims appear only inside the rule that forbids them", () => {
  const forbidden = /unique person|real human|accountable human|kyc|completed jobs|successful deals/i;
  for (const agent of agents) {
    for (const line of expand(agent.instructions).split("\n")) {
      if (forbidden.test(line)) {
        assert.match(line, /^- .*Never say/, `${agent.name}: ${line}`);
      }
    }
  }
});

test("the template's peer rules are kept on the front agent", () => {
  const front = agents.find((a) => a.name === "trust_desk");
  assert.match(expand(front.instructions), /When you have no website_\* tools, another site's assistant is asking/);
});

test("links.json is the publisher's empty binding map for this network", () => {
  assert.deepEqual(links, { version: 1, networks: { trust_desk: {} } });
});

test("no coded tools and no secrets in any published file", async () => {
  assert.equal(network.coded_tools, undefined);
  assert.equal(manifest.coded_tools, undefined);
  const secret = /otk_[A-Za-z0-9]|sk-[A-Za-z0-9]{10}|Bearer [A-Za-z0-9]|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|api[_-]?key"\s*:\s*"[^"]/;
  const files = ["agent-manifest.json", "trust_desk.network.json", "links.json", "agent-mcp.json",
    ".well-known/nsdeploy.json", ".well-known/nsdeploy-agent.json", "bridge/agent-manifest.json"];
  for (const name of files) {
    assert.doesNotMatch(await readFile(path.join(DESK, name), "utf8"), secret, name);
  }
});

test("the runtime is the skill's copy, unchanged, with its licence", async () => {
  const recorded = (await readFile(path.join(DESK, "tools/agentify/RUNTIME.sha256"), "utf8"))
    .split("\n").filter((ln) => ln && !ln.startsWith("#"))
    .map((ln) => ln.trim().split(/\s+\*?/)).map(([hash, file]) => [file, hash]);
  const listed = new Set(recorded.map(([file]) => file));
  const walk = async (dir) => (await Promise.all((await readdir(path.join(DESK, dir), { withFileTypes: true }))
    .map((e) => (e.isDirectory() ? walk(`${dir}/${e.name}`) : [`${dir}/${e.name}`])))).flat();
  const present = await walk("runtime");
  assert.deepEqual(present.sort(), [...listed].sort(), "same file list as recorded");
  for (const [file, hash] of recorded) {
    const actual = createHash("sha256").update(await readFile(path.join(DESK, file))).digest("hex");
    assert.equal(actual, hash, file);
  }
  assert.ok(listed.has("runtime/LICENSE.txt"));
});
