// desk/verifier.js gives the same answers as the Python implementation on every vector in vectors.json
// (made by tests/desk_vectors.py; tests/test_desk_vectors.py keeps the expectations equal to Python's).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as v from "../verifier.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DESK = path.resolve(HERE, "..");
const data = JSON.parse(await readFile(path.join(HERE, "vectors.json"), "utf8"));
const E = data.expected;
const body = (b64) => new Uint8Array(Buffer.from(b64, "base64"));

test("the bundled blind-RSA module is the holder page's, byte for byte", async () => {
  const desk = await readFile(path.join(DESK, "lib/blindrsa.js"));
  const webapp = await readFile(path.join(DESK, "../tgtrust/webapp/blindrsa.js"));
  assert.ok(desk.equals(webapp));
});

test("cards: the key a card names, or Python's exact error", () => {
  data.cards.forEach((c, i) => {
    let got;
    try {
      got = { key: v.agentKeyFromCard(c.card), error: null };
    } catch (err) {
      assert.ok(err instanceof v.CardError, c.name);
      got = { key: null, error: err.message };
    }
    assert.deepEqual(got, E.cards[i], c.name);
  });
});

test("credentials: parsed, bound to the key, issuer signature, key id", async () => {
  for (const [i, c] of data.credentials.entries()) {
    const got = await v.checkCredential(c.file, data.issuers[c.issuer]);
    const want = { ...E.credentials[i] };
    if (!want.parsed) delete want.agent;
    assert.deepEqual(got, want, c.name);
  }
});

test("request signatures: the proven key or Python's error code", async () => {
  for (const [i, r] of data.requests.entries()) {
    const nonces = new v.NonceCache(120);
    for (const [agent, nonce] of r.seen || []) nonces.use(agent, nonce, r.now);
    let got;
    try {
      got = { agent: await v.verifyRequest(r.method, r.path, r.headers, body(r.body_b64), { now: r.now, nonces }), error: null };
    } catch (err) {
      assert.ok(err instanceof v.GateError, `${r.name}: ${err}`);
      got = { agent: null, error: err.code };
    }
    assert.deepEqual(got, E.requests[i], r.name);
  }
});

test("a nonce is accepted once", async () => {
  const r = data.requests[0];
  const nonces = new v.NonceCache(120);
  const opts = { now: r.now, nonces };
  assert.equal(await v.verifyRequest(r.method, r.path, r.headers, body(r.body_b64), opts), data.agents[0].public_hex);
  await assert.rejects(v.verifyRequest(r.method, r.path, r.headers, body(r.body_b64), opts), (e) => e.code === "replay");
});

test("decisions: tier, level, evidence lines and Concordium fields equal Python's", async () => {
  for (const [i, d] of data.decisions.entries()) {
    const got = await v.decide(
      { method: d.method, path: d.path, headers: d.headers, body: body(d.body_b64) },
      {
        policy: d.policy,
        now: d.now,
        badgeLookup: async () => {
          if (d.badge === null) {
            const err = new Error("issuer unreachable");
            err.name = "_LookupFailed";
            throw err;
          }
          return structuredClone(d.badge);
        },
        linkLookup: d.link ? async () => ({ ...d.link }) : null,
        badgeUrl: (key) => `${d.issuer_url}/agents/${key}/badge`,
      },
    );
    assert.deepEqual(got, E.decisions[i], d.name);
  }
});

test("the desk's published policy is the one its network describes", async () => {
  const network = JSON.parse(await readFile(path.join(DESK, "trust_desk.network.json"), "utf8"));
  const table = network.commondefs.replacement_strings.policy_table;
  const p = v.DESK_POLICY;
  assert.match(table, new RegExp(`Credit up to ${p.staked.credit_limit}\\.`));
  assert.match(table, new RegExp(`Credit up to ${p.concordium_tier.credit_limit}\\.`));
  assert.match(table, /at least 0\.5 Gram/);
  assert.equal(p.min_stake_nanogram, 500_000_000);
  assert.match(table, new RegExp(`more than ${p.max_upheld_disputes} disputes upheld`));
  assert.equal(p.anonymous.allowed, false);
  // gate.py gives the Concordium tier to a verified key too, not only a staked one; the text must say so.
  assert.match(table, /staked\+concordium: key proven, level verified or staked/);
  assert.equal(E.decisions[data.decisions.findIndex((d) => d.name === "verified + Concordium valid")].tier.name,
    "staked+concordium");
  assert.match(table, new RegExp(`valid on Concordium ${p.require_concordium}\\.`));
});

function replayFetch(c) {
  return async (method, url, reqBody) => {
    if ((c.http || 200) !== 200) return [c.http, "{}"];
    if (method === "GET") {
      assert.ok(url.startsWith(v.BADGE_CHECK_URL) && url.endsWith(`?network=${c.network}`), url);
      return [200, JSON.stringify(c.replies.badge_check)];
    }
    assert.equal(url, v.CONCORDIUM_MCP_URL);
    const call = JSON.parse(reqBody);
    assert.equal(call.params.arguments.network, c.network);
    return [200, JSON.stringify(c.replies[call.params.name])];
  };
}

test("Concordium: the link read from recorded registry replies, and its lines", async () => {
  for (const [i, c] of data.links.entries()) {
    const link = await v.readConcordiumLink(c.agent, c.network, replayFetch(c));
    assert.deepEqual(link, E.links[i].link, c.name);
    assert.deepEqual(v.linkLines(link), E.links[i].lines, c.name);
  }
});

test("Concordium: a failed browser fetch is an error on the link, not a throw", async () => {
  const link = await v.readConcordiumLink(data.agents[0].public_hex, "testnet", async () => {
    throw new TypeError("Failed to fetch");
  });
  assert.equal(link.error, "Failed to fetch");
  assert.match(v.linkLines(link)[0], /^Concordium: unknown, the read failed \(Failed to fetch\)/);
});

test("Concordium: the badge and network named by the demo agent's cards", async () => {
  const testnet = JSON.parse(await readFile(path.join(DESK, "../examples/concordium/agent-card.json"), "utf8"));
  const mainnet = JSON.parse(await readFile(path.join(DESK, "../examples/concordium/agent-card-mainnet.json"), "utf8"));
  assert.deepEqual(v.concordiumFromCard(testnet), { network: "testnet", badge: "JyP9WrFnp62SuD2Gdquuv" });
  assert.deepEqual(v.concordiumFromCard(mainnet), { network: "mainnet", badge: "Mf22ooPJoTuWLJPahtmvD" });
  assert.equal(v.agentKeyFromCard(testnet), "dbc55639df6bfeef7366bd3c0436d0b75842ff63c3701625d818cbb7022aee26");
});

// ---------- assess(): the desk's own summary ----------

const alice = data.agents[0].public_hex;
const bob = data.agents[1].public_hex;
const issuers = [{ ...data.issuers.main, url: "https://issuer.example/v1", label: "vector issuer" }];
const goodCredential = data.credentials[0].file;
const verifiedBadge = data.decisions.find((d) => d.name === "verified").badge;
const stakedBadge = data.decisions.find((d) => d.name === "staked enough").badge;
const proofFor = (r = data.requests[0]) => ({ method: r.method, path: r.path, headers: r.headers, body: body(r.body_b64) });
const now = data.requests[0].now;
const stateOf = (res, id) => res.checks.find((c) => c.id === id)?.state;

test("assess: signed data only, issuer offline — verified, and says what was not read", async () => {
  const res = await v.assess({ key: alice, credential: goodCredential, proof: proofFor(), issuers, now,
    live: { badge: { ok: false, url: "https://issuer.example/v1/agents/x/badge", error: "Failed to fetch" }, link: "not_allowed" } });
  assert.equal(res.state, "verified");
  assert.equal(stateOf(res, "credential"), "pass");
  assert.match(res.checks.find((c) => c.id === "credential").text, /^one Telegram account per issuer epoch \(issuer-attested\), owner not disclosed/);
  assert.equal(stateOf(res, "registration"), "unavailable");
  assert.match(res.checks.find((c) => c.id === "registration").text, /^live lookup unavailable: the result uses signed data only/);
  assert.match(res.summary, /Not read: registration, concordium\./);
  // Without a badge the gate cannot place the key above "unknown"; that is what it says.
  assert.equal(res.tier.tier.name, "unknown");
  assert.equal(res.tier.error, "badge_lookup");
});

test("assess: live badge with stake and deals — wording and network label", async () => {
  const res = await v.assess({ key: alice, proof: proofFor(), issuers, now,
    live: { badge: { ok: true, url: "https://issuer.example/v1/agents/a/badge", badge: stakedBadge }, link: "not_allowed" } });
  assert.equal(res.state, "verified");
  assert.equal(res.checks.find((c) => c.id === "stake").text, "0.5 Gram active on TON testnet");
  assert.equal(res.checks.find((c) => c.id === "deals").text, "0 co-signed deal records (0 with staked counterparties)");
  assert.equal(res.tier.tier.name, "staked");
  assert.equal(res.tier.tier.creditLimit, "1000");
});

test("assess: a key that has not signed gets the anonymous tier now, and the tier it would get", async () => {
  const res = await v.assess({ key: alice, issuers, now,
    live: { badge: { ok: true, url: "u", badge: verifiedBadge }, link: "not_allowed" } });
  assert.equal(res.state, "partial");
  assert.equal(stateOf(res, "proof"), "absent");
  assert.equal(res.tier.tier.name, "anonymous");
  assert.equal(res.tier.tier.allowed, false);
  assert.equal(res.tierIfProven.tier.name, "verified");
});

test("assess: a card is a claim, and a card naming another key is invalid", async () => {
  const card = data.cards[0].card;
  const claim = await v.assess({ card, issuers, now });
  assert.equal(claim.key, alice);
  assert.equal(stateOf(claim, "card"), "claim");
  assert.match(claim.checks.find((c) => c.id === "card").text, /a card is only a claim until the key signs the desk's challenge/);
  const clash = await v.assess({ key: bob, card, issuers, now });
  assert.equal(clash.state, "invalid");
});

test("assess: false evidence is invalid — altered credential, credential of another key, bad signature", async () => {
  const altered = await v.assess({ key: alice, credential: data.credentials[4].file, issuers, now });
  assert.equal(altered.state, "invalid");
  assert.equal(stateOf(altered, "credential"), "fail");
  const other = await v.assess({ key: bob, credential: goodCredential, issuers, now });
  assert.equal(other.state, "invalid");
  const badSig = await v.assess({ key: alice, proof: proofFor(data.requests[4]), issuers, now });
  assert.equal(badSig.state, "invalid");
  const unknownIssuer = await v.assess({ key: alice, credential: data.credentials[1].file, issuers, now });
  assert.equal(unknownIssuer.state, "invalid");
});

test("assess: nothing to go on is unknown; a malformed key is invalid", async () => {
  assert.equal((await v.assess({ issuers, now })).state, "unknown");
  assert.equal((await v.assess({ key: "1234", issuers, now })).state, "invalid");
});

test("assess: a stake with no network label does not count", async () => {
  const badge = structuredClone(stakedBadge);
  delete badge.stake.network;
  const res = await v.assess({ key: alice, issuers, now, live: { badge: { ok: true, url: "u", badge }, link: "not_allowed" } });
  assert.equal(stateOf(res, "stake"), "fail");
  assert.match(res.checks.find((c) => c.id === "stake").text, /without a network label does not count/);
});

test("assess: no output uses a forbidden claim", async () => {
  const forbidden = /unique person|real human|accountable human|\bkyc\b|completed jobs|successful deals/i;
  const cases = [
    { key: alice, credential: goodCredential, proof: proofFor(), issuers, now,
      live: { badge: { ok: true, url: "u", badge: stakedBadge }, link: "not_allowed" } },
    { key: alice, issuers, now },
    { card: data.cards[0].card, issuers, now },
  ];
  for (const input of cases) {
    const res = await v.assess(input);
    for (const text of [res.summary, ...res.checks.map((c) => c.text)]) assert.doesNotMatch(text, forbidden, text);
  }
});
