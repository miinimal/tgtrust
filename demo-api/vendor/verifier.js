// tgtrust verifier for the browser: checks an agent's tgtrust evidence with no server of its own.
//
// It mirrors the Python implementation line by line, and desk/tests/verifier.test.mjs proves it on the vectors
// that tests/desk_vectors.py makes with that implementation:
//   agentKeyFromCard   <- tgtrust.client.agent_key_from_card
//   checkCredential    <- tgtrust.client.CredentialFile.from_dict + tgtrust.issuer.verify_credential
//   verifyRequest      <- tgtrust.gate.TrustGate.verify          (request signature tgtrust-req/v1)
//   decide             <- tgtrust.gate.TrustGate.decide          (tier, evidence lines)
//   readConcordiumLink <- tgtrust.concordium.read_link + link_lines
// assess() is the desk's own summary on top of these, with the wording fixed in WORDING.
//
// Works in browsers with WebCrypto Ed25519 (Chrome 137+, Safari 17+, Firefox 129+) and in Node 22+.
// Licence: Apache-2.0, as the rest of tgtrust.

import * as rsa from "./lib/blindrsa.js";

export const TGTRUST_EXTENSION_URI = "https://github.com/miinimal/tgtrust/blob/main/docs/CONCORDIUM.md#a2a-extension-v1";
export const CONCORDIUM_EXTENSION_URI = "https://docs.concordium.com/a2a-extensions/concordium-badge/v1";
export const CREDENTIAL_FORMAT = "tgtrust-credential/v1";
export const SCHEME = "tgtrust-req/v1";
export const H_AGENT = "X-Tgtrust-Agent";
export const H_TIME = "X-Tgtrust-Time";
export const H_NONCE = "X-Tgtrust-Nonce";
export const H_SIG = "X-Tgtrust-Signature";
export const HEADERS = [H_AGENT, H_TIME, H_NONCE, H_SIG];
export const LEVELS = ["unknown", "revoked", "verified", "staked"];

/** The only words the desk uses for each kind of evidence (ERC-8004 review R-1111-01). */
export const WORDING = {
  credential: "one Telegram account per issuer epoch (issuer-attested), owner not disclosed",
  deals: (n, m) => `${n} co-signed deal record${n === 1 ? "" : "s"} (${m} with staked counterparties)`,
  cardClaim: "a card is only a claim until the key signs the desk's challenge",
  liveUnavailable: "live lookup unavailable: the result uses signed data only",
};

const enc = new TextEncoder();
const KEY_RE = /^[0-9a-f]{64}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;
const METHOD_RE = /^[A-Z]{1,10}$/;
const PATH_MAX = 2048;

// ---------- small helpers ----------

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const has = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
/** Python's repr of True / False / None inside f-strings. */
const pyBool = (v) => (v === true ? "True" : v === false ? "False" : v === null || v === undefined ? "None" : String(v));

export function parseAgentKey(text) {
  const key = String(text ?? "").trim().toLowerCase();
  if (!KEY_RE.test(key)) throw new Error("an agent key is 64 hexadecimal characters");
  return key;
}

function b64urlDecodeStrict(value) {
  // Python: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)); a length of 1 mod 4 cannot decode.
  if (value.length % 4 === 1) throw new Error("bad base64url length");
  return rsa.b64urlDecode(value);
}

// ---------- cards (tgtrust.client.agent_key_from_card) ----------

export class CardError extends Error {}

export function agentKeyFromCard(card) {
  if (!isObject(card)) throw new CardError("the card is not a JSON object");
  const found = [];
  const caps = card.capabilities;
  const exts = isObject(caps) ? caps.extensions : null;
  for (const ext of Array.isArray(exts) ? exts : []) {
    if (isObject(ext) && ext.uri === TGTRUST_EXTENSION_URI) {
      found.push(isObject(ext.params) ? (has(ext.params, "agentKey") ? ext.params.agentKey : null) : null);
    }
  }
  const tg = card.tgtrust;
  if (isObject(tg) && has(tg, "agent_key")) found.push(tg.agent_key);
  if (!found.length) {
    throw new CardError("the card has no tgtrust agent key (no tgtrust extension, no tgtrust.agent_key)");
  }
  const keys = new Set();
  for (const k of found) {
    if (typeof k !== "string" || k.length !== 64 || [...k.toLowerCase()].some((c) => !"0123456789abcdef".includes(c))) {
      throw new CardError("the card's tgtrust agent key is not 64 hex characters");
    }
    keys.add(k.toLowerCase());
  }
  if (keys.size !== 1) throw new CardError("the card names two different tgtrust agent keys");
  return [...keys][0];
}

/** What a card says about Concordium: the badge token, its network (from the CAIP-2 genesis prefix) and account. */
export function concordiumFromCard(card) {
  if (!isObject(card) || !isObject(card.capabilities) || !Array.isArray(card.capabilities.extensions)) return null;
  const ext = card.capabilities.extensions.find((e) => isObject(e) && e.uri === CONCORDIUM_EXTENSION_URI);
  if (!ext || !isObject(ext.params) || typeof ext.params.tokenAddress !== "string") return null;
  const m = /^ccd:([0-9a-f]{32})\/cis-2:([1-9A-HJ-NP-Za-km-z]+)$/.exec(ext.params.tokenAddress);
  if (!m) return null;
  const network = Object.values(NETWORKS).find((n) => n.genesis_hash.startsWith(m[1]))?.name || null;
  return { network, badge: m[2] };
}

// ---------- credentials (CredentialFile.from_dict + verify_credential) ----------

/**
 * Check a credential file against a pinned issuer. Returns the same fields tests/desk_vectors.py computes:
 * {parsed, error, agent?, signature_valid, key_id_matches}.
 */
export async function checkCredential(file, issuer) {
  const malformed = { parsed: false, error: "credential file is malformed", signature_valid: null, key_id_matches: null };
  if (!isObject(file) || file.format !== CREDENTIAL_FORMAT) {
    return { parsed: false, error: "not a tgtrust credential file", signature_valid: null, key_id_matches: null };
  }
  let agent;
  let salt;
  let token;
  let signature;
  try {
    for (const field of ["agent_public_key", "salt", "token", "signature", "issuer", "key_id"]) {
      if (!has(file, field)) throw new Error(`missing ${field}`);
    }
    for (const field of ["agent_public_key", "salt", "token", "signature"]) {
      if (typeof file[field] !== "string") throw new Error(`bad ${field}`);
    }
    if (!/^([0-9a-fA-F]{2})*$/.test(file.agent_public_key)) throw new Error("bad hex");
    agent = rsa.fromHex(file.agent_public_key.toLowerCase());
    salt = b64urlDecodeStrict(file.salt);
    token = b64urlDecodeStrict(file.token);
    signature = b64urlDecodeStrict(file.signature);
  } catch {
    return malformed;
  }
  const inconsistent = {
    parsed: false, error: "credential file is inconsistent: the token is not bound to this agent key",
    signature_valid: null, key_id_matches: null,
  };
  if (agent.length !== 32) return inconsistent;
  // registry.agent_token accepts any salt length; blindrsa.agentToken insists on 16 bytes, so hash here.
  const expected = await rsa.sha256(rsa.concat(rsa.TOKEN_PREFIX, agent, salt));
  if (rsa.toHex(expected) !== rsa.toHex(token)) return inconsistent;
  const publicKey = rsa.parsePublicKey(issuer.public_key_pem);
  const valid = token.length === 32 && (await rsa.verify(publicKey, rsa.credentialMessage(token), signature));
  return {
    parsed: true, error: null, agent: rsa.toHex(agent), signature_valid: valid,
    key_id_matches: String(file.key_id) === issuer.key_id,
  };
}

// ---------- request signatures (gate.request_message, NonceCache, TrustGate.verify) ----------

export class GateError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export async function requestMessage(method, path, ts, nonce, body) {
  if (!METHOD_RE.test(method)) throw new GateError("bad_request", "method must be 1-10 upper-case letters");
  if (!path.startsWith("/") || path.length > PATH_MAX || /[\r\n]/.test(path)) {
    throw new GateError("bad_request", "path must start with / and be at most 2048 characters on one line");
  }
  if (!NONCE_RE.test(nonce)) throw new GateError("bad_nonce", "nonce must be 16-64 characters of A-Z a-z 0-9 _ -");
  const digest = rsa.toHex(await rsa.sha256(body));
  return enc.encode([SCHEME, method, path, String(Math.trunc(Number(ts))), nonce, digest].join("\n"));
}

/** Remembers (agent, nonce) pairs inside the time window, so a captured request cannot be replayed. */
export class NonceCache {
  constructor(windowSeconds, maxEntries = 100_000) {
    this.window = windowSeconds;
    this.maxEntries = maxEntries;
    this.seen = new Map();
  }

  use(agent, nonce, now) {
    const horizon = now - 2 * this.window;
    for (const [key, ts] of this.seen) {
      if (ts >= horizon && this.seen.size < this.maxEntries) break;
      this.seen.delete(key);
    }
    const key = `${agent}\n${nonce}`;
    if (this.seen.has(key)) return false;
    this.seen.set(key, now);
    return true;
  }
}

function header(headers, name) {
  for (const [k, v] of Object.entries(headers || {})) {
    if (k.toLowerCase() === name.toLowerCase()) return v;
  }
  return null;
}

async function ed25519Verify(publicKey, signature, message) {
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
  } catch {
    return false;
  }
}

/** The proven agent key, null when the request carries no tgtrust headers. Throws GateError otherwise. */
export async function verifyRequest(method, path, headers, body, { now, nonces, maxSkew = 120 }) {
  const values = Object.fromEntries(HEADERS.map((h) => [h, header(headers, h)]));
  if (HEADERS.every((h) => values[h] === null || values[h] === undefined)) return null;
  const missing = HEADERS.filter((h) => !values[h]);
  if (missing.length) throw new GateError("missing_header", `missing ${missing.join(", ")}`);
  const agent = String(values[H_AGENT]).toLowerCase();
  if (!KEY_RE.test(agent)) throw new GateError("bad_agent", "agent key must be 64 hex characters");
  if (!/^[0-9]{1,12}$/.test(values[H_TIME])) throw new GateError("bad_time", "time must be unix seconds");
  const ts = Number(values[H_TIME]);
  const clock = Math.trunc(now);
  if (Math.abs(clock - ts) > maxSkew) {
    throw new GateError("stale", `request time is more than ${maxSkew} s away from the server clock`);
  }
  const msg = await requestMessage(method, path, ts, values[H_NONCE], body);
  if (!/^[A-Za-z0-9_-]+$/.test(values[H_SIG] || "")) throw new GateError("bad_signature", "signature is not base64url");
  let sig;
  try {
    sig = b64urlDecodeStrict(values[H_SIG]);
  } catch {
    throw new GateError("bad_signature", "signature is not base64url");
  }
  if (sig.length !== 64) throw new GateError("bad_signature", "signature must be 64 bytes");
  if (!(await ed25519Verify(rsa.fromHex(agent), sig, msg))) {
    throw new GateError("bad_signature", "signature does not match the agent key and request");
  }
  if (!nonces.use(agent, values[H_NONCE], clock)) throw new GateError("replay", "this nonce was already used by this agent");
  return agent;
}

/** Client side (gate.sign_request): headers that prove a request comes from the holder of an Ed25519 key. */
export async function signRequest(privateKey, publicHex, method, path, body, { now, nonce }) {
  const msg = await requestMessage(method, path, now, nonce, body);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, msg));
  return { [H_AGENT]: publicHex, [H_TIME]: String(Math.trunc(now)), [H_NONCE]: nonce, [H_SIG]: rsa.b64urlEncode(sig) };
}

// ---------- tiers (gate.Tier, Policy, TrustGate.decide) ----------

const tierDict = (t) => ({ name: t.name, allowed: t.allowed, prepay: t.prepay, creditLimit: String(t.credit_limit) });

/** The desk's published policy: the example policy of docs/TRUST_GATE.md. Amounts are the caller API's own unit. */
export const DESK_POLICY = Object.freeze({
  anonymous: { name: "anonymous", allowed: false, prepay: true, credit_limit: 0 },
  unknown: { name: "unknown", allowed: true, prepay: true, credit_limit: 0 },
  verified: { name: "verified", allowed: true, prepay: true, credit_limit: 0 },
  staked: { name: "staked", allowed: true, prepay: false, credit_limit: 1000 },
  concordium_tier: { name: "staked+concordium", allowed: true, prepay: false, credit_limit: 5000 },
  require_concordium: "testnet",
  min_stake_nanogram: 500_000_000,
  max_upheld_disputes: 0,
});

function upheld(badge) {
  const disputes = (isObject(badge.history) ? badge.history.disputes : null) || {};
  let value = has(disputes, "upheld_against") ? disputes.upheld_against : has(disputes, "upheld") ? disputes.upheld : 0;
  if (typeof value === "boolean") value = value ? 1 : 0; // Python bool is an int
  return Number.isInteger(value) && value >= 0 ? value : 0;
}

/** Python int() of a JSON value, as BigInt; anything int() refuses becomes 0. */
function pyInt(value) {
  if (typeof value === "boolean") return value ? 1n : 0n;
  if (typeof value === "number" && Number.isFinite(value)) return BigInt(Math.trunc(value));
  if (typeof value === "string" && /^\s*[+-]?\d+\s*$/.test(value)) return BigInt(value.trim());
  return 0n;
}

function stakeAmount(badge) {
  const stake = (isObject(badge.stake) ? badge.stake : null) || {};
  if (stake.found !== true || stake.withdrawing) return 0n;
  const amount = has(stake, "amount_nanogram") ? stake.amount_nanogram : has(stake, "amount") ? stake.amount : 0;
  const n = pyInt(amount);
  return n > 0n ? n : 0n;
}

function decision(tier, extra = {}) {
  return { agent: null, level: null, proven: false, error: null, tier, evidence: [], concordium: null, ...extra };
}

/** The tier for a key that is already proven (the part of TrustGate.decide after verify). */
async function decideProven(agent, policy, { badgeLookup, linkLookup, badgeUrl }, evidence) {
  const p = policy;
  let badge;
  try {
    badge = await badgeLookup(agent);
  } catch (err) {
    evidence.push(`tgtrust badge: lookup failed (${err?.name || "Error"}); treated as unknown`);
    return decision(p.unknown, { agent, level: "unknown", proven: true, error: "badge_lookup", evidence });
  }
  const level = isObject(badge) ? badge.level : undefined;
  if (!isObject(badge) || (has(badge, "agent") && badge.agent !== agent) || !LEVELS.includes(level)) {
    evidence.push("tgtrust badge: malformed or for another key; treated as unknown");
    return decision(p.unknown, { agent, level: "unknown", proven: true, error: "badge_malformed", evidence });
  }
  const src = badgeUrl ? ` [source: ${badgeUrl(agent)}]` : " [source: issuer badge]";
  evidence.push(`tgtrust level: ${level}${src}`);
  const d = decision(p.unknown, { agent, level, proven: true, evidence });
  if (level === "unknown" || level === "revoked") return d;

  const up = upheld(badge);
  if (up > p.max_upheld_disputes) {
    evidence.push(`disputes upheld against it: ${up} (policy allows ${p.max_upheld_disputes}); held at the unknown tier`);
    return d;
  }
  d.tier = p.verified;
  const stake = stakeAmount(badge);
  const minStake = BigInt(p.min_stake_nanogram);
  if (level === "staked" && stake >= minStake) {
    const net = (isObject(badge.stake) && has(badge.stake, "network")) ? badge.stake.network : "?";
    evidence.push(`stake: ${stake} nanogram active on TON ${net}`);
    d.tier = p.staked;
  } else if (level === "staked") {
    evidence.push(`stake: ${stake} nanogram, below the policy minimum ${p.min_stake_nanogram}`);
  }
  if (p.require_concordium && p.concordium_tier && linkLookup) {
    const link = await linkLookup(agent);
    d.concordium = {
      network: link.network, account: link.account, binding: link.binding_status, badge: link.badge,
      badgeValid: link.badge_valid, error: link.error,
    };
    if (link.binding_status === "Active" && link.badge_valid === true && !link.error) {
      evidence.push(`Concordium: key bound to ${link.account}, badge ${link.badge} valid ` +
        `[source: Concordium ${link.network} Agent Registry]`);
      d.tier = p.concordium_tier;
    } else {
      const why = link.error || (link.account === null || link.account === undefined ? "not bound"
        : `binding ${pyBool(link.binding_status)}, badge valid ${pyBool(link.badge_valid)}`);
      evidence.push(`Concordium: not counted (${why})`);
    }
  }
  return d;
}

/**
 * gate.TrustGate.decide: verify the request signature, read the badge, map the evidence to a tier. Never throws
 * for caller mistakes or lookup failures. Returns the shape of gate.Decision.to_dict().
 */
export async function decide({ method, path, headers, body }, { policy = DESK_POLICY, badgeLookup, linkLookup,
  badgeUrl, now, nonces, maxSkew = 120 }) {
  let agent;
  try {
    agent = await verifyRequest(method, path, headers, body, { now, nonces: nonces || new NonceCache(maxSkew), maxSkew });
  } catch (err) {
    if (!(err instanceof GateError)) throw err;
    return toDict(decision(policy.anonymous, { error: err.code, evidence: [`request signature: rejected (${err.code})`] }));
  }
  if (agent === null) {
    return toDict(decision(policy.anonymous, { evidence: ["request signature: none (anonymous caller)"] }));
  }
  const evidence = [`request signature: valid for agent key ${agent} [${SCHEME}]`];
  return toDict(await decideProven(agent, policy, { badgeLookup, linkLookup, badgeUrl }, evidence));
}

/** The tier a key would get once it proves itself, from the same lookups (for a key that has not signed yet). */
export async function tierIfProven(agent, opts) {
  const policy = opts.policy || DESK_POLICY;
  const evidence = [`request signature: assumed valid for agent key ${agent} [${SCHEME}]`];
  return toDict(await decideProven(agent, policy, opts, evidence));
}

function toDict(d) {
  return { agent: d.agent, level: d.level, proven: d.proven, error: d.error, tier: tierDict(d.tier),
    evidence: [...d.evidence], concordium: d.concordium };
}

// ---------- Concordium Agent Registry (concordium.read_link, link_lines) ----------

export const CONCORDIUM_MCP_URL = "https://agent-registry-mcp.concordium.com/mcp";
export const BADGE_CHECK_URL = "https://agent-registry-mcp.concordium.com/v1/badge-check/";
// Values read by tgtrust/concordium.py from the registry's contract_info tool on 2026-11-13.
export const NETWORKS = {
  testnet: { name: "testnet", genesis_hash: "4221332d34e1694168c2a0c0b3fd0f273809612cb13d000d5c2e00e85f50f796",
    cis8: [12801, 0], cis8004: [12802, 0] },
  mainnet: { name: "mainnet", genesis_hash: "9dd9ca4d19e9393877d2c44b70f89acbfc0883c2243e5eeaecc0d1cd0503f478",
    cis8: [10081, 0], cis8004: [10082, 0] },
};
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

class ConcordiumError extends Error {}

/** concordium.account_bytes: Base58Check, version byte 1, 32-byte account. Throws on anything else. */
export async function accountBytes(address) {
  address = String(address).trim();
  if (address.length < 40 || address.length > 60 || [...address].some((c) => !B58.includes(c))) {
    throw new ConcordiumError("not a Concordium account address");
  }
  let n = 0n;
  for (const c of address) n = n * 58n + BigInt(B58.indexOf(c));
  if (n.toString(2).length > 37 * 8 && n !== 0n) throw new ConcordiumError("not a Concordium account address");
  const raw = rsa.i2osp(n, 37);
  if (raw[0] !== 1) throw new ConcordiumError("not a Concordium account address");
  const check = await rsa.sha256(await rsa.sha256(raw.subarray(0, 33)));
  if (rsa.toHex(check.subarray(0, 4)) !== rsa.toHex(raw.subarray(33))) {
    throw new ConcordiumError("Concordium account address checksum does not match");
  }
  return raw.subarray(1, 33);
}

const externalKey = (hex) => ({ namespace: "tgtrust:v1", key_type: "ed25519", public_key_hex: hex.toLowerCase() });

/** fetch(method, url, body, headers) -> [status, text]; the browser default uses window.fetch with a timeout. */
export function browserFetch(timeoutMs = 12_000) {
  return async (method, url, body, headers) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, { method, body, headers, signal: controller.signal, credentials: "omit",
        cache: "no-store", redirect: "follow" });
      return [resp.status, await resp.text()];
    } finally {
      clearTimeout(timer);
    }
  };
}

class RegistryReader {
  constructor(network, fetchImpl) {
    if (!has(NETWORKS, network)) throw new Error(`unknown network '${network}'`);
    this.network = network;
    this.fetch = fetchImpl;
  }

  async tool(name, args) {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name, arguments: { network: this.network, ...args } } });
    const [status, raw] = await this.fetch("POST", CONCORDIUM_MCP_URL, body,
      { "Content-Type": "application/json", Accept: "application/json, text/event-stream" });
    if (status !== 200) throw new ConcordiumError(`registry answered HTTP ${status}`);
    let text = String(raw);
    if (text.trimStart().startsWith("event:") || text.trimStart().startsWith("data:")) {
      text = text.split(/\r?\n/).find((ln) => ln.startsWith("data:"))?.slice(5) ?? "{}";
    }
    let result;
    let content;
    try {
      result = JSON.parse(text).result;
      content = result.content[0].text;
      if (content === undefined) throw new Error("shape");
    } catch {
      throw new ConcordiumError("registry reply has an unexpected shape");
    }
    if (result.isError) throw new ConcordiumError(`registry tool error: ${String(content).slice(0, 200)}`);
    try {
      return JSON.parse(content);
    } catch {
      throw new ConcordiumError(`registry tool error: ${String(content).slice(0, 200)}`);
    }
  }

  async ownerOfKey(hex) {
    const reply = await this.tool("owner_of_key", { external_key: externalKey(hex) });
    if (reply === null) return null;
    const owner = isObject(reply) ? reply.owner : undefined;
    if (typeof owner !== "string") throw new ConcordiumError("registry reply has an unexpected shape");
    await accountBytes(owner);
    return [owner, String(reply.status || "unknown")];
  }

  agentForKey(hex) {
    const [index, subindex] = NETWORKS[this.network].cis8;
    return this.tool("agent_by_external_reference", { external_reference: {
      contract_address: { index, subindex }, kind: "Cis8", key: externalKey(hex) } });
  }

  async badgeCheck(badge) {
    if (!badge || [...badge].some((c) => !B58.includes(c))) throw new ConcordiumError("not a badge token address");
    const url = `${BADGE_CHECK_URL}${encodeURIComponent(badge)}?network=${this.network}`;
    const [status, raw] = await this.fetch("GET", url, null, { Accept: "application/json" });
    if (status !== 200) throw new ConcordiumError(`badge check answered HTTP ${status}`);
    try {
      return JSON.parse(raw);
    } catch {
      throw new ConcordiumError("badge check reply is not JSON");
    }
  }
}

/** Key -> CIS-8 owner account -> that key's CIS-8004 agent -> badge check. Never throws on network errors. */
export async function readConcordiumLink(agentHex, network, fetchImpl) {
  const reader = new RegistryReader(network, fetchImpl);
  const link = { network, account: null, binding_status: null, badge: null, badge_valid: null, status: null, error: null };
  try {
    const bound = await reader.ownerOfKey(agentHex);
    if (bound === null) return link;
    [link.account, link.binding_status] = bound;
    if (link.binding_status !== "Active") return link;
    const agent = await reader.agentForKey(agentHex);
    const token = isObject(agent) ? agent.token_address : null;
    if (token) {
      link.badge = token;
      const verdict = await reader.badgeCheck(token);
      link.badge_valid = Boolean(verdict.badge_valid);
      const onChain = (isObject(verdict.on_chain) ? verdict.on_chain : null) || {};
      link.status = has(onChain, "status") ? onChain.status : null;
      const owner = onChain.owner_account;
      if (owner && owner !== link.account) {
        link.badge_valid = false;
        link.error = "badge owner is a different account than the key binding";
      }
    }
  } catch (err) {
    // Python catches ConcordiumError, OSError and ValueError; a failed browser fetch is the OSError case.
    link.error = String(err?.message || "") || err?.name || "Error";
  }
  return link;
}

export function linkLines(link) {
  const src = `[source: Concordium ${link.network} Agent Registry, CIS-8 / CIS-8004]`;
  if (link.error && link.account === null) return [`Concordium: unknown, the read failed (${link.error.slice(0, 80)}) ${src}`];
  if (link.account === null) return [`Concordium: this key is not bound to any Concordium account ${src}`];
  const short = `${link.account.slice(0, 6)}…${link.account.slice(-4)}`;
  if (link.binding_status !== "Active") {
    return [`Concordium: binding to account ${short} is ${link.binding_status}, not active ${src}`];
  }
  const lines = [`Concordium: key bound to account ${short} (accounts are opened only ` +
    `with an identity from an identity provider; the person is not disclosed) ${src}`];
  if (link.badge === null) {
    lines.push(!link.error ? `Concordium badge: none for this key ${src}`
      : `Concordium badge: unknown (${link.error.slice(0, 80)}) ${src}`);
  } else {
    const state = link.badge_valid ? "valid" : "NOT valid";
    const why = link.error ? `, ${link.error.slice(0, 80)}` : "";
    lines.push(`Concordium badge: ${link.badge}, ${state} (status ${link.status || "unknown"}${why}) ${src}`);
  }
  return lines;
}

// ---------- the issuer's public badge ----------

/** Read GET {issuer}/agents/{key}/badge. Returns {ok, badge?, error?, url}; never throws. */
export async function fetchBadge(issuerUrl, agentHex, fetchImpl) {
  const url = `${issuerUrl.replace(/\/$/, "")}/agents/${agentHex}/badge`;
  try {
    const [status, raw] = await fetchImpl("GET", url, null, { Accept: "application/json" });
    if (status !== 200) return { ok: false, url, error: `issuer answered HTTP ${status}` };
    return { ok: true, url, badge: JSON.parse(raw) };
  } catch (err) {
    return { ok: false, url, error: err?.name === "AbortError" ? "timed out" : String(err?.message || err) };
  }
}

// ---------- the desk's assessment ----------

function gram(nanogram) {
  const n = BigInt(nanogram);
  const whole = n / 1_000_000_000n;
  const frac = (n % 1_000_000_000n).toString().padStart(9, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
}

/**
 * Everything the desk can honestly say about one key, from what it was given.
 *
 * input: {key?, card?, credential?, proof?: {method, path, headers, body, nonces}, issuers: [pinned issuer],
 *         live: {badge?: {ok, badge?, error?, url} | "not_allowed", link?: link | "not_allowed"},
 *         now, policy?}
 * Returns {state, key, checks: [{id, label, state, text, source}], summary, tier, tierIfProven, live}.
 * Check states: pass, fail, claim (stated, not proven), unavailable (could not be read), absent (not given).
 */
export async function assess(input) {
  const checks = [];
  const add = (id, label, state, text, source = null) => checks.push({ id, label, state, text, source });
  const policy = input.policy || DESK_POLICY;
  let key = null;
  let invalid = false;

  // 1. Which key.
  let typed = null;
  if (input.key) {
    try {
      typed = parseAgentKey(input.key);
    } catch (err) {
      add("key", "Agent key", "fail", err.message);
      invalid = true;
    }
  }
  let carded = null;
  if (input.card !== undefined && input.card !== null) {
    try {
      carded = agentKeyFromCard(input.card);
    } catch (err) {
      add("card", "Agent card", "fail", err.message, "agent card");
      invalid = true;
    }
  }
  if (typed && carded && typed !== carded) {
    add("card", "Agent card", "fail", `the card names key ${carded}, not the key given (${typed})`, "agent card");
    invalid = true;
  } else if (carded) {
    add("card", "Agent card", "claim", `the card names key ${carded}; ${WORDING.cardClaim}`, "agent card");
  }
  key = typed || carded;
  if (!key) {
    if (!checks.length) add("key", "Agent key", "absent", "no agent key or card was given");
    return { state: invalid ? "invalid" : "unknown", key: null, checks, summary: summarize(invalid ? "invalid" : "unknown", checks),
      tier: null, tierIfProven: null };
  }
  if (typed) add("key", "Agent key", "pass", `well-formed Ed25519 public key ${key}`);

  // 2. Does the caller hold the key?
  let proven = false;
  if (input.proof) {
    try {
      const agent = await verifyRequest(input.proof.method, input.proof.path, input.proof.headers, input.proof.body,
        { now: input.now, nonces: input.proof.nonces || new NonceCache(120) });
      if (agent === key) {
        proven = true;
        add("proof", "Holds the key", "pass", `the key signed the desk's challenge (${SCHEME})`, "signature in the request");
      } else {
        add("proof", "Holds the key", "fail", agent === null ? "the request carries no tgtrust signature"
          : `the request was signed by another key (${agent})`, "signature in the request");
        invalid = agent !== null;
      }
    } catch (err) {
      add("proof", "Holds the key", "fail", `signature rejected (${err.code || "error"}): ${err.message}`, "signature in the request");
      invalid = true;
    }
  } else {
    add("proof", "Holds the key", "absent", "not proven: the key has not signed the desk's challenge");
  }

  // 3. Credential, checked offline against the pinned issuer key.
  let credentialOk = false;
  if (input.credential !== undefined && input.credential !== null) {
    const issuer = (input.issuers || []).find((i) => isObject(input.credential) && i.key_id === String(input.credential.key_id));
    if (!issuer) {
      add("credential", "Telegram check", "fail", "the credential names an issuer key this desk does not know",
        "credential file");
      invalid = true;
    } else {
      const r = await checkCredential(input.credential, issuer);
      const src = `credential file, issuer key ${issuer.key_id} (epoch ${issuer.epoch}, ${issuer.label || issuer.url})`;
      if (!r.parsed) {
        add("credential", "Telegram check", "fail", r.error, "credential file");
        invalid = true;
      } else if (r.agent !== key) {
        add("credential", "Telegram check", "fail", `the credential is bound to another key (${r.agent})`, src);
        invalid = true;
      } else if (!r.signature_valid) {
        add("credential", "Telegram check", "fail", "the issuer's signature does not verify", src);
        invalid = true;
      } else {
        credentialOk = true;
        add("credential", "Telegram check", "pass", `${WORDING.credential}; bound to this key`, src);
      }
    }
  } else {
    add("credential", "Telegram check", "absent", "no credential file was given");
  }

  // 4–7. The issuer's live badge: registration, stake, deals, disputes.
  const live = input.live || {};
  let badge = null;
  if (live.badge === "not_allowed" || live.badge === undefined) {
    const why = live.badge === "not_allowed" ? "live lookups are off" : "not looked up";
    add("registration", "Registration", "unavailable", `${WORDING.liveUnavailable} (${why})`);
  } else if (!live.badge.ok) {
    add("registration", "Registration", "unavailable", `${WORDING.liveUnavailable} (${live.badge.error})`, live.badge.url);
  } else {
    badge = live.badge.badge;
    const level = isObject(badge) ? badge.level : null;
    if (!isObject(badge) || badge.agent !== key || !LEVELS.includes(level)) {
      add("registration", "Registration", "fail", "the issuer's reply is malformed or for another key", live.badge.url);
      badge = null;
    } else {
      const state = level === "verified" || level === "staked" ? "pass" : "fail";
      const text = level === "unknown" ? "level unknown: this key is not registered at the issuer"
        : level === "revoked" ? "level revoked: the registration was revoked"
          : `level ${level}: registered with ${WORDING.credential}`;
      add("registration", "Registration", state, text, `${live.badge.url} (issuer HTTPS reply, not signed)`);
      const s = badge.stake;
      if (s === null || s === undefined) {
        add("stake", "Stake", "unavailable", "the issuer has no stake source configured", live.badge.url);
      } else if (!s.found) {
        add("stake", "Stake", "absent", `no active stake on TON ${s.network || "(network not stated)"}`, live.badge.url);
      } else if (!s.network) {
        add("stake", "Stake", "fail", "a stake without a network label does not count", live.badge.url);
      } else {
        const amount = stakeAmount(badge);
        add("stake", "Stake", s.withdrawing ? "fail" : "pass",
          `${gram(amount > 0n ? amount : pyInt(s.amount_nanogram))} Gram ${s.withdrawing ? "withdrawing" : "active"} on TON ${s.network}`,
          `${live.badge.url}; contract ${s.contract}`);
      }
      const h = isObject(badge.history) ? badge.history : {};
      const deals = isObject(h.deals) ? h.deals : {};
      add("deals", "Deals", "pass", WORDING.deals(Number(deals.count || 0), Number(deals.with_staked_counterparty || 0)),
        live.badge.url);
      const disputes = isObject(h.disputes) ? h.disputes : {};
      const up = upheld(badge);
      add("disputes", "Disputes", up > 0 ? "fail" : "pass",
        `${Number(disputes.filed_against || 0)} filed against it, ${up} upheld`, live.badge.url);
    }
  }

  // 8. Concordium.
  let link = null;
  if (live.link === "not_allowed" || live.link === undefined) {
    add("concordium", "Concordium", "unavailable",
      `${WORDING.liveUnavailable} (${live.link === "not_allowed" ? "live lookups are off" : "not looked up"})`);
  } else {
    link = live.link;
    const lines = linkLines(link);
    const ok = link.binding_status === "Active" && link.badge_valid === true && !link.error;
    const state = ok ? "pass" : link.error ? "unavailable" : link.account === null ? "absent" : "fail";
    add("concordium", "Concordium", state, lines.map((ln) => ln.replace(/ \[source: .*\]$/, "")).join("; "),
      `Concordium ${link.network} Agent Registry, CIS-8 / CIS-8004`);
  }

  // 9. Tier, by the gate's own rules.
  const lookups = {
    policy,
    badgeLookup: async () => {
      if (!badge) {
        const err = new Error("badge not read");
        err.name = "LiveLookupUnavailable";
        throw err;
      }
      return badge;
    },
    linkLookup: link ? async () => link : async () => ({ network: policy.require_concordium, account: null,
      binding_status: null, badge: null, badge_valid: null, status: null, error: "live lookup unavailable" }),
    badgeUrl: live.badge && live.badge.url ? () => live.badge.url : null,
  };
  const ifProven = await tierIfProven(key, lookups);
  const tier = proven ? { ...ifProven, proven: true,
    evidence: [`request signature: valid for agent key ${key} [${SCHEME}]`, ...ifProven.evidence.slice(1)] }
    : toDict(decision(policy.anonymous, { agent: key, evidence: ["request signature: none (the key has not signed the desk's challenge)"] }));

  const signedOk = credentialOk || (badge && (badge.level === "verified" || badge.level === "staked"));
  const state = invalid ? "invalid" : proven && signedOk ? "verified"
    : checks.some((c) => c.state === "pass" && c.id !== "key") || carded ? "partial" : "unknown";
  return { state, key, checks, summary: summarize(state, checks), tier, tierIfProven: ifProven };
}

function summarize(state, checks) {
  const unavailable = checks.filter((c) => c.state === "unavailable").map((c) => c.label.toLowerCase());
  const tail = unavailable.length ? ` Not read: ${unavailable.join(", ")}.` : "";
  switch (state) {
    case "verified":
      return `Verified: the caller holds this key and tgtrust evidence backs it.${tail}`;
    case "partial":
      return `Partial: some evidence checks out, but not enough to call this agent verified.${tail}`;
    case "invalid":
      return `Invalid: evidence was presented that does not check out. Do not rely on this agent.${tail}`;
    default:
      return `Unknown: nothing about this key could be checked.${tail}`;
  }
}
