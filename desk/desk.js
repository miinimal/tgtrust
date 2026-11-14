// The Trust Desk page object: what is on the desk, and the three read-only operations the page and the agents
// share. The page's own buttons and site-actions.js call the same methods, so both follow one set of rules.
// Nothing here changes any record outside this browser tab.

import {
  assess, browserFetch, concordiumFromCard, DESK_POLICY, fetchBadge, NonceCache, parseAgentKey,
  readConcordiumLink, signRequest, WORDING,
} from "./verifier.js";

export const CONCORDIUM_ORIGIN = "https://agent-registry-mcp.concordium.com";
export const REPOSITORY = "https://github.com/miinimal/tgtrust";

const TEXT_MAX = 256 * 1024;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function parseJsonField(text, field, label) {
  if (text === undefined || text === null || String(text).trim() === "") return { value: null };
  if (String(text).length > TEXT_MAX) return { refusal: { ok: false, field, reason: `${label} is larger than 256 KB` } };
  try {
    return { value: JSON.parse(String(text)) };
  } catch {
    return { refusal: { ok: false, field, reason: `${label} is not valid JSON` } };
  }
}

function randomId(bytes = 18) {
  const raw = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...raw)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export class Desk {
  /**
   * :param issuers: the pinned issuers (desk/issuers.json "issuers").
   * :param fetchImpl: (method, url, body, headers) -> [status, text]; the browser default has a timeout.
   * :param clock: unix seconds.
   */
  constructor({ issuers, fetchImpl = null, clock = () => Date.now() / 1000 } = {}) {
    this.issuers = issuers || [];
    this.fetchImpl = fetchImpl || browserFetch();
    this.clock = clock;
    this.current = null;
    this.cases = new Map();
    this.results = new Map();
    this.liveAllowed = false;
    this.challengeId = randomId();
    this.version = 0;
    this.listeners = new Set();
  }

  onChange(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  changed() {
    this.version += 1;
    for (const listener of this.listeners) listener(this);
  }

  /** Origins a live lookup contacts, and why. The page shows these before the visitor allows them. */
  liveOrigins() {
    const origins = this.issuers.map((i) => ({ origin: new URL(i.url).origin, purpose: `read the public tgtrust badge of the key (${i.label})` }));
    origins.push({ origin: CONCORDIUM_ORIGIN, purpose: "read the key's Concordium Agent Registry binding and badge" });
    return origins;
  }

  /** The visitor's choice; off by default, kept for this tab only. */
  setLiveAllowed(allowed) {
    this.liveAllowed = Boolean(allowed);
    this.results.clear();
    this.changed();
  }

  /** What a key must sign to prove it is held by the caller: a tgtrust-req/v1 request for this desk. */
  challenge() {
    return { method: "POST", path: `/trust-desk/v1/challenge/${this.challengeId}`, body: "",
      scheme: "tgtrust-req/v1", validSeconds: 120 };
  }

  /**
   * Put an agent's evidence on the desk. Every field is optional text, as pasted; the key may also come from
   * the card. Refuses unreadable input without changing anything.
   *
   * :return: {ok: true, key} or {ok: false, reason, field}.
   */
  load({ key = "", card = "", credential = "", proof = "", source = "pasted" } = {}) {
    const parsed = {};
    for (const [field, text, label] of [["card", card, "The agent card"], ["credential", credential, "The credential file"],
      ["proof", proof, "The signature headers"]]) {
      const r = parseJsonField(text, field, label);
      if (r.refusal) return r.refusal;
      parsed[field] = r.value;
    }
    if (parsed.proof !== null && !isObject(parsed.proof)) {
      return { ok: false, field: "proof", reason: "The signature headers must be a JSON object of X-Tgtrust-* headers" };
    }
    let typed = null;
    if (String(key).trim()) {
      try {
        typed = parseAgentKey(key);
      } catch (err) {
        return { ok: false, field: "key", reason: `The agent key: ${err.message}` };
      }
    }
    const fromCard = parsed.card ? this.keyOfCard(parsed.card) : null;
    const agentKey = typed || fromCard;
    if (!agentKey) {
      return { ok: false, field: typed === null && parsed.card ? "card" : "key",
        reason: parsed.card ? "The agent card names no tgtrust agent key, so give the key itself" : "Give an agent key or an agent card" };
    }
    this.cases.set(agentKey, { key: typed, card: parsed.card, credential: parsed.credential, proof: parsed.proof,
      source, loadedAt: this.clock() });
    this.results.delete(agentKey);
    this.current = agentKey;
    this.changed();
    return { ok: true, key: agentKey };
  }

  keyOfCard(card) {
    const caps = isObject(card) && isObject(card.capabilities) ? card.capabilities.extensions : null;
    for (const ext of Array.isArray(caps) ? caps : []) {
      const k = isObject(ext) && isObject(ext.params) ? ext.params.agentKey : null;
      if (typeof k === "string" && /^[0-9a-fA-F]{64}$/.test(k)) return k.toLowerCase();
    }
    const k = isObject(card) && isObject(card.tgtrust) ? card.tgtrust.agent_key : null;
    return typeof k === "string" && /^[0-9a-fA-F]{64}$/.test(k) ? k.toLowerCase() : null;
  }

  /** Make a fresh demo agent in this browser and have it sign the challenge. It is not registered anywhere. */
  async makeDemoAgent() {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const hex = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
    const c = this.challenge();
    const headers = await signRequest(pair.privateKey, hex, c.method, c.path, new Uint8Array(0),
      { now: Math.trunc(this.clock()), nonce: randomId(18) });
    return this.load({ key: hex, proof: JSON.stringify(headers), source: "demo agent made in this browser" });
  }

  issuerFor(caseData) {
    const kid = isObject(caseData.credential) ? String(caseData.credential.key_id) : null;
    return this.issuers.find((i) => i.key_id === kid) || this.issuers[0] || null;
  }

  /**
   * Check one key: offline checks on what is on the desk, plus live lookups when the visitor allowed them.
   *
   * :return: the assessment from verifier.assess, with what was looked up live.
   */
  async check(agentKey) {
    const key = parseAgentKey(agentKey);
    const caseData = this.cases.get(key) || { key, card: null, credential: null, proof: null, source: "key only" };
    const live = {};
    if (!this.liveAllowed) {
      live.badge = "not_allowed";
      live.link = "not_allowed";
    } else {
      const issuer = this.issuerFor(caseData);
      const fromCard = caseData.card ? concordiumFromCard(caseData.card) : null;
      const network = DESK_POLICY.require_concordium;
      [live.badge, live.link] = await Promise.all([
        issuer ? fetchBadge(issuer.url, key, this.fetchImpl) : Promise.resolve({ ok: false, url: null, error: "no issuer pinned" }),
        readConcordiumLink(key, network, this.fetchImpl),
      ]);
      if (fromCard && fromCard.network && fromCard.network !== network) {
        live.cardLink = await readConcordiumLink(key, fromCard.network, this.fetchImpl);
      }
    }
    const c = this.challenge();
    const proof = caseData.proof ? { method: c.method, path: c.path, headers: caseData.proof, body: new Uint8Array(0),
      nonces: new NonceCache(120) } : null;
    // A key that came only from a card stays a claim: do not also list it as a key the visitor typed.
    const typedKey = caseData.key || (caseData.card ? null : key);
    const result = await assess({ key: typedKey, card: caseData.card, credential: caseData.credential, proof,
      issuers: this.issuers, now: this.clock(), live: { badge: live.badge, link: live.link } });
    result.source = caseData.source;
    result.cardLink = live.cardLink || null;
    result.checkedAt = Math.trunc(this.clock());
    this.results.set(key, result);
    this.changed();
    return result;
  }

  /** The same result as check(), shaped for the agents: short, with every source named. */
  async checkForAgent(agentKey) {
    const r = await this.check(agentKey);
    const extra = r.cardLink ? [{ name: `Concordium ${r.cardLink.network} (named by the card)`,
      state: r.cardLink.badge_valid && r.cardLink.binding_status === "Active" ? "pass" : r.cardLink.error ? "unavailable" : "fail",
      text: `binding ${r.cardLink.binding_status || "none"}, badge ${r.cardLink.badge || "none"} ${r.cardLink.badge_valid ? "valid" : "not valid"}`,
      source: `Concordium ${r.cardLink.network} Agent Registry` }] : [];
    return {
      ok: true, key: r.key, state: r.state, summary: r.summary,
      checks: [...r.checks.map((c) => ({ name: c.label, state: c.state, text: c.text, source: c.source })), ...extra],
      live: this.liveAllowed ? "allowed by the visitor for this tab" : "not allowed by the visitor: live lookup unavailable",
      evidenceSource: r.source,
    };
  }

  /** The tier the desk's published policy gives this key now, and once it signs the challenge. */
  async recommend(agentKey) {
    const key = parseAgentKey(agentKey);
    const r = this.results.get(key) || (await this.check(key));
    return {
      ok: true, key,
      tier: r.tier.tier, tierIfProven: r.tierIfProven.tier,
      reasons: r.tier.proven ? r.tier.evidence : [...r.tier.evidence, ...r.tierIfProven.evidence.slice(1).map((e) => `if proven: ${e}`)],
      policy: { minStakeGram: DESK_POLICY.min_stake_nanogram / 1e9, maxUpheldDisputes: DESK_POLICY.max_upheld_disputes,
        concordiumNetwork: DESK_POLICY.require_concordium, units: "the calling API's own smallest unit" },
      note: "A recommendation from evidence; the calling site decides and moves no money through Trust Desk.",
    };
  }

  /** Plain JSON copy of what is on the desk. */
  getState() {
    const current = this.current ? this.cases.get(this.current) : null;
    const result = this.current ? this.results.get(this.current) : null;
    return {
      currentKey: this.current,
      onDesk: current ? {
        card: current.card ? "given" : "none", credential: current.credential ? "given" : "none",
        signature: current.proof ? "given" : "none", source: current.source,
      } : null,
      lastResult: result ? { state: result.state, summary: result.summary, tier: result.tier.tier.name } : null,
      liveLookups: this.liveAllowed ? "allowed for this tab" : "off",
      liveOrigins: this.liveOrigins(),
      issuers: this.issuers.map((i) => ({ keyId: i.key_id, epoch: i.epoch, url: i.url, label: i.label })),
      challenge: this.challenge(),
      wording: WORDING.credential,
      repository: REPOSITORY,
      cannotDo: ["move or hold money", "check a person's identity", "contact the agent", "change any issuer record"],
    };
  }
}
