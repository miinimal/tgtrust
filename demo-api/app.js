// The paid API operator desk: one incoming agent request at a time. The page's buttons and the agent's site
// actions call these same methods. Nothing here calls a real API or moves money.
import { decide, NonceCache, signRequest } from "./vendor/verifier.js";

export const TRUST_DESK_PAGE = "https://miinimal.github.io/tgtrust/";
const PATH = "/v1/report?id=42";

function randomId(bytes = 18) {
  const raw = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...raw)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export class DemoApi {
  constructor({ clock = () => Date.now() / 1000 } = {}) {
    this.clock = clock;
    this.request = null;
    this.served = [];
    this.serveCalls = 0;
    this.simulateTimeout = false;
    this.listeners = new Set();
    this.trustDeskPage = TRUST_DESK_PAGE;
  }

  onChange(listener) {
    this.listeners.add(listener);
  }

  changed() {
    for (const listener of this.listeners) listener(this);
  }

  /** A new agent sends a signed request for a paid report. Its key is made in this browser, registered nowhere. */
  async newRequest() {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const agent = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
    const now = Math.trunc(this.clock());
    const headers = await signRequest(pair.privateKey, agent, "GET", PATH, new Uint8Array(0), { now, nonce: randomId() });
    this.request = { id: `req-${randomId(6)}`, method: "GET", path: PATH, headers, agent, receivedAt: now,
      price: "0.10 USDC per report (demo price)" };
    this.inspection = null;
    this.changed();
    return this.request;
  }

  /** Check the caller's signature here and apply the gate's rules to what this page can read. */
  async inspect(requestId) {
    const r = this.request;
    if (!r || r.id !== requestId) return { ok: false, field: "requestId", reason: "no request with that id is in the queue" };
    const decision = await decide({ method: r.method, path: r.path, headers: r.headers, body: new Uint8Array(0) }, {
      now: Math.trunc(this.clock()),
      nonces: new NonceCache(120),
      badgeLookup: async () => {
        const err = new Error("this demo does not read the issuer");
        err.name = "NotRead";
        throw err;
      },
      badgeUrl: null,
    });
    this.inspection = { ok: true, requestId, agent: r.agent, path: r.path, price: r.price, proven: decision.proven,
      tier: decision.tier, evidence: decision.evidence, trustDeskPage: this.trustDeskPage };
    this.changed();
    return this.inspection;
  }

  /** The read-only check serve() runs first; the confirmation dialog runs it too. */
  check({ requestId, terms }) {
    const r = this.request;
    if (!r || r.id !== requestId) return { ok: false, field: "requestId", reason: "no request with that id is in the queue" };
    if (this.served.some((s) => s.requestId === requestId)) return { ok: false, field: "requestId", reason: "this request was already served" };
    const tier = this.inspection && this.inspection.requestId === requestId ? this.inspection.tier : null;
    if (!tier) return { ok: false, field: "requestId", reason: "inspect the caller first" };
    if (!tier.allowed) return { ok: false, field: "terms", reason: `tier ${tier.name} is denied` };
    if (terms === "credit" && tier.prepay) return { ok: false, field: "terms", reason: `tier ${tier.name} is prepay only` };
    return { ok: true, request: r, tier };
  }

  /** Mark the request served. Irreversible on this page. With "simulate a timeout" on, it never answers. */
  async serve({ requestId, terms }) {
    this.serveCalls += 1;
    this.changed();
    const c = this.check({ requestId, terms });
    if (!c.ok) return c;
    if (this.simulateTimeout) {
      // The upstream API never answers: the runtime's timeout reports the outcome as unknown.
      await new Promise(() => {});
    }
    const receipt = { ok: true, requestId, terms, agent: c.request.agent, tier: c.tier.name,
      note: "Demo: marked served on this page; no API call or payment was made." };
    this.served.push(receipt);
    this.changed();
    return receipt;
  }
}

export class App {
  static api = new DemoApi();
}
