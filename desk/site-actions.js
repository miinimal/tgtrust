// Registers Trust Desk's operations with the agent runtime. agent-manifest.json loads this module through
// "actions.module"; the names in "actions.agentTools" become model tools called website_<name>.
// All three are read-only: they read the evidence on the desk and, when the visitor allowed it, public
// lookups. None of them changes anything, here or anywhere else.
import { App } from "./app.js";

const KEY_SCHEMA = {
  type: "string",
  minLength: 64,
  maxLength: 64,
  description: "The agent's Ed25519 public key, 64 hexadecimal characters, exactly as the visitor or website_get_desk gave it.",
};

/** Wrap a desk call so bad input comes back as a refusal, never as a throw (a throw would read as "unknown"). */
async function refuseBadKey(run, args) {
  if (!/^[0-9a-fA-F]{64}$/.test(args.agentKey)) {
    return { ok: false, field: "agentKey", reason: "an agent key is 64 hexadecimal characters" };
  }
  return run(args.agentKey);
}

export class SiteActions {
  static registerActions(actions) {
    actions.register(SiteActions.getDeskAction());
    actions.register(SiteActions.checkAgentAction());
    actions.register(SiteActions.recommendLimitAction());
  }

  static getDeskAction() {
    return {
      name: "get_desk",
      description: "Read what is on the desk now: the current agent key, which evidence was given (card, credential, signature), the last result, whether the visitor allowed live lookups and to which origins, the pinned issuers, the challenge a key must sign, and what this site cannot do.",
      effect: "read",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      execute: () => App.desk.getState(),
    };
  }

  static checkAgentAction() {
    return {
      name: "check_agent",
      description: "Check the tgtrust evidence for one agent key: the agent card's claim, the key's signature over the desk's challenge, the credential against the pinned issuer key (offline), and, only if the visitor allowed live lookups, the issuer's badge (registration, stake with network, co-signed deal records, disputes) and the Concordium binding. Returns state (verified, partial, unknown or invalid), summary and one entry per check with its source. Reads only.",
      effect: "read",
      timeoutMs: 30_000,
      inputSchema: { type: "object", additionalProperties: false, required: ["agentKey"], properties: { agentKey: KEY_SCHEMA } },
      execute: (args) => refuseBadKey((key) => App.desk.checkForAgent(key), args),
    };
  }

  static recommendLimitAction() {
    return {
      name: "recommend_limit",
      description: "The limit tier the desk's published policy (the rules of tgtrust.gate) gives one agent key: tier now, tierIfProven (once the key signs the desk's challenge), the reasons, and the policy's thresholds. Amounts are in the calling API's own smallest unit. Reads only; moves no money.",
      effect: "read",
      timeoutMs: 30_000,
      inputSchema: { type: "object", additionalProperties: false, required: ["agentKey"], properties: { agentKey: KEY_SCHEMA } },
      execute: (args) => refuseBadKey((key) => App.desk.recommend(key), args),
    };
  }
}

export const registerActions = SiteActions.registerActions;
