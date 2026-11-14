// Registers the operator desk's operations with the agent runtime.
import { App } from "./app.js";

const REQUEST_ID = {
  type: "string",
  minLength: 4,
  maxLength: 40,
  description: "The request id shown in the queue, from website_inspect_caller.",
};

export class SiteActions {
  static registerActions(actions) {
    actions.register(SiteActions.inspectAction());
    actions.register(SiteActions.serveAction());
  }

  static inspectAction() {
    return {
      name: "inspect_caller",
      description: "Read the request in the queue and check its tgtrust-req/v1 signature in this browser: request id, caller key, whether the key is proven, the gate's tier from what this page could read (it does not read the issuer), the evidence lines, and Trust Desk's page link. Reads only.",
      effect: "read",
      inputSchema: { type: "object", additionalProperties: false, properties: {} },
      execute: async () => {
        const r = App.api.request;
        if (!r) return { ok: false, reason: "the queue is empty" };
        return App.api.inspect(r.id);
      },
    };
  }

  static serveAction() {
    return {
      name: "serve_request",
      description: "Serve the request in the queue on prepay or credit. The browser asks the operator to confirm first. Refused when the tier from website_inspect_caller does not allow those terms. Returns the receipt.",
      effect: "irreversible",
      timeoutMs: 4000,
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["requestId", "terms"],
        properties: {
          requestId: REQUEST_ID,
          terms: { type: "string", enum: ["prepay", "credit"], description: "prepay, or credit when the tier allows it." },
        },
      },
      execute: (args) => App.api.serve(args),
    };
  }
}

export const registerActions = SiteActions.registerActions;
