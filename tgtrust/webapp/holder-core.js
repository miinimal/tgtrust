// Holder flow of the tgtrust Mini App, without any page code, so the same functions run in the
// browser and in the tests (Node): prepare a blinded request, ask the issuer, unblind, register.
//
// Nothing here talks to anything except the issuer service passed in as `api`. The only values that
// ever leave the device are: Telegram init data + the blinded request (to /issue), and, when the
// holder chooses to register from the page, the finished credential + agent public key (to /register).
//
// Author: Aleksandr Shcherbakov (@miinimal), MINIMALCULT.

import {
  SCHEME, BlindRsaError, agentToken, b64urlDecode, b64urlEncode, bindMessage, blind, credentialMessage,
  finalize, fromHex, keyId, parsePublicKey, toHex,
} from "./blindrsa.js";

export const PENDING_KEY = "tgtrust.holder.pending.v1";
export const CREDENTIAL_FORMAT = "tgtrust-credential/v1";

export class HolderError extends Error {
  constructor(code, status = 0) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

// ---------- issuer API ----------

/** `base` is the service URL ending in /v1/. `fetchImpl` defaults to the platform fetch. */
export function createApi(base, fetchImpl = (...a) => fetch(...a)) {
  const root = String(base).replace(/\/*$/, "/");
  return async function call(method, path, body) {
    let response;
    try {
      response = await fetchImpl(root + path, {
        method,
        headers: body === undefined ? {} : { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } catch (err) {
      throw new HolderError("network");
    }
    let payload = null;
    try { payload = await response.json(); } catch (err) { payload = null; }
    if (!response.ok) {
      const detail = payload && payload.detail;
      const code = detail && typeof detail === "object" && !Array.isArray(detail) && typeof detail.code === "string"
        ? detail.code : (response.status === 422 ? "invalid_request" : "error");
      throw new HolderError(code, response.status);
    }
    if (payload === null || typeof payload !== "object") throw new HolderError("bad_response", response.status);
    return payload;
  };
}

/** Load the issuer description and refuse anything this page cannot verify itself. */
export async function loadIssuer(api) {
  const info = await api("GET", "issuer");
  if (info.scheme !== SCHEME) throw new HolderError("unsupported_scheme");
  if (info.credential_prefix !== "tgtrust/v1/credential:") throw new HolderError("unsupported_scheme");
  let publicKey;
  try { publicKey = parsePublicKey(info.public_key_pem); } catch (err) { throw new HolderError("bad_issuer_key"); }
  const id = await keyId(publicKey);
  if (id !== info.key_id) throw new HolderError("bad_issuer_key");
  return { publicKey, keyId: id, epoch: String(info.epoch), requirePremium: info.require_premium === true };
}

// ---------- agent keys (Ed25519) ----------

const PKCS8_ED25519_PREFIX = fromHex("302e020100300506032b657004220420");

export async function ed25519Supported() {
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    return true;
  } catch (err) {
    return false;
  }
}

/** New agent key. Returns the 32-byte seed (the private key the agent runs with) and the public key. */
export async function generateAgentKey() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  if (pkcs8.length !== 48 || publicKey.length !== 32) throw new HolderError("agent_key_failed");
  return { seed: pkcs8.slice(16), publicKey };
}

async function signWithSeed(seed, message) {
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, 16);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, message));
}

export function parseAgentPublicKey(text) {
  const hex = String(text).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new HolderError("bad_agent_key");
  return fromHex(hex);
}

// ---------- the flow ----------

/**
 * Step 1 (local): build the blinded request for one agent key. The returned record is everything
 * needed to finish later, so it must be saved BEFORE the request is sent: the issuer serves one
 * request per Telegram account and epoch, and only this exact request can be asked again.
 */
export async function prepareRequest(issuer, agentPublicKey, { seed = null, now = Date.now() } = {}) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const token = await agentToken(agentPublicKey, salt);
  const { blindedMessage, inverse } = await blind(issuer.publicKey, credentialMessage(token));
  return {
    v: 1,
    key_id: issuer.keyId,
    epoch: issuer.epoch,
    mode: seed ? "new" : "own",
    agent: toHex(agentPublicKey),
    seed: seed ? toHex(seed) : null,
    salt: b64urlEncode(salt),
    token: b64urlEncode(token),
    blinded: b64urlEncode(blindedMessage),
    inverse: inverse.toString(16),
    signature: null,
    registered: false,
    created_at: Math.floor(now / 1000),
  };
}

/** Step 2 (network): send init data and the blinded request. Safe to repeat with the same record. */
export async function requestBlindSignature(api, initData, pending) {
  const answer = await api("POST", "issue", { init_data: initData, blinded_message: pending.blinded });
  if (typeof answer.blind_signature !== "string" || answer.key_id !== pending.key_id) throw new HolderError("bad_response");
  return answer.blind_signature;
}

/** Step 3 (local): unblind and verify. Returns the record with the finished signature filled in. */
export async function completeCredential(issuer, pending, blindSignature) {
  if (pending.key_id !== issuer.keyId) throw new HolderError("issuer_changed");
  let signature;
  try {
    signature = await finalize(issuer.publicKey, credentialMessage(b64urlDecode(pending.token)),
      b64urlDecode(blindSignature), BigInt("0x" + pending.inverse));
  } catch (err) {
    if (err instanceof BlindRsaError) throw new HolderError("bad_signature");
    throw err;
  }
  // The blinding secret is of no use once the signature exists; drop it from the record.
  return { ...pending, signature: b64urlEncode(signature), inverse: null, blinded: null };
}

/** The file the agent needs to register itself: nothing in it is secret on its own. */
export function credentialPackage(issuerUrl, pending) {
  if (!pending.signature) throw new HolderError("not_finished");
  return {
    format: CREDENTIAL_FORMAT,
    issuer: issuerUrl,
    key_id: pending.key_id,
    epoch: pending.epoch,
    agent_public_key: pending.agent,
    salt: pending.salt,
    token: pending.token,
    signature: pending.signature,
  };
}

/** Optional step 4 (network): register the agent from the page, only when its key was created here. */
export async function registerAgent(api, pending) {
  if (!pending.signature || !pending.seed) throw new HolderError("not_finished");
  const { challenge } = await api("POST", "challenge");
  if (typeof challenge !== "string") throw new HolderError("bad_response");
  const proof = await signWithSeed(fromHex(pending.seed), bindMessage(b64urlDecode(challenge), b64urlDecode(pending.token)));
  let badge;
  try {
    badge = await api("POST", "register", {
      token: pending.token,
      signature: pending.signature,
      agent_public_key: b64urlEncode(fromHex(pending.agent)),
      salt: pending.salt,
      challenge,
      agent_signature: b64urlEncode(proof),
    });
  } catch (err) {
    // Registered by an earlier attempt whose answer was lost: the registry already holds this agent.
    if (!(err instanceof HolderError) || err.code !== "already_registered") throw err;
    badge = await api("GET", "agents/" + pending.agent);
  }
  if (badge.agent !== pending.agent) throw new HolderError("bad_response");
  return { ...pending, registered: true };
}

// ---------- saved state ----------

/** `storage` is the browser storage or anything with getItem/setItem/removeItem; failures are not fatal to reads. */
export function loadPending(storage) {
  try {
    const record = JSON.parse(storage.getItem(PENDING_KEY) || "null");
    if (!record || record.v !== 1 || typeof record.token !== "string" || typeof record.agent !== "string") return null;
    if (!record.signature && (typeof record.blinded !== "string" || typeof record.inverse !== "string")) return null;
    return record;
  } catch (err) {
    return null;
  }
}

/** Throws when the record cannot be saved: the caller must not send a request it could not save. */
export function savePending(storage, record) {
  try {
    storage.setItem(PENDING_KEY, JSON.stringify(record));
  } catch (err) {
    throw new HolderError("storage_unavailable");
  }
  if (!loadPending(storage)) throw new HolderError("storage_unavailable");
}

export function clearPending(storage) {
  try { storage.removeItem(PENDING_KEY); } catch (err) { /* nothing to clear */ }
}
