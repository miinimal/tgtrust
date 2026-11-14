// RSA blind signatures in the browser: RFC 9474, variant RSABSSA-SHA384-PSSZERO-Deterministic.
// Holder side only (blind, finalize, verify) plus the tgtrust token and binding messages.
// No dependencies: BigInt arithmetic and WebCrypto (browser or Node 20+). The byte formats match
// tgtrust/blind_rsa.py and tgtrust/registry.py; tests/test_webapp_crypto.py checks them against each other.
//
// Author: Aleksandr Shcherbakov (@miinimal), MINIMALCULT.

const HASH = "SHA-384";
const HASH_LEN = 48;
const enc = new TextEncoder();

export const CREDENTIAL_PREFIX = enc.encode("tgtrust/v1/credential:");
export const TOKEN_PREFIX = enc.encode("tgtrust/v1/agent:");
export const BIND_PREFIX = enc.encode("tgtrust/v1/bind:");
export const SCHEME = "RSABSSA-SHA384-PSSZERO-Deterministic";

export class BlindRsaError extends Error {}

// ---------- bytes ----------

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

export function toHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new BlindRsaError("not a hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function b64urlEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new BlindRsaError("not base64url");
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function os2ip(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

export function i2osp(value, length) {
  if (value < 0n || value >> BigInt(8 * length) !== 0n) throw new BlindRsaError("integer too large");
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) { out[i] = Number(value & 0xffn); value >>= 8n; }
  return out;
}

function bitLength(value) {
  return value === 0n ? 0 : value.toString(2).length;
}

// ---------- modular arithmetic ----------

export function modPow(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

export function gcd(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

export function modInverse(value, modulus) {
  let [r0, r1] = [modulus, value % modulus];
  let [t0, t1] = [0n, 1n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [t0, t1] = [t1, t0 - q * t1];
  }
  if (r0 !== 1n) throw new BlindRsaError("value has no inverse");
  return ((t0 % modulus) + modulus) % modulus;
}

// Uniform integer in [2, n - 1], by rejection sampling on the bit length of n.
function randomBlind(n) {
  const bits = bitLength(n);
  const bytes = Math.ceil(bits / 8);
  const mask = 0xff >> (8 * bytes - bits);
  for (;;) {
    const buf = crypto.getRandomValues(new Uint8Array(bytes));
    buf[0] &= mask;
    const r = os2ip(buf);
    if (r >= 2n && r < n && gcd(r, n) === 1n) return r;
  }
}

// ---------- hashing ----------

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function sha384(bytes) {
  return new Uint8Array(await crypto.subtle.digest(HASH, bytes));
}

async function mgf1(seed, length) {
  const out = new Uint8Array(length);
  let at = 0;
  for (let counter = 0; at < length; counter++) {
    const block = await sha384(concat(seed, i2osp(BigInt(counter), 4)));
    out.set(block.subarray(0, Math.min(block.length, length - at)), at);
    at += block.length;
  }
  return out;
}

// EMSA-PSS-ENCODE (RFC 8017, 9.1.1) with an empty salt.
export async function emsaPssEncode(message, emBits) {
  const emLen = Math.ceil(emBits / 8);
  if (emLen < HASH_LEN + 2) throw new BlindRsaError("modulus too small for the encoding");
  const mHash = await sha384(message);
  const h = await sha384(concat(new Uint8Array(8), mHash));
  const db = new Uint8Array(emLen - HASH_LEN - 1);
  db[db.length - 1] = 0x01;
  const mask = await mgf1(h, db.length);
  for (let i = 0; i < db.length; i++) db[i] ^= mask[i];
  db[0] &= 0xff >> (8 * emLen - emBits);
  return concat(db, h, new Uint8Array([0xbc]));
}

// ---------- public key ----------

function readDer(bytes, at) {
  const tag = bytes[at];
  let len = bytes[at + 1];
  let head = 2;
  if (len & 0x80) {
    const count = len & 0x7f;
    if (count === 0 || count > 4) throw new BlindRsaError("unsupported DER length");
    len = 0;
    for (let i = 0; i < count; i++) len = len * 256 + bytes[at + 2 + i];
    head = 2 + count;
  }
  const start = at + head;
  const end = start + len;
  if (!(tag >= 0) || end > bytes.length) throw new BlindRsaError("truncated DER");
  return { tag, start, end };
}

const RSA_OID = "06092a864886f70d010101"; // rsaEncryption

/** Parse a PEM "PUBLIC KEY" (SubjectPublicKeyInfo) holding an RSA key. */
export function parsePublicKey(pem) {
  const body = String(pem).replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  let der;
  try {
    const raw = atob(body);
    der = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) der[i] = raw.charCodeAt(i);
  } catch (err) {
    throw new BlindRsaError("public key is not valid PEM");
  }
  const spki = readDer(der, 0);
  const algorithm = readDer(der, spki.start);
  const bitString = readDer(der, algorithm.end);
  if (spki.tag !== 0x30 || algorithm.tag !== 0x30 || bitString.tag !== 0x03 || der[bitString.start] !== 0) {
    throw new BlindRsaError("unexpected public key structure");
  }
  if (!toHex(der.subarray(algorithm.start, algorithm.end)).startsWith(RSA_OID)) {
    throw new BlindRsaError("public key is not RSA");
  }
  const rsa = readDer(der, bitString.start + 1);
  const nField = readDer(der, rsa.start);
  const eField = readDer(der, nField.end);
  if (rsa.tag !== 0x30 || nField.tag !== 0x02 || eField.tag !== 0x02) {
    throw new BlindRsaError("unexpected RSA key structure");
  }
  const n = os2ip(der.subarray(nField.start, nField.end));
  const e = os2ip(der.subarray(eField.start, eField.end));
  const bits = bitLength(n);
  if (bits < 2048 || (n & 1n) === 0n || e < 3n || (e & 1n) === 0n) throw new BlindRsaError("weak or malformed RSA key");
  return { n, e, bits, k: Math.ceil(bits / 8), der };
}

/** Same short identifier the service publishes: first 16 hex characters of SHA-256 over the DER key. */
export async function keyId(publicKey) {
  return toHex(await sha256(publicKey.der)).slice(0, 16);
}

// ---------- protocol ----------

/**
 * Blind `message` for signing. Returns the bytes to send to the issuer and the secret `inverse`
 * the holder keeps until `finalize`. `options.r` fixes the blinding factor (tests only).
 */
export async function blind(publicKey, message, options = {}) {
  const { n, e, bits, k } = publicKey;
  const m = os2ip(await emsaPssEncode(message, bits - 1));
  if (gcd(m, n) !== 1n) throw new BlindRsaError("invalid input");
  const r = options.r === undefined ? randomBlind(n) : options.r;
  if (r < 2n || r >= n || gcd(r, n) !== 1n) throw new BlindRsaError("invalid blinding factor");
  const blinded = (m * modPow(r, e, n)) % n;
  return { blindedMessage: i2osp(blinded, k), inverse: modInverse(r, n) };
}

/** Standard RSASSA-PSS verification (SHA-384, MGF1-SHA-384, salt length 0) by the platform's own code. */
export async function verify(publicKey, message, signature) {
  if (signature.length !== publicKey.k) return false;
  try {
    const key = await crypto.subtle.importKey("spki", publicKey.der, { name: "RSA-PSS", hash: HASH }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 0 }, key, signature, message);
  } catch (err) {
    return false;
  }
}

/** Unblind the issuer's answer into an ordinary PSS signature and check it twice before returning it. */
export async function finalize(publicKey, message, blindSignature, inverse) {
  const { n, e, bits, k } = publicKey;
  if (blindSignature.length !== k) throw new BlindRsaError("blind signature has wrong length");
  const z = os2ip(blindSignature);
  if (z >= n) throw new BlindRsaError("blind signature out of range");
  const s = (z * inverse) % n;
  const expected = os2ip(await emsaPssEncode(message, bits - 1));
  if (modPow(s, e, n) !== expected) throw new BlindRsaError("unblinded signature does not verify");
  const signature = i2osp(s, k);
  if (!(await verify(publicKey, message, signature))) throw new BlindRsaError("unblinded signature does not verify");
  return signature;
}

// ---------- tgtrust messages ----------

/** Token that binds a credential to one agent key: SHA-256(prefix || agent key || salt). */
export async function agentToken(agentPublicKey, salt) {
  if (agentPublicKey.length !== 32 || salt.length !== 16) throw new BlindRsaError("agent key must be 32 bytes and salt 16 bytes");
  return sha256(concat(TOKEN_PREFIX, agentPublicKey, salt));
}

export function credentialMessage(token) {
  return concat(CREDENTIAL_PREFIX, token);
}

export function bindMessage(challenge, token) {
  return concat(BIND_PREFIX, challenge, token);
}
