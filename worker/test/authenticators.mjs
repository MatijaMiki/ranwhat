/* Authenticators, for the Worker's tests: a CBOR encoder, ES256, RS256 and
 * Ed25519 keys made by node:crypto, and the clientDataJSON and
 * authenticatorData a browser and an authenticator would hand back, so
 * that webauthn.test.mjs can break them one thing at a time and
 * passkeys.test.mjs can register and sign in with them end to end.
 */
import { createHash, generateKeyPairSync, sign } from "node:crypto";

export const ORIGIN = "https://account.ranwhat.com";
export const RP = "account.ranwhat.com";
export const UP = 0x01, UV = 0x04, BE = 0x08, BS = 0x10, AT = 0x40, ED = 0x80;

export const enc = new TextEncoder();
export const bytes = (b) => new Uint8Array(b);
export const b64 = (b) => Buffer.from(b).toString("base64url");
export const unb64 = (s) => bytes(Buffer.from(s, "base64url"));
export const sha256 = (b) => bytes(createHash("sha256").update(b).digest());
export const concat = (parts) => bytes(Buffer.concat(parts.map((p) => Buffer.from(p))));
export const be16 = (n) => [n >> 8, n & 255];
export const be32 = (n) => [n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255];

/* ---------- a CBOR encoder ---------- */

export function cbor(value) {
  const out = [];
  const head = (major, n) => {
    const m = major << 5;
    if (n < 24) out.push(m | n);
    else if (n < 0x100) out.push(m | 24, n);
    else if (n < 0x10000) out.push(m | 25, ...be16(n));
    else if (n < 0x100000000) out.push(m | 26, ...be32(n));
    else out.push(m | 27, ...be32(Math.floor(n / 0x100000000)), ...be32(n >>> 0));
  };
  const put = (v) => {
    if (v === false) out.push(0xf4);
    else if (v === true) out.push(0xf5);
    else if (v === null) out.push(0xf6);
    else if (typeof v === "number") (v >= 0 ? head(0, v) : head(1, -1 - v));
    else if (typeof v === "string") { const b = enc.encode(v); head(3, b.length); out.push(...b); }
    else if (v instanceof Uint8Array) { head(2, v.length); for (const x of v) out.push(x); }
    else if (Array.isArray(v)) { head(4, v.length); v.forEach(put); }
    else if (v instanceof Map) { head(5, v.size); for (const [k, x] of v) { put(k); put(x); } }
    else throw new Error(`cannot encode ${v}`);
  };
  put(value);
  return bytes(out);
}

/* ---------- keys ---------- */

export function es256() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  return {
    alg: -7, publicKey, privateKey,
    cose: new Map([[1, 2], [3, -7], [-1, 1], [-2, unb64(jwk.x)], [-3, unb64(jwk.y)]]),
    sign: (data) => bytes(sign("sha256", data, privateKey)),        // DER, as authenticators send it
  };
}

export function rs256(modulusLength = 2048, publicExponent = 65537) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength, publicExponent });
  const jwk = publicKey.export({ format: "jwk" });
  return {
    alg: -257, publicKey, privateKey,
    cose: new Map([[1, 3], [3, -257], [-1, unb64(jwk.n)], [-2, unb64(jwk.e)]]),
    sign: (data) => bytes(sign("sha256", data, privateKey)),
  };
}

export function ed25519() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  return {
    alg: -8, publicKey, privateKey,
    cose: new Map([[1, 1], [3, -8], [-1, 6], [-2, unb64(jwk.x)]]),
    sign: (data) => bytes(sign(null, data, privateKey)),
  };
}

/* ---------- what a browser and an authenticator hand back ---------- */

/* challenge: bytes, or base64url as the server sent it. */
export function clientData({ type, challenge, origin = ORIGIN, extra = {} }) {
  const text = typeof challenge === "string" ? challenge : b64(challenge);
  return enc.encode(JSON.stringify({ type, challenge: text, origin, crossOrigin: false, ...extra }));
}

export function authData({ rpId = RP, flags, signCount = 0, credential = null, extensions = null, tail = [] }) {
  const parts = [sha256(enc.encode(rpId)), [flags], be32(signCount)];
  if (credential) {
    parts.push(credential.aaguid || new Uint8Array(16), be16(credential.id.length), credential.id,
      credential.key || cbor(credential.cose));
  }
  if (extensions) parts.push(cbor(extensions));
  parts.push(tail);
  return concat(parts);
}
