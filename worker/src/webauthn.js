/* Passkeys, part one: checking what a browser's WebAuthn calls hand back,
 * written here on WebCrypto alone, as oauth.js is. Nothing in this file
 * touches D1, a cookie or a page: the routes that issue challenges and keep
 * passkeys rows are another file's. Anything that is not exactly what a
 * check expects is refused, with a PasskeyRefused whose `why` says which
 * check it failed.
 *
 * What is read.
 *   CBOR    only as much as WebAuthn uses (decodeCbor): unsigned and
 *           negative integers, byte and text strings, arrays, maps keyed by
 *           integers or text, and false, true and null, every one with a
 *           definite length. Tags, floats, undefined, indefinite lengths,
 *           reserved encodings, a duplicate map key, a length longer than
 *           what is left, nesting deeper than MAX_DEPTH, more than
 *           MAX_ITEMS entries in all, and any byte after the item are
 *           refused. Nothing is allocated before its bytes are known to be
 *           there.
 *   authenticatorData (parseAuthData): the rpId hash, the flags, the
 *           signature counter and, when AT says one is attached, the new
 *           credential: its AAGUID, id and COSE public key.
 *   COSE keys (coseKey): ES256 (P-256), RS256 (2048 to 4096 bits, exponent
 *           65537) and EdDSA (Ed25519), which is every key passkeys and
 *           security keys make; any other algorithm, and a key carrying a
 *           private part, is refused.
 *
 * Registering (verifyRegistration). clientDataJSON must say webauthn.create,
 * carry the challenge we issued (compared in constant time), come from
 * exactly https://account.ranwhat.com and not from inside another site's
 * frame. The authenticator data must be for the rpId account.ranwhat.com,
 * with user presence, user verification (the device's PIN or biometric,
 * not a touch alone) and a credential attached.
 *
 * Attestation. The account asks for none and trusts none: a passkey is as
 * good as the signed-in session that adds it, not as good as its maker, so
 * nothing would be done with a verified statement. fmt 'none' must carry an
 * empty statement. A browser may still pass on another registered format
 * (packed self-attestation, in particular, is what the spec lets a client
 * keep when none was asked for); those are accepted as 'none'-equivalent:
 * the statement is decoded under the same limits and then ignored, never
 * verified, and nothing is returned from it. An fmt that is not a
 * registered WebAuthn format is refused.
 *
 * Signing in (verifyAssertion). The same checks on clientDataJSON (now
 * webauthn.get) and on the authenticator data, which must not attach a
 * credential, then the signature over authenticatorData || SHA-256 of
 * clientDataJSON under the key stored at registration. Then the counter:
 * once a passkey has reported a count above zero, every use must report a
 * higher one, and one that stands still, goes back or falls to zero means
 * two copies of the key may exist and is refused. Passkeys that always say
 * 0 (synced ones usually do) are not held to it.
 *
 * Stored. The public key is kept as the COSE bytes the authenticator sent,
 * base64url, which say their own algorithm and are checked again whenever
 * they are used; the credential id as base64url too, the passkeys table's
 * id.
 */
import { ACCOUNT_HOST, ACCOUNT_ORIGIN } from "./accounts.js";
import { same } from "./list.js";
import { b64url } from "./session.js";

export const RP_ID = ACCOUNT_HOST;
export const RP_ORIGIN = ACCOUNT_ORIGIN;

/* The COSE algorithms accepted, as WebAuthn numbers them, in the order the
   registration options will list them. */
export const ES256 = -7;
export const EDDSA = -8;
export const RS256 = -257;
export const ALGORITHMS = [ES256, EDDSA, RS256];

export const MAX_DEPTH = 8;            // CBOR nesting; WebAuthn needs four at most
export const MAX_ITEMS = 256;          // CBOR array and map entries in one item, in all
const MAX_CLIENT_DATA = 4096;          // clientDataJSON, bytes
const MAX_ATTESTATION = 16384;         // an attestation object, certificates and all
const MAX_AUTH_DATA = 4096;            // authenticatorData from a sign-in
const MAX_COSE_KEY = 2048;             // a stored public key; RSA 4096 needs about 530
const MAX_SIGNATURE = 1024;            // RSA 4096 signs in 512
const MAX_CREDENTIAL_ID = 1023;        // the spec's own limit
const MIN_CHALLENGE = 16;
const MAX_CHALLENGE = 64;

/* The attestation statement formats in the WebAuthn registry. Every one but
   'none' is taken as 'none' (see above). */
const FORMATS = new Set(["none", "packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "apple"]);

/* The authenticator data flags. */
const UP = 0x01, UV = 0x04, BE = 0x08, BS = 0x10, AT = 0x40, ED = 0x80;

const enc = new TextEncoder();
const utf8 = () => new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export class PasskeyRefused extends Error {
  constructor(why) {
    super(`passkey refused: ${why}`);
    this.why = why;
  }
}

const refuse = (why) => { throw new PasskeyRefused(why); };

/* ---------- bytes ---------- */

const B64URL = /^[A-Za-z0-9_-]*$/;

/* Base64url without padding, as WebAuthn and the browser write it, and
   only the one way of writing each value. */
function fromB64url(text, max, why) {
  if (text.length > Math.ceil(max * 4 / 3) || !B64URL.test(text) || text.length % 4 === 1) refuse(why);
  const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
  if (b64url(bytes) !== text) refuse(why);
  return bytes;
}

/* A binary input: bytes, an ArrayBuffer, or base64url text. */
function binary(value, max, why) {
  let bytes;
  if (typeof value === "string") bytes = fromB64url(value, max, why);
  else if (value instanceof Uint8Array) bytes = new Uint8Array(value);   // a copy, and never a Buffer
  else if (value instanceof ArrayBuffer) bytes = new Uint8Array(value);
  else refuse(why);
  if (bytes.length === 0 || bytes.length > max) refuse(why);
  return bytes;
}

/* Equal bytes, in time that depends on the length only. */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const digest = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

/* ---------- CBOR ---------- */

/* The item at bytes[offset] and where it ends: for a CBOR item that other
   bytes follow, as the credential key in authenticatorData is. */
export function decodeCborPrefix(input, offset = 0, { maxDepth = MAX_DEPTH, maxItems = MAX_ITEMS } = {}) {
  if (!(input instanceof Uint8Array)) refuse("cbor");
  const bytes = input;
  let at = offset;
  let items = 0;
  const need = (n) => { if (n > bytes.length - at) refuse("cbor"); };
  const byte = () => { need(1); return bytes[at++]; };

  /* The argument of a head, at most 2^53 - 1. */
  const argument = (info) => {
    if (info < 24) return info;
    if (info === 24) return byte();
    if (info === 25) { need(2); const v = bytes[at] * 0x100 + bytes[at + 1]; at += 2; return v; }
    if (info === 26) { need(4); const v = word(at); at += 4; return v; }
    if (info === 27) {
      need(8);
      const high = word(at), low = word(at + 4);
      at += 8;
      if (high > 0x1fffff) refuse("cbor");
      return high * 0x100000000 + low;
    }
    return refuse("cbor");               // 28 to 30 are reserved, 31 is an indefinite length
  };
  const word = (i) => bytes[i] * 0x1000000 + bytes[i + 1] * 0x10000 + bytes[i + 2] * 0x100 + bytes[i + 3];

  /* Room for n entries of at least `each` bytes, before any is read. */
  const entries = (n, each) => {
    items += n;
    if (items > maxItems) refuse("cbor");
    need(n * each);
  };

  const item = (depth) => {
    const head = byte();
    const major = head >> 5;
    const info = head & 31;
    if (major === 7) {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      return refuse("cbor");             // undefined, other simple values, floats and break
    }
    if (major === 6) return refuse("cbor");  // tags
    const n = argument(info);
    switch (major) {
      case 0:
        return n;
      case 1: {
        const v = -1 - n;
        if (!Number.isSafeInteger(v)) refuse("cbor");
        return v;
      }
      case 2: {
        need(n);
        const v = bytes.slice(at, at + n);
        at += n;
        return v;
      }
      case 3: {
        need(n);
        let v;
        try {
          v = utf8().decode(bytes.subarray(at, at + n));
        } catch {
          refuse("cbor");
        }
        at += n;
        return v;
      }
      case 4: {
        if (depth >= maxDepth) refuse("cbor");
        entries(n, 1);
        const v = [];
        for (let i = 0; i < n; i++) v.push(item(depth + 1));
        return v;
      }
      default: {                          // 5, a map
        if (depth >= maxDepth) refuse("cbor");
        entries(n, 2);
        const v = new Map();
        for (let i = 0; i < n; i++) {
          const key = item(depth + 1);
          if ((typeof key !== "number" && typeof key !== "string") || v.has(key)) refuse("cbor");
          v.set(key, item(depth + 1));
        }
        return v;
      }
    }
  };

  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.length) refuse("cbor");
  const value = item(0);
  return { value, end: at };
}

/* One CBOR item that is the whole of `bytes`. Maps come back as Map, so
   that the key 1 and the key "1" stay two keys. */
export function decodeCbor(bytes, limits = {}) {
  const { value, end } = decodeCborPrefix(bytes, 0, limits);
  if (end !== bytes.length) refuse("cbor");
  return value;
}

/* ---------- authenticator data ---------- */

export function parseAuthData(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 37) refuse("authenticator-data");
  const flags = bytes[32];
  if ((flags & BS) && !(flags & BE)) refuse("authenticator-data");
  const result = {
    rpIdHash: bytes.slice(0, 32),
    flags: {
      up: Boolean(flags & UP), uv: Boolean(flags & UV), be: Boolean(flags & BE),
      bs: Boolean(flags & BS), at: Boolean(flags & AT), ed: Boolean(flags & ED),
    },
    signCount: bytes[33] * 0x1000000 + bytes[34] * 0x10000 + bytes[35] * 0x100 + bytes[36],
    credential: null,
    extensions: null,
  };
  let at = 37;
  if (flags & AT) {
    if (bytes.length < at + 18) refuse("authenticator-data");
    const aaguid = bytes.slice(at, at + 16);
    const length = bytes[at + 16] * 0x100 + bytes[at + 17];
    at += 18;
    if (length === 0 || length > MAX_CREDENTIAL_ID || bytes.length < at + length) refuse("authenticator-data");
    const id = bytes.slice(at, at + length);
    at += length;
    if (at >= bytes.length) refuse("authenticator-data");
    const { end } = decodeCborPrefix(bytes, at);
    result.credential = { aaguid, id, publicKey: bytes.slice(at, end) };
    at = end;
  }
  if (flags & ED) {
    if (at >= bytes.length) refuse("authenticator-data");
    const { value, end } = decodeCborPrefix(bytes, at);
    if (!(value instanceof Map)) refuse("authenticator-data");
    result.extensions = value;
    at = end;
  }
  if (at !== bytes.length) refuse("authenticator-data");
  return result;
}

/* ---------- COSE keys ---------- */

const integer = (v) => Number.isSafeInteger(v);
const octets = (v, length) => v instanceof Uint8Array && (length === undefined || v.length === length);

/* Big-endian bytes without their leading zeros. */
function trimmed(v) {
  let i = 0;
  while (i < v.length - 1 && v[i] === 0) i++;
  return v.subarray(i);
}

/* A COSE_Key, as bytes, read into what WebCrypto needs to import it:
   { alg, format, data, algorithm }. */
export function coseKey(bytes) {
  const map = decodeCbor(bytes);
  if (!(map instanceof Map)) refuse("key");
  const kty = map.get(1);
  const alg = map.get(3);
  if (!integer(kty) || !integer(alg)) refuse("key");
  if (kty === 2 && alg === ES256) {
    const x = map.get(-2), y = map.get(-3);
    if (map.get(-1) !== 1 || !octets(x, 32) || !octets(y, 32) || map.has(-4)) refuse("key");
    const point = new Uint8Array(65);
    point[0] = 4;
    point.set(x, 1);
    point.set(y, 33);
    return { alg, format: "raw", data: point, algorithm: { name: "ECDSA", namedCurve: "P-256" } };
  }
  if (kty === 3 && alg === RS256) {
    const n = map.get(-1), e = map.get(-2);
    if (!octets(n) || !octets(e)) refuse("key");
    for (let label = -3; label >= -12; label--) if (map.has(label)) refuse("key");
    const modulus = trimmed(n), exponent = trimmed(e);
    const bits = (modulus.length - 1) * 8 + (32 - Math.clz32(modulus[0]));
    if (bits < 2048 || bits > 4096 || b64url(exponent) !== "AQAB") refuse("key");
    return {
      alg, format: "jwk",
      data: { kty: "RSA", n: b64url(modulus), e: "AQAB", alg: "RS256", ext: true },
      algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    };
  }
  if (kty === 1 && alg === EDDSA) {
    const x = map.get(-2);
    if (map.get(-1) !== 6 || !octets(x, 32) || map.has(-4)) refuse("key");
    return { alg, format: "raw", data: x, algorithm: { name: "Ed25519" } };
  }
  return refuse("algorithm");
}

/* The CryptoKey that verifies under a stored COSE key, with its alg. A
   point off the curve, or a key WebCrypto will not take, is refused. */
export async function importCoseKey(bytes) {
  const parsed = coseKey(bytes);
  try {
    return { alg: parsed.alg, key: await crypto.subtle.importKey(parsed.format, parsed.data, parsed.algorithm, false, ["verify"]) };
  } catch {
    if (parsed.alg !== EDDSA) refuse("key");
  }
  /* Workers before the standard name called Ed25519 this. */
  try {
    const algorithm = { name: "NODE-ED25519", namedCurve: "NODE-ED25519" };
    return { alg: parsed.alg, key: await crypto.subtle.importKey("raw", parsed.data, algorithm, false, ["verify"]) };
  } catch {
    return refuse("key");
  }
}

/* An ES256 signature as WebAuthn sends it, DER's SEQUENCE of two INTEGERs,
   as the 64 bytes of r || s that WebCrypto takes. Only DER's one encoding
   of each is read. */
export function rawSignature(der) {
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) refuse("signature");
  const out = new Uint8Array(64);
  let at = 2;
  for (const offset of [0, 32]) {
    if (at + 2 > der.length || der[at] !== 0x02) refuse("signature");
    const length = der[at + 1];
    at += 2;
    if (length < 1 || length > 33 || at + length > der.length) refuse("signature");
    let v = der.subarray(at, at + length);
    if (v[0] & 0x80) refuse("signature");                         // negative
    if (v[0] === 0) {
      if (length === 1 || !(v[1] & 0x80)) refuse("signature");    // zero, or a needless leading zero
      v = v.subarray(1);
    }
    if (v.length > 32) refuse("signature");
    out.set(v, offset + 32 - v.length);
    at += length;
  }
  if (at !== der.length) refuse("signature");
  return out;
}

async function signed({ key, alg }, signature, data) {
  let algorithm = { name: key.algorithm.name };
  if (alg === ES256) {
    signature = rawSignature(signature);
    algorithm = { name: "ECDSA", hash: "SHA-256" };
  } else if (alg === EDDSA && signature.length !== 64) {
    return false;
  }
  try {
    return await crypto.subtle.verify(algorithm, key, signature, data);
  } catch {
    return false;
  }
}

/* ---------- the checks both ceremonies make ---------- */

/* The expected challenge as base64url, whether given as bytes or text. */
function challengeText(expected) {
  const bytes = binary(expected, MAX_CHALLENGE, "challenge");
  if (bytes.length < MIN_CHALLENGE) refuse("challenge");
  return b64url(bytes);
}

function checkClientData(bytes, type, expectedChallenge, expectedOrigin) {
  let data;
  try {
    data = JSON.parse(utf8().decode(bytes));
  } catch {
    refuse("client-data");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) refuse("client-data");
  if (data.type !== type) refuse("type");
  if (typeof data.challenge !== "string" || !same(data.challenge, challengeText(expectedChallenge))) refuse("challenge");
  if (typeof expectedOrigin !== "string" || !expectedOrigin || data.origin !== expectedOrigin) refuse("origin");
  /* Not from inside another site's frame. */
  if ((data.crossOrigin !== undefined && data.crossOrigin !== false) || data.topOrigin !== undefined) refuse("origin");
  /* Token binding was never used here, so one the browser says is in use
     cannot be ours. */
  if (data.tokenBinding !== undefined &&
      (!data.tokenBinding || typeof data.tokenBinding !== "object" || data.tokenBinding.status === "present")) {
    refuse("client-data");
  }
}

async function checkAuthData(auth, rpId) {
  if (typeof rpId !== "string" || !rpId || !sameBytes(auth.rpIdHash, await digest(enc.encode(rpId)))) refuse("rp");
  if (!auth.flags.up) refuse("presence");
  if (!auth.flags.uv) refuse("verification");
}

/* ---------- registering ---------- */

/* A new passkey, once every check above holds:
   { credentialId, publicKey, alg, signCount, backupEligible, backedUp },
   the id and key as base64url. Inputs are bytes or base64url. */
export async function verifyRegistration({
  attestationObject, clientDataJSON, expectedChallenge, expectedOrigin = RP_ORIGIN, rpId = RP_ID,
} = {}) {
  checkClientData(binary(clientDataJSON, MAX_CLIENT_DATA, "client-data"), "webauthn.create",
    expectedChallenge, expectedOrigin);

  const attestation = decodeCbor(binary(attestationObject, MAX_ATTESTATION, "attestation"));
  if (!(attestation instanceof Map) || attestation.size !== 3) refuse("attestation");
  const fmt = attestation.get("fmt");
  const statement = attestation.get("attStmt");
  const authData = attestation.get("authData");
  if (typeof fmt !== "string" || !(statement instanceof Map) || !(authData instanceof Uint8Array)) refuse("attestation");
  if (!FORMATS.has(fmt) || (fmt === "none" && statement.size !== 0)) refuse("attestation");

  const auth = parseAuthData(authData);
  await checkAuthData(auth, rpId);
  if (!auth.flags.at || !auth.credential) refuse("authenticator-data");
  const { alg } = await importCoseKey(auth.credential.publicKey);

  return {
    credentialId: b64url(auth.credential.id),
    publicKey: b64url(auth.credential.publicKey),
    alg,
    signCount: auth.signCount,
    backupEligible: auth.flags.be,
    backedUp: auth.flags.bs,
  };
}

/* ---------- signing in ---------- */

/* A sign-in with a stored passkey, once every check above holds:
   { signCount, backupEligible, backedUp }, the count to store. publicKey
   is what verifyRegistration returned; storedSignCount the count stored. */
export async function verifyAssertion({
  authenticatorData, clientDataJSON, signature, publicKey, expectedChallenge,
  expectedOrigin = RP_ORIGIN, rpId = RP_ID, storedSignCount = 0,
} = {}) {
  const client = binary(clientDataJSON, MAX_CLIENT_DATA, "client-data");
  checkClientData(client, "webauthn.get", expectedChallenge, expectedOrigin);

  const data = binary(authenticatorData, MAX_AUTH_DATA, "authenticator-data");
  const auth = parseAuthData(data);
  if (auth.flags.at) refuse("authenticator-data");
  await checkAuthData(auth, rpId);

  const key = await importCoseKey(binary(publicKey, MAX_COSE_KEY, "key"));
  const message = new Uint8Array(data.length + 32);
  message.set(data);
  message.set(await digest(client), data.length);
  if (!await signed(key, binary(signature, MAX_SIGNATURE, "signature"), message)) refuse("signature");

  if (!integer(storedSignCount) || storedSignCount < 0 || storedSignCount > 0xffffffff) refuse("counter");
  if (storedSignCount > 0 && auth.signCount <= storedSignCount) refuse("counter");

  return { signCount: auth.signCount, backupEligible: auth.flags.be, backedUp: auth.flags.bs };
}
