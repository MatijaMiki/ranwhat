/* The WebAuthn verifier (webauthn.js) on its own: the CBOR decoder, the
 * authenticator data and COSE keys, and both ceremonies. Registrations and
 * assertions are built here as an authenticator would build them, with
 * ES256, RS256 and Ed25519 keys made by node:crypto and a CBOR encoder
 * written for the test, then broken one thing at a time.
 *
 *     node --test --test-timeout=60000 worker/test/webauthn.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";

const {
  ALGORITHMS, MAX_DEPTH, MAX_ITEMS, PasskeyRefused, RP_ID, RP_ORIGIN, coseKey, decodeCbor, decodeCborPrefix,
  importCoseKey, parseAuthData, rawSignature, verifyAssertion, verifyRegistration,
} = await import("../src/webauthn.js");

const ORIGIN = "https://account.ranwhat.com";
const RP = "account.ranwhat.com";
const UP = 0x01, UV = 0x04, BE = 0x08, BS = 0x10, AT = 0x40, ED = 0x80;

const enc = new TextEncoder();
const bytes = (b) => new Uint8Array(b);
const b64 = (b) => Buffer.from(b).toString("base64url");
const unb64 = (s) => bytes(Buffer.from(s, "base64url"));
const sha256 = (b) => bytes(createHash("sha256").update(b).digest());
const concat = (parts) => bytes(Buffer.concat(parts.map((p) => Buffer.from(p))));
const be16 = (n) => [n >> 8, n & 255];
const be32 = (n) => [n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255];

/* ---------- a CBOR encoder, for the test only ---------- */

function cbor(value) {
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

/* ---------- authenticators ---------- */

function es256() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  return {
    alg: -7, publicKey, privateKey,
    cose: new Map([[1, 2], [3, -7], [-1, 1], [-2, unb64(jwk.x)], [-3, unb64(jwk.y)]]),
    sign: (data) => bytes(sign("sha256", data, privateKey)),        // DER, as authenticators send it
  };
}

function rs256(modulusLength = 2048, publicExponent = 65537) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength, publicExponent });
  const jwk = publicKey.export({ format: "jwk" });
  return {
    alg: -257, publicKey, privateKey,
    cose: new Map([[1, 3], [3, -257], [-1, unb64(jwk.n)], [-2, unb64(jwk.e)]]),
    sign: (data) => bytes(sign("sha256", data, privateKey)),
  };
}

function ed25519() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  return {
    alg: -8, publicKey, privateKey,
    cose: new Map([[1, 1], [3, -8], [-1, 6], [-2, unb64(jwk.x)]]),
    sign: (data) => bytes(sign(null, data, privateKey)),
  };
}

const ES = es256();
const RS = rs256();
const ED25519 = ed25519();
const PAIRS = [["ES256", ES], ["RS256", RS], ["Ed25519", ED25519]];

const CHALLENGE = bytes(randomBytes(32));

function clientData({ type, challenge = CHALLENGE, origin = ORIGIN, extra = {} }) {
  return enc.encode(JSON.stringify({ type, challenge: b64(challenge), origin, crossOrigin: false, ...extra }));
}

function authData({ rpId = RP, flags, signCount = 0, credential = null, extensions = null, tail = [] }) {
  const parts = [sha256(enc.encode(rpId)), [flags], be32(signCount)];
  if (credential) {
    parts.push(credential.aaguid || new Uint8Array(16), be16(credential.id.length), credential.id,
      credential.key || cbor(credential.cose));
  }
  if (extensions) parts.push(cbor(extensions));
  parts.push(tail);
  return concat(parts);
}

/* What navigator.credentials.create() hands back, base64url, as the page
   will post it. */
function registration(pair, {
  challenge, origin, type = "webauthn.create", extra, rpId, flags = UP | UV | AT, signCount = 0,
  id = bytes(randomBytes(16)), fmt = "none", attStmt = new Map(), key, more = [], attestation,
} = {}) {
  const data = authData({ rpId, flags, signCount, credential: flags & AT || key ? { id, cose: pair.cose, key } : null });
  const object = attestation || new Map([["fmt", fmt], ["attStmt", attStmt], ["authData", data], ...more]);
  return {
    id,
    attestationObject: b64(object instanceof Uint8Array ? object : cbor(object)),
    clientDataJSON: b64(clientData({ type, challenge, origin, extra })),
  };
}

const expected = { expectedChallenge: b64(CHALLENGE), expectedOrigin: ORIGIN, rpId: RP };

async function registered(pair, options) {
  const r = registration(pair, options);
  return verifyRegistration({ attestationObject: r.attestationObject, clientDataJSON: r.clientDataJSON, ...expected });
}

/* What navigator.credentials.get() hands back, signed by `pair`. */
function assertion(pair, {
  challenge, origin, type = "webauthn.get", extra, rpId, flags = UP | UV, signCount = 1, signer = pair,
} = {}) {
  const client = clientData({ type, challenge, origin, extra });
  const data = authData({ rpId, flags, signCount });
  return { authenticatorData: data, clientDataJSON: client, signature: signer.sign(concat([data, sha256(client)])) };
}

const publicKeyOf = (pair) => b64(cbor(pair.cose));

const asserted = (pair, a, more = {}) =>
  verifyAssertion({ ...a, publicKey: publicKeyOf(pair), ...expected, storedSignCount: 0, ...more });

async function refused(promise, why) {
  await assert.rejects(promise, (e) => {
    assert.ok(e instanceof PasskeyRefused, `not a refusal: ${e && e.stack}`);
    assert.equal(e.why, why);
    return true;
  });
}

function refusedNow(fn, why) {
  assert.throws(fn, (e) => {
    assert.ok(e instanceof PasskeyRefused, `not a refusal: ${e && e.stack}`);
    assert.equal(e.why, why);
    return true;
  });
}

/* ---------- CBOR ---------- */

test("the decoder reads every type WebAuthn uses", () => {
  const value = new Map([
    [1, 2], [3, -7], [-1, 1], [-257, "RS256"], ["fmt", "none"], ["empty", new Map()],
    ["bytes", bytes([0, 1, 2, 255])], ["list", [0, -1, true, false, null, "é"]],
    ["nested", new Map([["deeper", [new Map([[2, bytes([9])]])]]])],
  ]);
  assert.deepEqual(decodeCbor(cbor(value)), value);
});

test("the decoder reads one, two, four and eight byte arguments", () => {
  for (const n of [0, 23, 24, 255, 256, 65535, 65536, 0xffffffff, 0x100000000, Number.MAX_SAFE_INTEGER]) {
    assert.equal(decodeCbor(cbor(n)), n);
    assert.equal(decodeCbor(cbor(-1 - Math.min(n, Number.MAX_SAFE_INTEGER - 1))), -1 - Math.min(n, Number.MAX_SAFE_INTEGER - 1));
  }
  const long = bytes(randomBytes(70000));
  assert.deepEqual(decodeCbor(cbor(long)), long);
});

test("the decoder keeps the key 1 and the key \"1\" apart", () => {
  const map = decodeCbor(cbor(new Map([[1, "number"], ["1", "text"]])));
  assert.equal(map.size, 2);
  assert.equal(map.get(1), "number");
  assert.equal(map.get("1"), "text");
});

test("the decoder refuses what WebAuthn never sends", () => {
  const cases = {
    "nothing": [],
    "an indefinite byte string": [0x5f, 0x41, 0x00, 0xff],
    "an indefinite text string": [0x7f, 0xff],
    "an indefinite array": [0x9f, 0x01, 0xff],
    "an indefinite map": [0xbf, 0x01, 0x02, 0xff],
    "a break": [0xff],
    "a tag": [0xc0, 0x60],
    "a tag with a one-byte number": [0xd8, 0x18, 0x41, 0x00],
    "a half float": [0xf9, 0x3c, 0x00],
    "a single float": [0xfa, 0x3f, 0x80, 0x00, 0x00],
    "a double float": [0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0],
    "undefined": [0xf7],
    "a small simple value": [0xf0],
    "a one-byte simple value": [0xf8, 0x20],
    "reserved additional information 28": [0x1c],
    "reserved additional information 29": [0x3d],
    "reserved additional information 30": [0x5e],
    "a duplicate key": [0xa2, 0x01, 0x00, 0x01, 0x01],
    "a duplicate text key": [0xa2, 0x61, 0x61, 0x00, 0x61, 0x61, 0x01],
    "a byte string key": [0xa1, 0x41, 0x00, 0x00],
    "a boolean key": [0xa1, 0xf5, 0x00],
    "an array key": [0xa1, 0x80, 0x00],
    "a map key": [0xa1, 0xa0, 0x00],
    "text that is not UTF-8": [0x62, 0xc3, 0x28],
    "a lone surrogate": [0x63, 0xed, 0xa0, 0x80],
    "a truncated argument": [0x19, 0x01],
    "a truncated byte string": [0x42, 0x00],
    "a truncated array": [0x82, 0x01],
    "a truncated map": [0xa1, 0x01],
    "a byte string four gigabytes long": [0x5a, 0xff, 0xff, 0xff, 0xff, 0x00],
    "a byte string with an eight-byte length": [0x5b, 0, 0, 0, 1, 0, 0, 0, 0, 0x00],
    "text with a huge length": [0x7a, 0x7f, 0xff, 0xff, 0xff, 0x61],
    "an array of 2^53 - 1 items": [0x9b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
    "a map of 65535 entries": [0xb9, 0xff, 0xff, 0x00, 0x00],
    "a map with more entries than bytes": [0xa8, 0x01, 0x02],
    "an integer above 2^53 - 1": [0x1b, 0x00, 0x20, 0, 0, 0, 0, 0, 0],
    "an integer of eight 0xff bytes": [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    "a negative integer below -2^53 + 1": [0x3b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    "a trailing byte": [0x01, 0x00],
    "a map and then more": [0xa0, 0xa0],
  };
  for (const [name, input] of Object.entries(cases)) {
    assert.throws(() => decodeCbor(bytes(input)), (e) => e instanceof PasskeyRefused && e.why === "cbor", name);
  }
});

test("the decoder refuses nesting deeper than its limit, and too many entries", () => {
  const nested = (levels) => bytes([...Array(levels).fill(0x81), 0x00]);
  assert.ok(Array.isArray(decodeCbor(nested(MAX_DEPTH))));
  refusedNow(() => decodeCbor(nested(MAX_DEPTH + 1)), "cbor");
  refusedNow(() => decodeCbor(nested(4), { maxDepth: 3 }), "cbor");
  refusedNow(() => decodeCbor(bytes([...Array(5000).fill(0xa1), 0x00])), "cbor");

  assert.equal(decodeCbor(cbor(Array(MAX_ITEMS).fill(0))).length, MAX_ITEMS);
  refusedNow(() => decodeCbor(cbor(Array(MAX_ITEMS + 1).fill(0))), "cbor");
  /* Counted across the whole item, not per container. */
  const spread = Array.from({ length: 4 }, () => Array(MAX_ITEMS / 4).fill(0));
  refusedNow(() => decodeCbor(cbor(spread)), "cbor");
});

test("decodeCborPrefix says where the item ends, and refuses a bad offset", () => {
  const input = concat([cbor(new Map([[1, 2]])), [0xff, 0xff]]);
  assert.deepEqual(decodeCborPrefix(input, 0), { value: new Map([[1, 2]]), end: 3 });
  refusedNow(() => decodeCborPrefix(input, input.length), "cbor");
  refusedNow(() => decodeCborPrefix(input, -1), "cbor");
  refusedNow(() => decodeCborPrefix([0x01]), "cbor");
});

/* ---------- authenticator data ---------- */

test("authenticator data: the rpId hash, flags, counter, credential and extensions", () => {
  const id = bytes(randomBytes(20));
  const aaguid = bytes(randomBytes(16));
  const data = authData({
    flags: UP | UV | BE | BS | AT | ED, signCount: 0x01020304,
    credential: { id, aaguid, cose: ES.cose }, extensions: new Map([["credProtect", 2]]),
  });
  const parsed = parseAuthData(data);
  assert.deepEqual(parsed.rpIdHash, sha256(enc.encode(RP)));
  assert.deepEqual(parsed.flags, { up: true, uv: true, be: true, bs: true, at: true, ed: true });
  assert.equal(parsed.signCount, 0x01020304);
  assert.deepEqual(parsed.credential.aaguid, aaguid);
  assert.deepEqual(parsed.credential.id, id);
  assert.deepEqual(parsed.credential.publicKey, cbor(ES.cose));
  assert.deepEqual(parsed.extensions, new Map([["credProtect", 2]]));

  const bare = parseAuthData(authData({ flags: UP, signCount: 0xffffffff }));
  assert.deepEqual(bare.flags, { up: true, uv: false, be: false, bs: false, at: false, ed: false });
  assert.equal(bare.signCount, 0xffffffff);
  assert.equal(bare.credential, null);
  assert.equal(bare.extensions, null);
});

test("authenticator data that does not add up is refused", () => {
  const id = bytes(randomBytes(16));
  const full = authData({ flags: UP | UV | AT, credential: { id, cose: ES.cose } });
  const cases = {
    "too short": full.slice(0, 36),
    "backed up without being backup eligible": authData({ flags: UP | UV | BS }),
    "AT without a credential": authData({ flags: UP | UV | AT }),
    "AT with a credential id longer than what is left": concat([full.slice(0, 37), new Uint8Array(16), [0x01, 0x00], id]),
    "a credential id of no bytes": authData({ flags: UP | UV | AT, credential: { id: new Uint8Array(0), cose: ES.cose } }),
    "a credential id over 1023 bytes": authData({ flags: UP | UV | AT, credential: { id: new Uint8Array(1024), cose: ES.cose } }),
    "a credential with no key": concat([full.slice(0, 37), new Uint8Array(16), be16(16), id]),
    "bytes after the key without ED": concat([full, [0xa0]]),
    "bytes after the header without AT or ED": concat([authData({ flags: UP | UV }), [0x00]]),
    "ED without extensions": authData({ flags: UP | UV | ED }),
    "extensions that are not a map": authData({ flags: UP | UV | ED, tail: cbor([1]) }),
    "bytes after the extensions": authData({ flags: UP | UV | ED, extensions: new Map(), tail: [0x00] }),
  };
  for (const [name, input] of Object.entries(cases)) {
    assert.throws(() => parseAuthData(input),
      (e) => e instanceof PasskeyRefused && ["authenticator-data", "cbor"].includes(e.why), name);
  }
  refusedNow(() => parseAuthData(authData({ flags: UP | UV | AT, credential: { id, cose: ES.cose }, tail: [0x9f] })),
    "authenticator-data");
});

/* ---------- COSE keys ---------- */

test("COSE keys: ES256, RS256 and Ed25519 import; nothing else does", async () => {
  for (const [, pair] of PAIRS) {
    const { alg, key } = await importCoseKey(cbor(pair.cose));
    assert.equal(alg, pair.alg);
    assert.equal(key.type, "public");
  }
  assert.deepEqual(ALGORITHMS, [-7, -8, -257]);

  const with_ = (pair, changes) => {
    const m = new Map(pair.cose);
    for (const [k, v] of changes) (v === undefined ? m.delete(k) : m.set(k, v));
    return cbor(m);
  };
  const algorithm = {
    "ES384": cbor(new Map([[1, 2], [3, -35], [-1, 2], [-2, new Uint8Array(48)], [-3, new Uint8Array(48)]])),
    "PS256": with_(RS, [[3, -37]]),
    "EC2 with RS256's alg": with_(ES, [[3, -257]]),
    "OKP with ES256's alg": with_(ED25519, [[3, -7]]),
    "an unknown kty": with_(ES, [[1, 4]]),
  };
  for (const [name, input] of Object.entries(algorithm)) {
    assert.throws(() => coseKey(input), (e) => e instanceof PasskeyRefused && e.why === "algorithm", name);
  }
  const key = {
    "not a map": cbor([1, 2]),
    "no alg": with_(ES, [[3, undefined]]),
    "no kty": with_(ES, [[1, undefined]]),
    "a text alg": with_(ES, [[3, "ES256"]]),
    "P-384 under ES256": with_(ES, [[-1, 2]]),
    "a short x": with_(ES, [[-2, new Uint8Array(31)]]),
    "a compressed y": with_(ES, [[-3, true]]),
    "an EC2 private key": with_(ES, [[-4, new Uint8Array(32)]]),
    "an RSA private exponent": with_(RS, [[-3, new Uint8Array(256)]]),
    "an RSA prime": with_(RS, [[-4, new Uint8Array(128)]]),
    "an RSA key with no e": with_(RS, [[-2, undefined]]),
    "an Ed448 curve": with_(ED25519, [[-1, 7]]),
    "an OKP private key": with_(ED25519, [[-4, new Uint8Array(32)]]),
  };
  for (const [name, input] of Object.entries(key)) {
    assert.throws(() => coseKey(input), (e) => e instanceof PasskeyRefused && e.why === "key", name);
  }
});

test("COSE keys: RSA below 2048 bits, or with an exponent other than 65537, is refused", async () => {
  const small = rs256(1024);
  await refused(importCoseKey(cbor(small.cose)), "key");
  const three = rs256(2048, 3);
  await refused(importCoseKey(cbor(three.cose)), "key");
  /* A leading zero on n is read past, not counted. */
  const padded = new Map(RS.cose);
  padded.set(-1, concat([[0], RS.cose.get(-1)]));
  assert.equal((await importCoseKey(cbor(padded))).alg, -257);
});

test("COSE keys: a point that is not on P-256 is refused", async () => {
  const off = new Map(ES.cose);
  const y = new Uint8Array(ES.cose.get(-3));
  y[31] ^= 1;
  off.set(-3, y);
  await refused(importCoseKey(cbor(off)), "key");
});

test("ES256 signatures: DER becomes r || s, and only strict DER is read", () => {
  for (let i = 0; i < 20; i++) {
    const data = randomBytes(40);
    const der = ES.sign(data);
    assert.ok(verify("sha256", data, { key: ES.publicKey, dsaEncoding: "ieee-p1363" }, rawSignature(der)));
  }
  const int = (v) => [0x02, v.length, ...v];
  const seq = (...parts) => bytes([0x30, parts.flat().length, ...parts.flat()]);
  const r = [0x01, ...new Uint8Array(31)];
  assert.equal(rawSignature(seq(int(r), int(r))).length, 64);
  const cases = {
    "a needless leading zero": seq(int([0, ...r]), int(r)),
    "a negative r": seq(int([0x80, ...new Uint8Array(31)]), int(r)),
    "a zero r": seq(int([0]), int(r)),
    "an r of 33 bytes": seq(int([0x01, ...new Uint8Array(32)]), int(r)),
    "a trailing byte": bytes([...seq(int(r), int(r)), 0]),
    "a wrong sequence length": bytes([0x30, 0x45, ...int(r), ...int(r)]),
    "not a sequence": bytes([0x31, 0x44, ...int(r), ...int(r)]),
    "a bit string for s": seq(int(r), [0x03, 32, ...r]),
    "an extra integer": seq(int(r), int(r), int([1])),
    "a raw r || s": bytes([...r, ...r]),
    "too short": bytes([0x30, 0x02, 0x02, 0x00]),
  };
  for (const [name, input] of Object.entries(cases)) {
    assert.throws(() => rawSignature(input), (e) => e instanceof PasskeyRefused && e.why === "signature", name);
  }
});

/* ---------- registering ---------- */

for (const [name, pair] of PAIRS) {
  test(`registration: a ${name} passkey is accepted, and signs in`, async () => {
    const r = registration(pair, { flags: UP | UV | AT | BE, signCount: 7 });
    const out = await verifyRegistration({ attestationObject: r.attestationObject, clientDataJSON: r.clientDataJSON, ...expected });
    assert.deepEqual(out, {
      credentialId: b64(r.id), publicKey: publicKeyOf(pair), alg: pair.alg, signCount: 7,
      backupEligible: true, backedUp: false,
    });
    const a = assertion(pair, { signCount: 8, flags: UP | UV | BE | BS });
    const used = await verifyAssertion({ ...a, publicKey: out.publicKey, ...expected, storedSignCount: out.signCount });
    assert.deepEqual(used, { signCount: 8, backupEligible: true, backedUp: true });
  });
}

test("registration: inputs may be bytes, ArrayBuffers or base64url, and the defaults are account.ranwhat.com", async () => {
  assert.equal(RP_ID, RP);
  assert.equal(RP_ORIGIN, ORIGIN);
  const r = registration(ES);
  const out = await verifyRegistration({
    attestationObject: unb64(r.attestationObject), clientDataJSON: unb64(r.clientDataJSON).buffer,
    expectedChallenge: CHALLENGE,
  });
  assert.equal(out.credentialId, b64(r.id));
  assert.equal(out.backedUp, false);
});

test("registration: another registered format counts as none, and its statement is never read", async () => {
  const attStmt = new Map([["alg", -7], ["sig", bytes(randomBytes(70))], ["x5c", [bytes(randomBytes(300))]]]);
  for (const fmt of ["packed", "tpm", "fido-u2f", "android-key", "android-safetynet", "apple"]) {
    const out = await registered(ES, { fmt, attStmt });
    assert.equal(out.alg, -7);
  }
  await refused(registered(ES, { fmt: "made-up" }), "attestation");
  await refused(registered(ES, { fmt: "None" }), "attestation");
  await refused(registered(ES, { fmt: 1 }), "attestation");
  await refused(registered(ES, { attStmt: new Map([["alg", -7]]) }), "attestation");
  await refused(registered(ES, { attStmt: [] }), "attestation");
});

test("registration: the wrong origin is refused", async () => {
  for (const origin of ["https://evil.example", "https://ranwhat.com", "http://account.ranwhat.com",
    "https://account.ranwhat.com/", "https://account.ranwhat.com:443", "https://ACCOUNT.ranwhat.com",
    "https://account.ranwhat.com.evil.example", "android:apk-key-hash:abc", ""]) {
    await refused(registered(ES, { origin }), "origin");
  }
  await refused(registered(ES, { extra: { origin: undefined } }), "origin");
  await refused(registered(ES, { extra: { crossOrigin: true } }), "origin");
  await refused(registered(ES, { extra: { crossOrigin: "false" } }), "origin");
  await refused(registered(ES, { extra: { topOrigin: "https://evil.example" } }), "origin");
  const r = registration(ES);
  await refused(verifyRegistration({ ...r, ...expected, expectedOrigin: "https://evil.example" }), "origin");
});

test("registration: a challenge that is not ours is refused", async () => {
  await refused(registered(ES, { challenge: bytes(randomBytes(32)) }), "challenge");
  await refused(registered(ES, { challenge: CHALLENGE.slice(0, 31) }), "challenge");
  await refused(registered(ES, { extra: { challenge: b64(CHALLENGE) + "=" } }), "challenge");
  await refused(registered(ES, { extra: { challenge: Buffer.from(CHALLENGE).toString("base64") + "x" } }), "challenge");
  await refused(registered(ES, { extra: { challenge: [...CHALLENGE] } }), "challenge");
  await refused(registered(ES, { extra: { challenge: undefined } }), "challenge");
  const r = registration(ES);
  const call = (expectedChallenge) =>
    verifyRegistration({ attestationObject: r.attestationObject, clientDataJSON: r.clientDataJSON, ...expected, expectedChallenge });
  await refused(call(undefined), "challenge");
  await refused(call(""), "challenge");
  await refused(call(b64(CHALLENGE) + "="), "challenge");
  /* A challenge of fewer than 16 bytes is not one we would issue. */
  const short = bytes(randomBytes(8));
  const s = registration(ES, { challenge: short });
  await refused(verifyRegistration({ ...s, ...expected, expectedChallenge: b64(short) }), "challenge");
});

test("registration: the wrong ceremony type, or client data that is not JSON, is refused", async () => {
  await refused(registered(ES, { type: "webauthn.get" }), "type");
  await refused(registered(ES, { type: "payment.get" }), "type");
  await refused(registered(ES, { extra: { tokenBinding: { status: "present", id: "abc" } } }), "client-data");
  assert.equal((await registered(ES, { extra: { tokenBinding: { status: "supported" } } })).alg, -7);
  const r = registration(ES);
  for (const clientDataJSON of [b64(enc.encode("not json")), b64(enc.encode("[]")), b64(enc.encode("null")),
    b64(bytes([0x7b, 0xff, 0x7d])), b64(new Uint8Array(5000)), "", "%%%", b64(enc.encode("{}")) + "="]) {
    await refused(verifyRegistration({ attestationObject: r.attestationObject, clientDataJSON, ...expected }), "client-data");
  }
  await refused(verifyRegistration({ attestationObject: r.attestationObject, clientDataJSON: 42, ...expected }), "client-data");
});

test("registration: another rpId's authenticator data is refused", async () => {
  await refused(registered(ES, { rpId: "ranwhat.com" }), "rp");
  await refused(registered(ES, { rpId: "evil.example" }), "rp");
  const r = registration(ES);
  await refused(verifyRegistration({ ...r, ...expected, rpId: "ranwhat.com" }), "rp");
  await refused(verifyRegistration({ ...r, ...expected, rpId: "" }), "rp");
});

test("registration: user presence, user verification and an attached credential are required", async () => {
  await refused(registered(ES, { flags: UP | AT }), "verification");
  await refused(registered(ES, { flags: UV | AT }), "presence");
  await refused(registered(ES, { flags: UP | UV }), "authenticator-data");
  await refused(registered(ES, { flags: UP | UV | AT | BS }), "authenticator-data");
});

test("registration: an attestation object that is not exactly fmt, attStmt and authData is refused", async () => {
  const data = authData({ flags: UP | UV | AT, credential: { id: bytes(randomBytes(16)), cose: ES.cose } });
  const objects = {
    "a list": cbor([1, 2, 3]),
    "no authData": cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["other", 1]])),
    "authData as text": cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", "abc"]])),
    "a fourth key": cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", data], ["epAtt", true]])),
  };
  for (const [name, attestation] of Object.entries(objects)) {
    await assert.rejects(registered(ES, { attestation }), (e) => e.why === "attestation", name);
  }
  const good = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", data]]));
  const malformed = {
    "trailing bytes": concat([good, [0x00]]),
    "truncated": good.slice(0, good.length - 1),
    "an indefinite map": concat([[0xbf], good.slice(1), [0xff]]),
    "a tag around it": concat([[0xd9, 0xd9, 0xf7], good]),
    "a length past the end": concat([good.slice(0, good.length - data.length - 3), [0x5a, 0x7f, 0xff, 0xff, 0xff], data]),
  };
  for (const [name, attestation] of Object.entries(malformed)) {
    await assert.rejects(registered(ES, { attestation }), (e) => e.why === "cbor", name);
  }
  /* Over the size limit before a byte of it is decoded. */
  const huge = new Map([["alg", -7], ["sig", new Uint8Array(17000)]]);
  await refused(registered(ES, { fmt: "packed", attStmt: huge }), "attestation");
  const r = registration(ES);
  await refused(verifyRegistration({ ...r, ...expected, attestationObject: r.attestationObject + "=" }), "attestation");
  await refused(verifyRegistration({ ...r, ...expected, attestationObject: null }), "attestation");
});

test("registration: a key in an algorithm we do not take, or broken, is refused", async () => {
  const es384 = new Map([[1, 2], [3, -35], [-1, 2], [-2, new Uint8Array(48)], [-3, new Uint8Array(48)]]);
  await refused(registered({ cose: es384 }), "algorithm");
  await refused(registered(rs256(1024)), "key");
  const off = new Map(ES.cose);
  off.set(-2, new Uint8Array(32));
  await refused(registered({ cose: off }), "key");
  await refused(registered(ES, { key: concat([cbor(ES.cose).slice(0, 10)]) }), "cbor");
});

/* ---------- signing in ---------- */

for (const [name, pair] of PAIRS) {
  test(`assertion: a ${name} signature is checked over authenticatorData and the client data's hash`, async () => {
    const a = assertion(pair, { signCount: 3 });
    assert.deepEqual(await asserted(pair, a), { signCount: 3, backupEligible: false, backedUp: false });

    const sig = new Uint8Array(a.signature);
    sig[sig.length - 1] ^= 1;
    await refused(asserted(pair, { ...a, signature: sig }), "signature");

    const data = new Uint8Array(a.authenticatorData);
    data[36] ^= 1;                                    // the counter, after it was signed
    await refused(asserted(pair, { ...a, authenticatorData: data }), "signature");

    const client = JSON.parse(new TextDecoder().decode(a.clientDataJSON));
    const changed = enc.encode(JSON.stringify({ ...client, other: "x" }));
    await refused(asserted(pair, { ...a, clientDataJSON: changed }), "signature");

    const other = { ES256: es256, RS256: rs256, Ed25519: ed25519 }[name]();
    await refused(asserted(pair, assertion(pair, { signer: other })), "signature");
    await refused(asserted(pair, { ...a, signature: new Uint8Array(0) }), "signature");
    await refused(asserted(pair, { ...a, signature: new Uint8Array(2000) }), "signature");
  });
}

test("assertion: a signature made for another algorithm's key is refused", async () => {
  const a = assertion(ES);
  await refused(asserted(RS, a), "signature");
  await refused(asserted(ED25519, a), "signature");
  await refused(asserted(ES, assertion(ED25519, { signer: ED25519 })), "signature");
});

test("assertion: an ES256 signature must be DER, and strict DER", async () => {
  const a = assertion(ES);
  const der = a.signature;
  const raw = rawSignature(der);
  await refused(asserted(ES, { ...a, signature: raw }), "signature");
  await refused(asserted(ES, { ...a, signature: concat([der, [0]]) }), "signature");
  /* The same r and s, with a needless leading zero on r. */
  const rLength = der[3];
  const padded = concat([[0x30, der[1] + 1, 0x02, rLength + 1, 0x00], der.slice(4)]);
  await refused(asserted(ES, { ...a, signature: padded }), "signature");
});

test("assertion: the wrong origin, rpId, challenge or type is refused", async () => {
  await refused(asserted(ES, assertion(ES, { origin: "https://evil.example" })), "origin");
  await refused(asserted(ES, assertion(ES, { origin: "https://ranwhat.com" })), "origin");
  await refused(asserted(ES, assertion(ES, { extra: { crossOrigin: true } })), "origin");
  await refused(asserted(ES, assertion(ES), { expectedOrigin: "https://ranwhat.com" }), "origin");
  await refused(asserted(ES, assertion(ES, { rpId: "ranwhat.com" })), "rp");
  await refused(asserted(ES, assertion(ES), { rpId: "ranwhat.com" }), "rp");
  await refused(asserted(ES, assertion(ES, { challenge: bytes(randomBytes(32)) })), "challenge");
  await refused(asserted(ES, assertion(ES), { expectedChallenge: b64(randomBytes(32)) }), "challenge");
  await refused(asserted(ES, assertion(ES, { type: "webauthn.create" })), "type");
});

test("assertion: user presence and user verification are required, and no credential may be attached", async () => {
  await refused(asserted(ES, assertion(ES, { flags: UP })), "verification");
  await refused(asserted(ES, assertion(ES, { flags: UV })), "presence");
  await refused(asserted(ES, assertion(ES, { flags: UP | UV | BS })), "authenticator-data");
  const id = bytes(randomBytes(16));
  const client = clientData({ type: "webauthn.get" });
  const data = authData({ flags: UP | UV | AT, signCount: 1, credential: { id, cose: ES.cose } });
  const signature = ES.sign(concat([data, sha256(client)]));
  await refused(asserted(ES, { authenticatorData: data, clientDataJSON: client, signature }), "authenticator-data");
  await refused(asserted(ES, { ...assertion(ES), authenticatorData: new Uint8Array(36) }), "authenticator-data");
});

test("assertion: a counter that stands still or goes back is refused as a possible clone", async () => {
  const at = async (signCount, storedSignCount) =>
    (await asserted(ES, assertion(ES, { signCount }), { storedSignCount })).signCount;
  assert.equal(await at(0, 0), 0);                    // a passkey that never counts
  assert.equal(await at(5, 0), 5);
  assert.equal(await at(6, 5), 6);
  assert.equal(await at(0xffffffff, 0xfffffffe), 0xffffffff);
  await refused(asserted(ES, assertion(ES, { signCount: 10 }), { storedSignCount: 10 }), "counter");
  await refused(asserted(ES, assertion(ES, { signCount: 5 }), { storedSignCount: 10 }), "counter");
  /* Once it has counted, a zero is a step back too. */
  await refused(asserted(ES, assertion(ES, { signCount: 0 }), { storedSignCount: 10 }), "counter");
  for (const storedSignCount of [-1, 1.5, "3", null, 2 ** 32, NaN]) {
    await refused(asserted(ES, assertion(ES, { signCount: 5 }), { storedSignCount }), "counter");
  }
  /* A bad signature is reported as that, before any counter is looked at. */
  const a = assertion(ES, { signCount: 1 });
  await refused(asserted(ES, { ...a, signature: rawSignature(a.signature) }, { storedSignCount: 10 }), "signature");
});

test("assertion: a stored key that is not a COSE key is refused", async () => {
  const a = assertion(ES);
  await refused(verifyAssertion({ ...a, ...expected, publicKey: "" }), "key");
  await refused(verifyAssertion({ ...a, ...expected, publicKey: "!!" }), "key");
  await refused(verifyAssertion({ ...a, ...expected, publicKey: b64(new Uint8Array(3000)) }), "key");
  await refused(verifyAssertion({ ...a, ...expected, publicKey: b64(cbor(ES.cose)).slice(0, 20) }), "cbor");
  await refused(verifyAssertion({ ...a, ...expected, publicKey: b64(concat([cbor(ES.cose), [0]])) }), "cbor");
  await refused(verifyAssertion({ ...a, ...expected, publicKey: b64(cbor("text")) }), "key");
});
