/* What a machine may push, and nothing else: the allow-list that push.js
 * checks every body against, strictly, before anything is stored.
 *
 * The body is derived metadata and no more: the rule that fired and its
 * severity, the action's 16-hex id (ranwhat/watch.py's action_id), the
 * agent's id, a UTC time, counts, ranwhat's version and the window in
 * days. It has no field for a command, a path, evidence, a working
 * directory, a session id, a secret, a hostname or a user name, and a key
 * this file does not list is refused, so a future client bug cannot send
 * one through. Rule and agent ids are enumerated from push/schema.json
 * (made from ranwhat's own rule and agent lists), never matched by
 * pattern, so even a client bug cannot put a 32-character secret in an
 * id field. The machine is the token's, never the body's: the body has no
 * machine, organisation, host or user field.
 *
 * validate() rebuilds the value from scratch out of the checked fields, so
 * nothing unchecked rides along, and answers a refusal with a JSON
 * pointer built from this schema's own path and array indexes and one of
 * a closed set of reasons. It never repeats a value from the request, and
 * for an unknown key it names the object that held it, not the key.
 *
 * Pure: no I/O, no clock but the one it is given.
 */
import SCHEMA from "../push/schema.json" with { type: "json" };

export const VERSION = 1;

export const LIMITS = Object.freeze({
  MAX_BODY: 32768,
  MAX_ACTIONS: 100,
  MAX_HITS: 15,
  MAX_RULE_KEYS: 32,
  MAX_AGENT_KEYS: 40,
  MAX_COUNT: 1_000_000,
});

const DAY = 86400;
const AHEAD = 1 * DAY;       // a time no more than a day in the server's future
const BEHIND = 7 * DAY;      // a snapshot made no more than a week ago
const ACTION_BEHIND = 366 * DAY;

export const RULES = Object.freeze(Object.fromEntries(Object.entries(SCHEMA.rules)));
export const AGENTS = Object.freeze(Object.fromEntries(Object.entries(SCHEMA.agents)));
export const SEVERITIES = Object.freeze([...SCHEMA.severities]);

const ROOT_KEYS = ["v", "ranwhat", "generated_at", "window_days", "counts", "actions"];
const COUNT_KEYS = ["flagged", "ignored", "omitted", "unread", "severity", "rules", "agents", "scanned"];
const ACTION_KEYS = ["id", "agent", "at", "hits"];
const HIT_KEYS = ["rule", "severity"];

const VERSION_TEXT = /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([a-z0-9.+-]{0,16})?$/;
const TIME = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;
const ACTION_ID = /^[0-9a-f]{16}$/;

class Refusal extends Error {
  constructor(field, reason, extra = {}) {
    super(reason);
    this.field = field;
    this.reason = reason;
    this.extra = extra;
  }
}
const refuse = (field, reason, extra) => { throw new Refusal(field || "/", reason, extra); };

const isObject = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const own = (map, key) => Object.hasOwn(map, key);

/* An object with exactly these keys: refused for one it does not list (the
   object's own pointer, never the key), then for one it lacks. */
function exact(value, keys, path) {
  if (!isObject(value)) refuse(path, "type");
  const have = Object.keys(value);
  if (have.some((k) => !keys.includes(k))) refuse(path, "unknown_key");
  for (const k of keys) if (!Object.hasOwn(value, k)) refuse(`${path}/${k}`, "missing");
}

function int(value, path, min, max) {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) refuse(path, "type");
  if (value < min || value > max) refuse(path, "range");
  return value;
}

/* A UTC instant as unix seconds, only when it is a real one: 2026-02-31
   does not round-trip through Date. */
function instant(value, path) {
  if (typeof value !== "string" || value.length !== 20) refuse(path, typeof value === "string" ? "format" : "type");
  const m = TIME.exec(value);
  if (!m) refuse(path, "format");
  const ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) + "Z" !== value) refuse(path, "format");
  return ms / 1000;
}

const iso = (t) => new Date(t * 1000).toISOString().slice(0, 19) + "Z";

/* A map of known ids to counts of 1 or more. */
function tally(value, path, known, maxKeys) {
  if (!isObject(value)) refuse(path, "type");
  const keys = Object.keys(value);
  if (keys.length > maxKeys) refuse(path, "too_many");
  const out = {};
  for (const k of keys.sort()) {
    if (!own(known, k)) refuse(path, "unknown_value");
    out[k] = int(value[k], `${path}/${k}`, 1, LIMITS.MAX_COUNT);
  }
  return out;
}

/* The checked body, rebuilt, or the first thing wrong with it. now: unix
   seconds. */
export function validate(doc, now) {
  try {
    return { ok: true, value: check(doc, now) };
  } catch (err) {
    if (!(err instanceof Refusal)) throw err;
    return { ok: false, error: err.reason === "unsupported_version" ? "unsupported_version" : "invalid",
             field: err.field, reason: err.reason, ...err.extra };
  }
}

function check(doc, now) {
  if (!isObject(doc)) refuse("/", "type");
  /* A version this server does not speak is its own answer, before the
     rest is held against a schema it may not follow. */
  if (Object.hasOwn(doc, "v") && typeof doc.v === "number" && Number.isSafeInteger(doc.v) && doc.v !== VERSION) {
    refuse("/v", "unsupported_version", { supported: [VERSION] });
  }
  exact(doc, ROOT_KEYS, "");
  int(doc.v, "/v", VERSION, VERSION);
  if (typeof doc.ranwhat !== "string") refuse("/ranwhat", "type");
  if (doc.ranwhat.length > 24 || !VERSION_TEXT.test(doc.ranwhat)) refuse("/ranwhat", "format");
  const generated = instant(doc.generated_at, "/generated_at");
  if (generated > now + AHEAD || generated < now - BEHIND) refuse("/generated_at", "range");
  const windowDays = int(doc.window_days, "/window_days", 1, 365);

  const c = doc.counts;
  exact(c, COUNT_KEYS, "/counts");
  const flagged = int(c.flagged, "/counts/flagged", 0, LIMITS.MAX_COUNT);
  const ignored = int(c.ignored, "/counts/ignored", 0, LIMITS.MAX_COUNT);
  const omitted = int(c.omitted, "/counts/omitted", 0, LIMITS.MAX_COUNT);
  const unread = int(c.unread, "/counts/unread", 0, LIMITS.MAX_COUNT);
  exact(c.severity, ["critical", "high", "medium"], "/counts/severity");
  const severity = {
    critical: int(c.severity.critical, "/counts/severity/critical", 0, LIMITS.MAX_COUNT),
    high: int(c.severity.high, "/counts/severity/high", 0, LIMITS.MAX_COUNT),
    medium: int(c.severity.medium, "/counts/severity/medium", 0, LIMITS.MAX_COUNT),
  };
  const rules = tally(c.rules, "/counts/rules", RULES, LIMITS.MAX_RULE_KEYS);
  const agents = tally(c.agents, "/counts/agents", AGENTS, LIMITS.MAX_AGENT_KEYS);
  const scanned = tally(c.scanned, "/counts/scanned", AGENTS, LIMITS.MAX_AGENT_KEYS);
  if (severity.critical + severity.high + severity.medium !== flagged) refuse("/counts/severity", "inconsistent");
  if (Object.values(agents).reduce((a, b) => a + b, 0) !== flagged) refuse("/counts/agents", "inconsistent");

  if (!Array.isArray(doc.actions)) refuse("/actions", "type");
  if (doc.actions.length > LIMITS.MAX_ACTIONS) refuse("/actions", "too_many");
  if (doc.actions.length + omitted !== flagged) refuse("/actions", "inconsistent");
  const seen = new Set();
  const actions = doc.actions.map((a, i) => {
    const at = `/actions/${i}`;
    exact(a, ACTION_KEYS, at);
    if (typeof a.id !== "string") refuse(`${at}/id`, "type");
    if (!ACTION_ID.test(a.id)) refuse(`${at}/id`, "format");
    if (seen.has(a.id)) refuse(`${at}/id`, "duplicate");
    seen.add(a.id);
    if (typeof a.agent !== "string") refuse(`${at}/agent`, "type");
    if (!own(AGENTS, a.agent)) refuse(`${at}/agent`, "unknown_value");
    let when = null;
    if (a.at !== null) {
      const t = instant(a.at, `${at}/at`);
      if (t < generated - ACTION_BEHIND || t > generated + AHEAD) refuse(`${at}/at`, "range");
      when = a.at;
    }
    if (!Array.isArray(a.hits)) refuse(`${at}/hits`, "type");
    if (a.hits.length < 1) refuse(`${at}/hits`, "range");
    if (a.hits.length > LIMITS.MAX_HITS) refuse(`${at}/hits`, "too_many");
    const rulesHere = new Set();
    const hits = a.hits.map((h, j) => {
      const hp = `${at}/hits/${j}`;
      exact(h, HIT_KEYS, hp);
      if (typeof h.rule !== "string") refuse(`${hp}/rule`, "type");
      if (!own(RULES, h.rule)) refuse(`${hp}/rule`, "unknown_value");
      if (rulesHere.has(h.rule)) refuse(`${hp}/rule`, "duplicate");
      rulesHere.add(h.rule);
      if (typeof h.severity !== "string") refuse(`${hp}/severity`, "type");
      if (!SEVERITIES.includes(h.severity)) refuse(`${hp}/severity`, "unknown_value");
      return { rule: h.rule, severity: h.severity };
    });
    return { id: a.id, agent: a.agent, at: when, hits };
  });

  return {
    v: VERSION, ranwhat: doc.ranwhat, generated_at: iso(generated), window_days: windowDays,
    counts: { flagged, ignored, omitted, unread, severity, rules, agents, scanned },
    actions,
  };
}

const sorted = (map) => Object.fromEntries(Object.keys(map).sort().map((k) => [k, map[k]]));

/* The canonical form of a checked value: fixed key order, maps sorted by
   key, actions by id, hits by rule, so that two bodies that say the same
   thing digest the same however the client ordered them. */
export function normalise(value) {
  const c = value.counts;
  return {
    v: value.v, ranwhat: value.ranwhat, generated_at: value.generated_at, window_days: value.window_days,
    counts: {
      flagged: c.flagged, ignored: c.ignored, omitted: c.omitted, unread: c.unread,
      severity: { critical: c.severity.critical, high: c.severity.high, medium: c.severity.medium },
      rules: sorted(c.rules), agents: sorted(c.agents), scanned: sorted(c.scanned),
    },
    actions: value.actions.map((a) => ({
      id: a.id, agent: a.agent, at: a.at,
      hits: a.hits.map((h) => ({ rule: h.rule, severity: h.severity })).sort((x, y) => (x.rule < y.rule ? -1 : 1)),
    })).sort((x, y) => (x.id < y.id ? -1 : 1)),
  };
}

/* SHA-256, in hex, of the normalised body without its time: the same
   findings pushed again are the same push. */
export async function digestOf(value) {
  const { generated_at: _when, ...rest } = normalise(value);
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(rest))));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
