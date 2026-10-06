/* What each plan unlocks on the server, in one place: auth.js's entitled()
 * refuses from it, and the dashboard draws its Plus and Team panels from
 * it, so a refusal and a locked panel can never disagree.
 *
 * Only what needs a server is here. Everything ranwhat works out on a
 * machine (check, watch, clean, scan, live, demo) is free and stays out of
 * this map: nothing local is ever locked.
 *
 * plan: the least plan that has it. status: 'live' once the server serves
 * it, 'coming' until then; the dashboard says which.
 *
 * The plan itself is never stored: auth.js's plan() works it out from an
 * organisation's grants and linked subscriptions on every request.
 */

export const PLANS = Object.freeze(["free", "plus", "team"]);

export const PLAN_NAMES = Object.freeze({ free: "Free", plus: "Plus", team: "Team" });

const RANK = Object.freeze({ free: 0, plus: 1, team: 2 });

export const FEATURES = Object.freeze({
  feed: Object.freeze({
    plan: "plus", status: "live", name: "Catalogue feed",
    says: "Scopes rated since the last release, fetched by ranwhat update.",
  }),
  push: Object.freeze({
    plan: "plus", status: "coming", name: "Push",
    says: "Send a machine's findings to your account, as derived metadata only.",
  }),
  alerts: Object.freeze({
    plan: "plus", status: "coming", name: "Alerts",
    says: "An email when what a linked machine's agents can do changes.",
  }),
  machines: Object.freeze({
    plan: "plus", status: "coming", name: "Cross-machine view",
    says: "Every linked machine's findings side by side.",
  }),
  history: Object.freeze({
    plan: "plus", status: "coming", name: "13-month record",
    says: "What your agents could do, kept for 13 months.",
  }),
  drift: Object.freeze({
    plan: "plus", status: "coming", name: "Drift",
    says: "What changed since a baseline you chose.",
  }),
  digest: Object.freeze({
    plan: "plus", status: "coming", name: "Digest",
    says: "A weekly summary by email.",
  }),
  signed_reports: Object.freeze({
    plan: "plus", status: "coming", name: "Signed reports",
    says: "Reports anyone can check came from your account, unchanged.",
  }),
  hash_chain: Object.freeze({
    plan: "team", status: "coming", name: "Hash-chained records",
    says: "Each record bound to the one before, so a gap or an edit shows.",
  }),
  underwriter_export: Object.freeze({
    plan: "team", status: "coming", name: "Underwriter export",
    says: "The record in the form an insurer or auditor asks for.",
  }),
});

/* Whether `plan` is `least` or more. */
export const atLeast = (plan, least) =>
  Object.hasOwn(RANK, plan) && Object.hasOwn(RANK, least) && RANK[plan] >= RANK[least];

/* Whether `plan` has `feature`. An unknown feature or plan has nothing, so
   a misspelt name refuses rather than lets through. */
export const allows = (plan, feature) =>
  Object.hasOwn(FEATURES, feature) && atLeast(plan, FEATURES[feature].plan);

/* The features a plan is the least plan for, in the map's order. */
export const featuresOf = (plan) =>
  Object.entries(FEATURES).filter(([, f]) => f.plan === plan).map(([key, f]) => ({ key, ...f }));
