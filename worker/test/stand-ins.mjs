/* What the Worker's tests run it against: a D1 database that is a real
 * SQLite one (node:sqlite, which is what D1 runs), and cloudflare:email,
 * which only exists on Workers. Imported before index.js. */
import { register } from "node:module";
import { DatabaseSync } from "node:sqlite";

register("data:text/javascript," + encodeURIComponent(`
  export async function resolve(spec, ctx, next) {
    if (spec === "cloudflare:email") {
      return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
        "export class EmailMessage { constructor(f, t, r) { this.from = f; this.to = t; this.raw = r; } }") };
    }
    return next(spec, ctx);
  }`));

export function d1() {
  const db = new DatabaseSync(":memory:");
  const statement = (sql, params = []) => ({
    bind: (...p) => statement(sql, p),
    first: async () => { const r = db.prepare(sql).get(...params); return r ? { ...r } : null; },
    all: async () => ({ results: db.prepare(sql).all(...params).map((r) => ({ ...r })) }),
    run: async () => ({ meta: { changes: Number(db.prepare(sql).run(...params).changes) } }),
    now: () => db.prepare(sql).run(...params),
  });
  return {
    sql: db,
    prepare: (sql) => statement(sql),
    batch: async (statements) => {
      db.exec("BEGIN");
      try {
        const out = statements.map((s) => ({ meta: { changes: Number(s.now().changes) } }));
        db.exec("COMMIT");
        return out;
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    },
  };
}
