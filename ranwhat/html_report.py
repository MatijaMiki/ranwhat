"""HTML report generation.

This is the artifact that leaves the building: the thing attached to a
submission, shown to a broker, or published as a Trust Page. It is a static
self-contained file with no network calls, because it will be opened by
people whose security teams will check that.
"""
from __future__ import annotations

import datetime
import html
import os

_STATUS_TONE = {"UNINSURABLE": "bad", "IMPAIRED": "warn", "INSURABLE": "good"}
_SEV_TONE = {"critical": "bad", "high": "warn", "medium": "info", "low": "muted"}

_CSS = """
:root{
  --bg:#fbfaf8; --panel:#fff; --ink:#16150f; --muted:#6a675c; --line:#e5e2d9;
  --bad:#b4331f; --bad-bg:#fbeeeb; --warn:#8a6100; --warn-bg:#fcf4e2;
  --good:#1f6b43; --good-bg:#ebf5ee; --info:#2a5b8c; --info-bg:#eaf1f8;
  --accent:#16150f;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
  --bg:#12120f; --panel:#1a1a16; --ink:#f2f0e9; --muted:#9a968a; --line:#2c2b25;
  --bad:#f08b78; --bad-bg:#2b1a16; --warn:#e0b25c; --warn-bg:#2a2214;
  --good:#7fc79b; --good-bg:#16261d; --info:#8fb8de; --info-bg:#172530;
  --accent:#f2f0e9;
  }
}
:root[data-theme="dark"]{
  --bg:#12120f; --panel:#1a1a16; --ink:#f2f0e9; --muted:#9a968a; --line:#2c2b25;
  --bad:#f08b78; --bad-bg:#2b1a16; --warn:#e0b25c; --warn-bg:#2a2214;
  --good:#7fc79b; --good-bg:#16261d; --info:#8fb8de; --info-bg:#172530;
  --accent:#f2f0e9;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Inter,system-ui,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:860px;margin:0 auto;padding:48px 16px 80px}
header{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:28px}
.brand{font-weight:650;letter-spacing:-.01em}
.brand span{color:var(--muted);font-weight:400}
h1{font-size:26px;letter-spacing:-.02em;margin:14px 0 4px}
.meta{color:var(--muted);font-size:13px}
.verdict{display:flex;gap:14px;align-items:flex-start;padding:18px 20px;
  border-radius:10px;border:1px solid var(--line);margin:24px 0}
.verdict.bad{background:var(--bad-bg);border-color:color-mix(in srgb,var(--bad) 32%,transparent)}
.verdict.warn{background:var(--warn-bg);border-color:color-mix(in srgb,var(--warn) 32%,transparent)}
.verdict.good{background:var(--good-bg);border-color:color-mix(in srgb,var(--good) 32%,transparent)}
.badge{font-size:11px;font-weight:700;letter-spacing:.08em;padding:5px 9px;
  border-radius:5px;white-space:nowrap;text-transform:uppercase}
.bad .badge{background:var(--bad);color:var(--bg)}
.warn .badge{background:var(--warn);color:var(--bg)}
.good .badge{background:var(--good);color:var(--bg)}
.verdict h2{margin:0 0 5px;font-size:16px;letter-spacing:-.01em}
.verdict p{margin:0;color:var(--muted);font-size:13.5px}
.scores{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:26px 0}
.score{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.score .lab{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
.score .num{font-size:30px;font-weight:650;letter-spacing:-.03em;margin:6px 0 2px;
  font-variant-numeric:tabular-nums}
.score .num small{font-size:14px;color:var(--muted);font-weight:400}
.track{height:5px;background:var(--line);border-radius:3px;overflow:hidden;margin-top:10px}
.fill{height:100%;border-radius:3px}
h3{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);
  margin:34px 0 12px;font-weight:600}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px}
.kv{display:flex;justify-content:space-between;gap:16px;padding:9px 0;
  border-bottom:1px solid var(--line);font-size:14px}
.kv:last-child{border-bottom:0}
.kv .k{color:var(--muted)}
.kv .v{text-align:right;font-variant-numeric:tabular-nums}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:3px;
  border-radius:8px;padding:14px 16px;margin-bottom:10px}
.finding.bad{border-left-color:var(--bad)}
.finding.warn{border-left-color:var(--warn)}
.finding.info{border-left-color:var(--info)}
.finding.muted{border-left-color:var(--muted)}
.finding .sev{font-size:10px;font-weight:700;letter-spacing:.09em;text-transform:uppercase}
.bad .sev{color:var(--bad)} .warn .sev{color:var(--warn)}
.info .sev{color:var(--info)} .muted .sev{color:var(--muted)}
.finding h4{margin:5px 0 6px;font-size:15px;letter-spacing:-.01em}
.finding p{margin:0;color:var(--muted);font-size:13.5px}
ul.ev{margin:10px 0 0;padding:0;list-style:none}
ul.ev li{font:12px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);
  overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;
  color:var(--muted);font-weight:600;padding:0 8px 9px 0;border-bottom:1px solid var(--line)}
td{padding:9px 8px 9px 0;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
code{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
.pill{display:inline-block;font-size:10.5px;font-weight:600;letter-spacing:.04em;
  padding:2px 7px;border-radius:4px;text-transform:uppercase}
.p-read{background:var(--info-bg);color:var(--info)}
.p-write{background:var(--warn-bg);color:var(--warn)}
.p-financial{background:var(--bad-bg);color:var(--bad)}
.p-destructive{background:var(--bad);color:var(--bg)}
.u-unused{color:var(--bad);font-weight:600}
.u-used{color:var(--muted)}
footer{margin-top:44px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--muted);font-size:12px}
@media(max-width:620px){
  .wrap{padding:28px 16px 60px}
  .scores{grid-template-columns:1fr}
  .verdict{flex-direction:column;gap:10px}
  table{display:block;overflow-x:auto}
}
"""


def _tone_color(n):
    return "var(--bad)" if n < 40 else ("var(--warn)" if n < 70 else "var(--good)")


def _esc(s):
    return html.escape(str(s))


def build_html(result):
    v = result["verdict"]
    tone = _STATUS_TONE[v["status"]]
    ba = result["blast_radius"]
    c = result["counts"]
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%d %b %Y %H:%M UTC")

    scores = "".join(
        '<div class="score"><div class="lab">{lab}</div>'
        '<div class="num">{n}<small>/100 · {g}</small></div>'
        '<div class="track"><div class="fill" style="width:{n}%;background:{col}"></div></div>'
        "</div>".format(lab=lab, n=result["scores"][k], g=result["grades"][k],
                        col=_tone_color(result["scores"][k]))
        for k, lab in (("authority", "Authority"),
                       ("observability", "Observability"),
                       ("reversibility", "Reversibility"))
    )

    findings = ""
    for f in result["findings"]:
        ev = "".join("<li>· %s</li>" % _esc(e) for e in f["evidence"][:8])
        more = ("<li>· … and %d more</li>" % (len(f["evidence"]) - 8)) if len(f["evidence"]) > 8 else ""
        findings += (
            '<div class="finding {t}"><div class="sev">{s}</div><h4>{title}</h4>'
            '<p>{body}</p>{ev}</div>'.format(
                t=_SEV_TONE.get(f["severity"], "muted"), s=_esc(f["severity"]),
                title=_esc(f["title"]), body=_esc(f["body"]),
                ev=('<ul class="ev">%s%s</ul>' % (ev, more)) if ev else ""))

    cov_rows = result.get("usage_coverage") or []
    if cov_rows:
        _lvl = {"full": ("Verified", "var(--good)"),
                "writes": ("Writes only", "var(--warn)"),
                "none": ("Unverified", "var(--bad)")}
        coverage = "".join(
            '<div class="kv"><span class="k">{p}</span>'
            '<span class="v" style="color:{col}">{lab}</span></div>'
            '<div style="color:var(--muted);font-size:12.5px;padding:0 0 9px">{note}</div>'.format(
                p=_esc(c["provider"]), lab=_lvl.get(c["level"], ("?", "var(--muted)"))[0],
                col=_lvl.get(c["level"], ("?", "var(--muted)"))[1], note=_esc(c["note"]))
            for c in cov_rows)
    else:
        coverage = ('<div style="color:var(--muted);font-size:13.5px">'
                    'No usage pull was run. Granted permissions could not be '
                    'compared against exercised ones.</div>')

    order = {"destructive": 0, "financial": 1, "write": 2, "read": 3}
    rows = sorted(result["scopes"], key=lambda r: (order[r["authority"]], r["provider"]))
    table = "".join(
        "<tr><td><code>{scope}</code><br><span style='color:var(--muted)'>{label}</span></td>"
        "<td>{prov}</td><td><span class='pill p-{auth}'>{auth}</span></td>"
        "<td>{rev}</td><td class='u-{usage}'>{usage}</td></tr>".format(
            scope=_esc(r["scope"]), label=_esc(r["label"]), prov=_esc(r["provider"]),
            auth=_esc(r["authority"]), rev="yes" if r["reversible"] else "no",
            usage=_esc(r["usage"]))
        for r in rows)

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Authority Report</title>
<style>{css}</style></head>
<body><div class="wrap">
<header>
  <div class="brand">ranwhat <span>· agent authority &amp; insurability</span></div>
  <h1>{agent}</h1>
  <div class="meta">Generated {now} · read-only credential introspection</div>
</header>

<div class="verdict {tone}">
  <div class="badge">{status}</div>
  <div><h2>{headline}{composite}</h2><p>{detail}</p></div>
</div>

<div class="scores">{scores}</div>

<h3>Exposure</h3>
<div class="panel">
  <div class="kv"><span class="k">Permissions granted</span><span class="v">{total}</span></div>
  <div class="kv"><span class="k">Exercised in window</span><span class="v">{used}</span></div>
  <div class="kv"><span class="k">Never exercised</span><span class="v" style="color:var(--bad);font-weight:600">{unused}</span></div>
  <div class="kv"><span class="k">Financial authority</span><span class="v">{monetary}</span></div>
  <div class="kv"><span class="k">Irreversible actions available</span><span class="v">{irr}</span></div>
  <div class="kv"><span class="k">Blast radius</span><span class="v">{dims}</span></div>
</div>

<h3>Usage coverage</h3>
<div class="panel">{coverage}</div>

<h3>Findings</h3>
{findings}

<h3>Granted permissions</h3>
<div class="panel">
<table><thead><tr><th>Scope</th><th>Provider</th><th>Authority</th><th>Reversible</th><th>Usage</th></tr></thead>
<tbody>{table}</tbody></table>
</div>

<footer>
No credential, prompt, message body or customer record was transmitted to
produce this report. Scope classification is advisory; permissions marked
unclassified were inferred from their action verb and should be confirmed
manually before this report is relied on for underwriting.
</footer>
</div></body></html>""".format(
        css=_CSS, agent=_esc(result["agent"]), now=now, tone=tone,
        status=_esc(v["status"]), headline=_esc(v["headline"]),
        composite=(" · %s/100 (%s)" % (v["composite"], v["grade"])
                   if v.get("composite") is not None else ""),
        detail=_esc(v["detail"] or "Scored across authority, observability and reversibility."),
        scores=scores, total=c["total"], used=c["used"], unused=c["unused"],
        monetary=_esc(ba["monetary"] or "none"),
        irr=len(ba["irreversible_actions"]),
        dims=_esc(", ".join(ba["dimensions"]) or "none"),
        findings=findings, table=table, coverage=coverage)


def write_html(result, path):
    """Write the report owner-readable only, and never through a symlink.

    The report is a map of an agent's entire authority surface -- which
    permissions exist, which are unused, what the blast radius is. That is
    useful to an attacker, so it does not get mode 644, and a pre-planted
    symlink at the output path does not get followed.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)     # Windows: else \r\n lands as \r\r\n
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as e:
        if getattr(e, "errno", None) in (40, 62):      # ELOOP
            raise SystemExit("ranwhat: %s is a symlink; refusing to write "
                             "through it" % path)
        raise SystemExit("ranwhat: cannot write %s (%s)" % (path, e.strerror))
    try:
        if hasattr(os, "fchmod"):       # Windows before Python 3.13 has none
            os.fchmod(fd, 0o600)
        # The page declares utf-8; the locale's encoding (cp1252 on Windows)
        # would garble every middle dot, and fail on anything it lacks.
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(build_html(result))
    except OSError as e:
        raise SystemExit("ranwhat: cannot write %s (%s)" % (path, e.strerror))
    return path
