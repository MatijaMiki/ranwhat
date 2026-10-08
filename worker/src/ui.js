/* The pages account.ranwhat.com serves, and the headers on every response
 * from it.
 *
 * The pages are plain HTML forms, and two scripts are allowed, each only
 * where it is needed. Cloudflare Turnstile's runs only on the pages whose
 * form mails a code to someone signing in (sign in, make an account,
 * reset, a new code, and the page that offers one when password sign-in
 * is paused): never on the page a code is typed into, and never on the
 * account's own pages, a step-up's included. Ours is one file,
 * /passkeys.js (passkeys.js), which WebAuthn cannot do without: it runs
 * only on the two passkey pages, adding one and signing in with one,
 * whose policy then allows that one script and fetches to the two paths
 * it asks for options, and nothing else; no page has an inline script. Every other page's policy
 * allows no script at all, and every way in but a passkey works on
 * pages without one. The one inline style is allowed by its hash
 * rather than by 'unsafe-inline', so markup that ever slipped past
 * escape() could not style itself either. Nothing loads from ranwhat.com,
 * so GTM, the analytics and the X pixel that run there never share a page
 * with a signed-in session.
 *
 * Two layouts share that one style. page() is the narrow centred card of
 * the pages around signing in and of every one-off page (a code, a
 * passkey, a terminal to approve, the upgrade, an invite, an error).
 * shell() is the signed-in app: a sidebar with the organisation, the six
 * account pages and signing out, which becomes a top bar on a phone, and
 * the page's own header and cards. Neither needs a script: the nav is
 * links (wrapped onto rows on a phone, so every page and the current one
 * show), the organisation switcher a form folded in a <details>, as are a
 * row's Rename and removing a password, and a table becomes one block per
 * row on a phone by CSS alone. Icons
 * are inline SVG markup drawn here (icon()), since default-src 'none'
 * lets no image, font or anything else be fetched.
 */
import { escape } from "./list.js";
import { CHALLENGE_ORIGIN, CHALLENGE_SCRIPT, SITEKEY } from "./challenge.js";
import { ACCOUNT_ORIGIN, DAY, now } from "./accounts.js";

/* ranwhat.com's colours, both themes, with system fonts in place of its
   own: /fonts/ is on ranwhat.com, which this host's policy does not reach.
   Dark when the device is. --line is for the edges of inputs and buttons,
   which need 3:1 against what they sit on; --rule and --rule-2 only
   separate. Long words (an address, an organisation's name) wrap anywhere
   rather than push a page sideways. The account pages' columns follow the
   width of the page's own column (.page is a container), not the
   window's, since the sidebar takes part of it. */
const CSS = `
:root{color-scheme:light;--ground:#edeff1;--surface:#fff;--raise:#f7f8f9;--ink:#12171c;--ink-2:#39434e;--muted:#5a6672;--line:#7d8794;--rule:#d5dae0;--rule-2:#e4e8ec;--brand:#b8482d;--on-brand:#fff;--brand-bg:#fbeeea;--crit:#b02a1e;--crit-bg:#f7e9e7;--warn:#8a5a00;--warn-bg:#f8f0df;--ok:#1b6b4a;--ok-bg:#e6f0eb;--info:#2a4f7c;--info-bg:#e8eef5;--focus:#2a4f7c;--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;--mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--ground:#0E1318;--surface:#151B21;--raise:#1C242C;--ink:#e9edf0;--ink-2:#c2cad2;--muted:#8e99a4;--line:#66717c;--rule:#242C34;--rule-2:#222a32;--brand:#ea8471;--on-brand:#0E1318;--brand-bg:#2a1714;--crit:#ea8471;--crit-bg:#2a1714;--warn:#d7a44f;--warn-bg:#271e10;--ok:#72c69d;--ok-bg:#12241c;--info:#8db4dd;--info-bg:#141e29;--focus:#8db4dd}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;background:var(--ground);color:var(--ink);font:15px/1.55 var(--sans);-webkit-font-smoothing:antialiased;overflow-wrap:anywhere}
[hidden]{display:none!important}
a{color:inherit;text-underline-offset:.2em;text-decoration-thickness:1px}
a:hover{color:var(--brand)}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
h1,h2,h3{color:var(--ink);text-wrap:balance}
p{margin:0 0 14px;color:var(--ink-2)}
p,li,dd{text-wrap:pretty}
small{font-size:13px;color:var(--muted)}
strong{font-weight:600;color:var(--ink)}
code{font:.92em var(--mono)}
ul{padding-left:18px;color:var(--ink-2)}li{margin:4px 0}
dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:8px 20px;margin:0 0 14px}
dt{color:var(--muted);font-size:14px}dd{margin:0}
details{margin:8px 0}summary{cursor:pointer;font-size:14px;color:var(--ink)}
summary.btn,summary.toggle{list-style:none}summary.btn::-webkit-details-marker,summary.toggle::-webkit-details-marker{display:none}
.i{width:18px;height:18px;flex:none}
.skip{position:absolute;left:12px;top:-80px;z-index:20;padding:8px 14px;border-radius:6px;background:var(--ink);color:var(--surface);font-weight:500;text-decoration:none}
.skip:focus{top:12px;color:var(--surface)}
.label{display:block;font:500 11px/1.4 var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
.wm{font:600 17px/1 var(--mono);letter-spacing:-.03em;color:var(--ink);text-decoration:none;overflow-wrap:normal}
.wm i{font-style:normal;color:var(--brand)}
.wm:hover{color:var(--ink)}
.mark{display:flex;align-items:baseline;gap:9px}
.mark .label{font-size:10.5px}
label{display:block;margin:14px 0 6px;font-size:14px;font-weight:500;color:var(--ink)}
label:has(input[type=checkbox]){display:flex;gap:9px;align-items:flex-start;font-weight:400;color:var(--ink-2)}
input[type=checkbox]{width:16px;height:16px;margin:3px 0 0;flex:none;accent-color:var(--brand)}
input[type=email],input[type=text],input[type=password],select{display:block;width:100%;min-height:40px;margin:0;padding:9px 11px;font:15px/1.35 var(--sans);color:var(--ink);background:var(--raise);border:1px solid var(--line);border-radius:6px}
input::placeholder{color:var(--muted);opacity:1}
input:focus-visible,select:focus-visible{outline:2px solid var(--focus);outline-offset:1px;border-color:var(--focus)}
button,.button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;max-width:100%;min-height:40px;margin:14px 0 0;padding:9px 15px;font:500 14px/1.25 var(--sans);text-align:center;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:6px;text-decoration:none;cursor:pointer;overflow-wrap:normal}
button:hover,.button:hover,.btn:hover{color:var(--ink);border-color:var(--ink)}
button .i,.btn .i{width:16px;height:16px}
button.primary,a.primary{color:var(--on-brand);background:var(--brand);border-color:var(--brand)}
button.primary:hover,a.primary:hover{color:var(--on-brand);border-color:var(--brand);filter:brightness(1.08)}
button.danger,a.danger,summary.danger{color:var(--crit);background:transparent;border-color:var(--crit)}
button.danger:hover,a.danger:hover,summary.danger:hover{color:var(--crit);background:var(--crit-bg);border-color:var(--crit)}
button.compact,a.compact,summary.compact{min-height:32px;margin:0;padding:5px 11px;font-size:13px;white-space:nowrap}
button.compact .i,a.compact .i,summary.compact .i{width:14px;height:14px}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
.actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:16px}
.actions>*{margin:0}.actions form button{margin:0}
.bad{color:var(--crit)}
p.bad{padding:10px 12px;background:var(--crit-bg);border-left:3px solid var(--crit);border-radius:6px;font-size:14px}
.cf-turnstile{min-height:65px;margin-top:14px}
.secret-label{margin:20px 0 6px}
input[name=code],input[name=user_code]{padding:11px 12px;font:500 20px/1.3 var(--mono);letter-spacing:.16em;text-transform:uppercase}
input[name=code]::placeholder,input[name=user_code]::placeholder{letter-spacing:.16em}
.secret{display:block;margin:0 0 16px;padding:12px 14px;font:15px/1.5 var(--mono);color:var(--ink);background:var(--raise);border:1px solid var(--rule);border-radius:6px;user-select:all;-webkit-user-select:all}
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 7px;font:500 11px/1.3 var(--mono);letter-spacing:.03em;color:var(--muted);background:var(--raise);border:1px solid var(--rule);border-radius:4px;white-space:nowrap;vertical-align:1px}
.pill .i{width:12px;height:12px}
.pill.brand{color:var(--brand);background:var(--brand-bg);border-color:transparent}
.pill.ok{color:var(--ok);background:var(--ok-bg);border-color:transparent}
.pill.warn{color:var(--warn);background:var(--warn-bg);border-color:transparent}
.pill.crit{color:var(--crit);background:var(--crit-bg);border-color:transparent}
.pill.info{color:var(--info);background:var(--info-bg);border-color:transparent}
.pills{display:inline-flex;flex-wrap:wrap;gap:6px;align-items:center}
.lock{display:inline-grid;place-items:center;width:24px;height:24px;border-radius:6px;color:var(--brand);background:var(--brand-bg);flex:none}
.lock .i{width:14px;height:14px}
.cmd{display:flex;gap:10px;align-items:center;margin:10px 0 0;padding:10px 12px;font:13.5px/1.4 var(--mono);color:var(--ink);background:var(--raise);border:1px solid var(--rule);border-radius:6px;overflow-x:auto}
.cmd::before{content:"$";color:var(--muted)}
.cmd code{font:inherit;white-space:nowrap;user-select:all;-webkit-user-select:all}
.cmd+p,.cmd+.hint{margin-top:12px}
.empty .cmd{max-width:440px;margin:14px auto 0;text-align:left}
.callout{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:flex-start;padding:14px 16px;border:1px solid var(--rule);border-radius:8px;background:var(--surface)}
.callout>.i{margin-top:2px;color:var(--muted)}
.callout-text{flex:1 1 240px;min-width:0}
.callout-text p{margin:0}.callout-text p+p,.callout-text p+ul{margin-top:6px}.callout-text>strong{display:block;margin-bottom:2px}
.callout-text ul{margin:6px 0 0;padding-left:18px}.callout-text li{margin:2px 0}
.callout form button{margin:0}
.callout.info{background:var(--info-bg);border-color:transparent}.callout.info>.i{color:var(--info)}
.callout.ok{background:var(--ok-bg);border-color:transparent}.callout.ok>.i{color:var(--ok)}
.callout.warn{background:var(--warn-bg);border-color:transparent}.callout.warn>.i{color:var(--warn)}
.callout.crit{background:var(--crit-bg);border-color:transparent}.callout.crit>.i{color:var(--crit)}
.empty{padding:22px;text-align:center;border:1px dashed var(--rule);border-radius:8px;color:var(--muted)}
.empty p{color:var(--muted)}.empty p:last-child{margin-bottom:0}
.solo{display:flex;flex-direction:column;align-items:center;padding:7vh 16px 48px}
.solo-top,.solo-card{width:100%;max-width:520px}
.solo-top{margin:0 0 16px;padding:0 2px}
.solo-card{padding:30px 30px 24px;background:var(--surface);border:1px solid var(--rule);border-radius:8px}
.solo-card h1{margin:0 0 12px;font-size:25px;line-height:1.2;letter-spacing:-.022em;font-weight:650}
.solo-card h2{margin:24px 0 8px;font-size:15px}
.solo-card>:last-child{margin-bottom:0}
.solo-card .callout{margin:0 0 16px}
@media(max-width:560px){.solo{padding:16px 12px 32px}.solo-card{padding:22px 18px 18px}}
.app{display:grid;grid-template-columns:248px minmax(0,1fr);min-height:100vh}
.side{min-width:0;background:var(--surface);border-right:1px solid var(--rule)}
.side-in{position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column;gap:22px;padding:22px 16px 18px}
.side .mark{padding:2px 8px 0}
.org{min-width:0;padding:12px;background:var(--raise);border:1px solid var(--rule);border-radius:8px}
.org-name{display:-webkit-box;margin:5px 0 8px;font-size:14.5px;font-weight:600;line-height:1.3;color:var(--ink);-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.org-meta{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center;font-size:13px;color:var(--muted)}
.switch{margin:10px 0 0;padding-top:10px;border-top:1px solid var(--rule)}
.switch>summary{display:inline-flex;align-items:center;gap:6px;min-height:28px;font-size:13px;color:var(--ink-2)}
.switch>summary .i{width:15px;height:15px;color:var(--muted)}
.switch>summary:hover{color:var(--ink)}
.switch[open]>summary{color:var(--ink)}
.switch form{display:grid;gap:8px;margin-top:8px}
.switch label{margin:0;font:500 11px/1.4 var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
.switch select{background:var(--surface)}
.switch button{width:100%;margin:0}
.nav{display:flex;flex-direction:column;gap:2px}
.nav a{display:flex;align-items:center;gap:10px;min-height:38px;padding:8px 10px;border-radius:6px;font-size:14.5px;color:var(--ink-2);text-decoration:none;overflow-wrap:normal}
.nav a .i{color:var(--muted)}
.nav a:hover{color:var(--ink);background:var(--raise)}
.nav a[aria-current=page]{color:var(--ink);font-weight:600;background:var(--brand-bg)}
.nav a[aria-current=page] .i{color:var(--brand)}
.side-foot{margin-top:auto;padding:14px 8px 0;border-top:1px solid var(--rule)}
.side-foot .who{display:block;margin:4px 0 10px;font-size:13.5px;color:var(--ink)}
.side-foot form button{margin:0}
.main{min-width:0;padding:32px 40px 56px}
.page{max-width:1120px;margin:0 auto;container-type:inline-size}
.head{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:14px 24px;margin:0 0 24px}
.head>div{flex:1 1 320px;min-width:0}
.head h1{margin:0;font-size:27px;line-height:1.15;letter-spacing:-.025em;font-weight:650}
.head p{margin:6px 0 0;max-width:72ch;color:var(--muted)}
.head>.head-act{display:flex;flex:none;flex-wrap:wrap;gap:10px}.head-act>*,.head-act button{margin:0}
.foot{margin-top:40px;font-size:13px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px;align-items:start}
.grid>*{grid-column:1/-1;min-width:0}
.grid>.c7{grid-column:span 7}.grid>.c5{grid-column:span 5}.grid>.c8{grid-column:span 8}.grid>.c4{grid-column:span 4}.grid>.c6{grid-column:span 6}
.stack{display:flex;flex-direction:column;gap:16px;min-width:0}
.section-label{margin:10px 0 -4px}
.card{min-width:0;padding:20px;background:var(--surface);border:1px solid var(--rule);border-radius:8px}
.card>:last-child{margin-bottom:0}
.card-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:0 0 14px}
.card-head>:first-child{margin-right:auto;padding-right:6px}
.card-head h2,.card-head h3{display:flex;align-items:center;gap:9px;min-width:0;margin:0;font-size:15.5px;line-height:1.3;font-weight:600;letter-spacing:-.01em}
.card-head .i{color:var(--muted)}
.card-head a{font-size:13.5px}
.card p{font-size:14.5px}
.locked{border-style:dashed}
.danger-zone{border-color:color-mix(in srgb,var(--crit) 40%,var(--rule))}
.danger-zone .card-head h2 .i{color:var(--crit)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}
.stat{display:flex;flex-direction:column;min-width:0;padding:16px 18px;color:var(--ink);background:var(--surface);border:1px solid var(--rule);border-radius:8px;text-decoration:none}
.stat:hover{color:var(--ink);border-color:var(--line)}
.stat .label{display:flex;align-items:center;gap:7px}
.stat .label .i{width:15px;height:15px}
.stat-v{margin:10px 0 2px;font:600 26px/1.15 var(--mono);letter-spacing:-.03em}
.stat-s{font-size:13px;color:var(--muted)}
.steps{margin:0;padding:0;list-style:none}
.step{display:grid;grid-template-columns:26px minmax(0,1fr);gap:12px;margin:0;padding:14px 0;border-top:1px solid var(--rule-2)}
.step:first-child{padding-top:2px;border-top:0}.step:last-child{padding-bottom:0}
.step-mark{display:grid;place-items:center;width:26px;height:26px;border:1px solid var(--line);border-radius:50%;font:500 12px var(--mono);color:var(--muted)}
.step-mark .i{width:15px;height:15px}
.step.done .step-mark{color:var(--ok);background:var(--ok-bg);border-color:transparent}
.step-title{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;font-weight:600;color:var(--ink)}
.step p{margin:4px 0 0;font-size:14px;color:var(--muted)}
.events{margin:0;padding:0;list-style:none}
.events li{display:flex;justify-content:space-between;gap:4px 14px;margin:0;padding:10px 0;font-size:14px;color:var(--ink-2);border-top:1px solid var(--rule-2)}
.events li>span{min-width:0}
.events li:first-child{padding-top:0;border-top:0}
.events li:last-child{padding-bottom:0}
.events time,.when{flex:none;font:12px/1.6 var(--mono);color:var(--muted);white-space:nowrap}
.upsell{padding:0;overflow:hidden}
.upsell.locked{border-style:solid;border-color:color-mix(in srgb,var(--brand) 35%,var(--rule))}
.upsell-top{display:flex;flex-wrap:wrap;align-items:flex-start;justify-content:space-between;gap:14px 20px;padding:22px 22px 18px;background:linear-gradient(180deg,var(--brand-bg),var(--surface));border-bottom:1px solid var(--rule)}
.upsell-top>div{flex:1 1 300px;min-width:0}
.upsell-title{display:flex;align-items:center;gap:10px;margin:4px 0 0;font-size:21px;line-height:1.2;letter-spacing:-.02em}
.upsell-title .lock{background:var(--surface);border:1px solid var(--rule)}
.upsell-title small{font:500 14px var(--mono);letter-spacing:0;color:var(--muted)}
.upsell-top .lead{margin:10px 0 0;font-size:15px;color:var(--ink)}
.upsell-top .actions{margin:2px 0 0}
.upsell-body{padding:18px 22px 22px}
.upsell-body>.label{margin:0 0 10px}
.upsell-foot{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:6px 18px;margin:18px 0 0;padding-top:14px;border-top:1px solid var(--rule-2)}
.upsell-foot p{margin:0;font-size:14px}
.price{margin:0;font:500 14px var(--mono);color:var(--ink)}
.price+.hint{margin:4px 0 0}
.feats{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin:0;padding:0;list-style:none}
.feat{margin:0;padding:12px 14px;background:var(--raise);border:1px solid var(--rule);border-radius:6px}
.feat-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.feat-top strong{flex:1 1 auto;min-width:0;font-size:14px}
.feat-top .i{width:15px;height:15px;color:var(--brand)}
.feat.on .feat-top .i{color:var(--ok)}
.feat p{margin:6px 0 0;font-size:13px;color:var(--muted)}
.soon-list{display:flex;flex-wrap:wrap;gap:6px;margin:0;padding:0;list-style:none}
.soon-list .feat{display:inline-flex;padding:4px 10px 4px 8px;border-radius:999px}
.soon-list .feat-top{gap:6px}
.soon-list .feat-top .i{width:14px;height:14px;color:var(--muted)}
.soon-list .feat-top strong{font-size:13px;font-weight:500;color:var(--ink-2)}
.soon-list .pill{position:absolute;width:1px;height:1px;padding:0;overflow:hidden;clip-path:inset(50%);border:0}
.feats+.label,.soon-list+.label{margin-top:16px}
.team .feats{margin-top:12px}
.table{width:100%;border-collapse:collapse;font-size:14px}
.table th{padding:0 14px 10px 0;font:500 11px/1.4 var(--mono);letter-spacing:.09em;text-transform:uppercase;text-align:left;white-space:nowrap;color:var(--muted);border-bottom:1px solid var(--rule)}
.table td{padding:11px 14px 11px 0;vertical-align:middle;color:var(--ink-2);border-bottom:1px solid var(--rule-2)}
.table tr:last-child td{border-bottom:0}
.table tbody tr:hover td{background:var(--raise)}
.table .cell-main strong{font-weight:600;color:var(--ink)}
.table .cell-main .pill{margin-left:6px}
.table time,.table .mono{font:12.5px/1.5 var(--mono);color:var(--ink-2);white-space:nowrap}
.table .none{color:var(--muted)}
.table th.act,.table td.act{text-align:right}
.table col.when{width:150px}.table col.area{width:140px}
.flush{margin:0 -20px}
.flush .table th:first-child,.flush .table td:first-child{padding-left:20px}
.flush .table th:last-child,.flush .table td:last-child{padding-right:20px}
.flush .table tr:last-child td{padding-bottom:4px}
.flush+p,.flush+.hint{margin-top:16px}
.act-row{display:inline-flex;flex-wrap:wrap;justify-content:flex-end;align-items:center;gap:6px;vertical-align:middle}
.act-row>form{display:inline-flex;margin:0}
.act-row button,.act-row .btn{margin:0}
.pop{position:relative;display:inline-block;margin:0}
.pop>summary{list-style:none}.pop>summary::-webkit-details-marker{display:none}
.pop[open]>summary{color:var(--ink);border-color:var(--ink)}
.pop-body{position:absolute;right:0;top:calc(100% + 6px);z-index:5;width:300px;padding:2px 14px 14px;text-align:left;white-space:normal;background:var(--surface);border:1px solid var(--line);border-radius:8px;box-shadow:0 10px 28px -14px rgb(0 0 0 / .45)}
.pop-body label{margin-top:10px}
.inline{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.inline>input,.inline>select{flex:1 1 160px;min-width:0}
.inline>button{flex:none;margin:0}
.fields{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,200px);gap:0 12px;max-width:560px}
.method-items{margin:12px 0 10px;padding:0;list-style:none;border:1px solid var(--rule);border-radius:6px}
.method-items li{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 14px;margin:0;padding:10px 12px;border-top:1px solid var(--rule-2)}
.method-items li>span{min-width:0}
.method-items li:first-child{border-top:0}
.method-items form button{margin:0}
.method-form{max-width:440px}
.hint{font-size:13.5px;color:var(--muted)}
form+.hint{margin-top:8px}
.hint .i{width:14px;height:14px;vertical-align:-2px;margin-right:4px}
.disclose{margin:18px 0 0;padding-top:14px;border-top:1px solid var(--rule-2)}
.disclose>summary{display:inline-flex}
.disclose[open]>summary{margin-bottom:4px}
.disclose .method-form{margin-top:4px}
.sub{display:block;margin-top:3px;font-size:13px;line-height:1.45;color:var(--muted)}
.card-intro{margin:-4px 0 16px;color:var(--muted)}
.subhead{display:block;margin:22px 0 10px;padding-top:16px;border-top:1px solid var(--rule-2);font:500 11px/1.4 var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
.back-row{margin:18px 0 0}.alt .back-row{margin:0}
.counts{display:flex;flex-wrap:wrap;gap:6px}
.checks{margin:0;padding:0;list-style:none}
.checks li{display:grid;grid-template-columns:18px minmax(0,1fr) auto;gap:2px 12px;align-items:start;margin:0;padding:11px 0;border-top:1px solid var(--rule-2)}
.checks li:first-child{border-top:0;padding-top:0}
.checks li:last-child{padding-bottom:0}
.checks li>.i{width:16px;height:16px;margin-top:3px;color:var(--muted)}
.checks li.on>.i{color:var(--ok)}
.checks li.locked-item>.i{color:var(--brand)}
.checks strong{font-size:14px}
.checks p{margin:2px 0 0;font-size:13px;color:var(--muted)}
.plan-now{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 14px;margin:0 0 14px}
.plan-now b{font:600 34px/1.1 var(--mono);letter-spacing:-.04em;color:var(--ink)}
.plan-now span{font-size:14px;color:var(--muted)}
.subs>div{padding:14px 0 0;margin:14px 0 0;border-top:1px solid var(--rule-2)}
.subs>div:first-child{margin-top:0;padding-top:0;border-top:0}
.subs dl{margin-bottom:12px}
.subs form button{margin:0}
.subs+p{margin-top:12px}
.plan-list{margin:0 0 4px}
.choices{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.choice{display:flex;flex-direction:column;min-width:0;margin:0;padding:16px;background:var(--raise);border:1px solid var(--rule);border-radius:8px}
.choice.best{border-color:color-mix(in srgb,var(--brand) 55%,var(--rule))}
.choice-price{margin:10px 0 2px;font:600 19px/1.25 var(--mono);letter-spacing:-.02em;color:var(--ink)}
.choice .hint{margin:0}
.choice .pill{align-self:flex-start}
.choices+.hint,.choices+p{margin-top:14px}
.choice button{width:100%;margin-top:14px}
.danger-zone .danger-row{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 12px;margin:0;padding:10px 0;border-top:1px solid var(--rule-2)}
.danger-zone .danger-row>span{min-width:0}
.danger-zone .danger-row:first-child{border-top:0;padding-top:0}
.danger-zone form button{margin:0}
.danger-zone ul{margin:12px 0;padding:0;list-style:none}
.notes{margin:0;padding-left:18px}.notes li{margin:0 0 6px;font-size:14px}
.solo-mark{display:inline-grid;place-items:center;width:40px;height:40px;margin:0 0 18px;border-radius:8px;color:var(--brand);background:var(--brand-bg)}
.solo-mark .i{width:20px;height:20px}
.solo-mark.ok{color:var(--ok);background:var(--ok-bg)}.solo-mark.warn{color:var(--warn);background:var(--warn-bg)}
.solo-mark.crit{color:var(--crit);background:var(--crit-bg)}.solo-mark.info{color:var(--info);background:var(--info-bg)}
.solo-foot{width:100%;max-width:520px;margin:18px 0 0;padding:0 2px;font-size:13px;color:var(--muted)}
.solo-card .lead{font-size:15.5px;color:var(--ink-2)}
.solo-card dl{padding:14px 16px;background:var(--raise);border:1px solid var(--rule);border-radius:6px}
.solo-card form .primary.wide,.wide{width:100%}
.or{display:flex;align-items:center;gap:12px;margin:20px 0 14px;font:500 11px/1 var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
.or::before,.or::after{content:"";flex:1;border-top:1px solid var(--rule)}
.ways-in{display:grid;gap:10px;margin:0}
.ways-in .button{width:100%;margin:0}
.alt{margin:22px 0 0;padding:16px 0 0;border-top:1px solid var(--rule-2);font-size:14px}
.alt p{margin:0 0 6px;font-size:14px}.alt p:last-child{margin:0}
.fine{margin:18px 0 0;font-size:12.5px;line-height:1.6;color:var(--muted)}
.fine small{font-size:inherit}
.back{display:inline-flex;align-items:center;gap:6px;font-size:14px}
.back .i{width:15px;height:15px}
.solo-card .actions{margin-top:18px}
.solo-card form+p{margin-top:16px}
.solo-card .switch{margin:0 0 18px;padding:12px 0 0;border-top:1px solid var(--rule-2)}
.solo-card .switch form{grid-template-columns:minmax(0,1fr) auto;align-items:end}
.solo-card .switch label{grid-column:1/-1}
.solo-card .switch button{width:auto}
.solo-card .choices{margin:18px 0 4px}
@container (max-width:900px){.table .opt{display:none}}
@container (max-width:720px){.grid>.c7,.grid>.c5,.grid>.c8,.grid>.c4,.grid>.c6{grid-column:1/-1}}
@container (max-width:680px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
@container (min-width:721px) and (max-width:1060px){.upsell .feats{grid-template-columns:minmax(0,1fr)}}
@media(min-width:900px) and (max-width:1179px){.app{grid-template-columns:220px minmax(0,1fr)}.main{padding:28px 28px 48px}}
@media(max-width:759px){
.flush{margin:0}
.flush .table th:first-child,.flush .table td:first-child{padding-left:0}
.flush .table th:last-child,.flush .table td:last-child{padding-right:0}
.table thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
.table,.table tbody,.table tr,.table td{display:block}
.table tr{padding:12px 0;border-bottom:1px solid var(--rule-2)}
.table tr:first-child{padding-top:0}
.table tr:last-child{border-bottom:0;padding-bottom:0}
.table tbody tr:hover td{background:none}
.table td{padding:2px 0;border:0}
.table td[data-label]{display:grid;grid-template-columns:104px minmax(0,1fr);gap:10px;align-items:baseline;justify-items:start}
.table td[data-label]::before{content:attr(data-label);font:500 10.5px/1.6 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.table td.cell-main{padding-bottom:6px}
.table td.act{padding-top:8px;text-align:left}
.table td.act .act-row{justify-content:flex-start}
.table .cell-main .pill{margin-left:4px}
.act-row{display:flex}
.pop[open]{flex-basis:100%}
.pop-body{position:static;width:auto;margin-top:8px;box-shadow:none}
}
@media(max-width:899px){
.app{display:block}
.side{border-right:0;border-bottom:1px solid var(--rule)}
.side-in{position:static;height:auto;overflow:visible;display:grid;grid-template-columns:minmax(0,1fr) auto;grid-template-areas:"mark foot" "org org" "nav nav";gap:12px;padding:14px 16px}
.side .mark{grid-area:mark;padding:0;align-self:center}
.side-foot{grid-area:foot;margin:0;padding:0;border:0;align-self:center}
.side-foot .label,.side-foot .who{display:none}
.org{grid-area:org;display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;padding:0;background:none;border:0}
.org>.label{display:none}
.org-name{margin:0;-webkit-line-clamp:1}
.switch{margin:0;padding:0;border:0}
.switch[open]{flex:1 1 100%}
.switch form{grid-template-columns:minmax(0,1fr) auto;align-items:end}
.switch label{grid-column:1/-1}
.switch button{width:auto}
.nav{grid-area:nav;flex-direction:row;flex-wrap:wrap;gap:6px}
.nav a{flex:none;min-height:40px;padding:8px 13px 8px 11px;font-size:14px;border:1px solid var(--rule);border-radius:999px}
.nav a .i{width:15px;height:15px}
.nav a[aria-current=page]{border-color:transparent}
.main{padding:22px 16px 40px}
.head h1{font-size:23px}
}
@media(max-width:639px){
.nav{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}
.nav a{justify-content:center;gap:6px;padding:8px 6px}
.upsell-top,.upsell-body{padding-left:16px;padding-right:16px}
.card:not(.upsell){padding-left:16px;padding-right:16px}
.flush{margin:0}
.stat{padding:14px}.stat .label{min-height:31px;align-items:flex-start}
.events li{flex-direction:column;gap:2px}
.fields{grid-template-columns:minmax(0,1fr)}
.choices{grid-template-columns:minmax(0,1fr)}
}
@media(max-width:899px),(pointer:coarse){
.nav a,.switch>summary,.side-foot button,.switch select,.switch button,button.compact,a.compact,summary.compact,.act-row button,.act-row .btn,.method-items form button{min-height:40px}
button.compact,a.compact,summary.compact{padding-top:8px;padding-bottom:8px}
}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important;scroll-behavior:auto!important}}`;

let styleHash = null;

/* default-src 'none' covers script, images, fonts, frames and fetches;
   form-action keeps every form posting here; frame-ancestors keeps the
   page out of anyone's frame. With `challenge`, Turnstile's script and
   its frame, from challenges.cloudflare.com and nowhere else. With
   `passkeys`, /passkeys.js and the two paths whose JSON it asks for,
   each named exactly (a source without a trailing slash is that one
   path), so nothing else this host ever answers can run or be fetched
   there; every other response is HTML or JSON sent with nosniff besides.
   `away`: origins a form here may be redirected on to, which browsers
   hold to form-action too. Only the account page's forms that link
   Google or GitHub need it (oauth.js's PROVIDERS), for those two, and
   Manage billing and the upgrade's (billing.js), for Stripe's billing
   portal and Checkout: each only on a page that shows that form. */
async function csp(challenge = false, away = [], passkeys = false) {
  if (!styleHash) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(CSS)));
    let s = "";
    for (const b of digest) s += String.fromCharCode(b);
    styleHash = btoa(s);
  }
  const policy = `default-src 'none'; style-src 'sha256-${styleHash}'; form-action ${["'self'", ...away].join(" ")}; ` +
    "frame-ancestors 'none'; base-uri 'none'";
  if (challenge) return `${policy}; script-src ${CHALLENGE_ORIGIN}; frame-src ${CHALLENGE_ORIGIN}`;
  if (passkeys) {
    return `${policy}; script-src ${ACCOUNT_ORIGIN}/passkeys.js; ` +
      `connect-src ${ACCOUNT_ORIGIN}/passkeys/new ${ACCOUNT_ORIGIN}/passkeys/challenge`;
  }
  return policy;
}

/* On every response from this host, redirects included. HSTS is sent here
   and only here: this host has only ever been HTTPS, and leaving out
   includeSubDomains keeps the decision for ranwhat.com and its other hosts
   separate (site/_headers says why it waits there). Referrer-Policy is
   same-origin, not no-referrer: see sameOrigin() in session.js. */
async function secured(headers, { challenge = false, away = [], passkeys = false } = {}) {
  headers.set("cache-control", "no-store");
  headers.set("content-security-policy", await csp(challenge, away, passkeys));
  headers.set("x-frame-options", "DENY");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "same-origin");
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  headers.set("x-robots-tag", "noindex, nofollow");
  headers.set("strict-transport-security", "max-age=31536000");
  return headers;
}

/* ---------- icons ---------- */

/* Hand-drawn on a 24-unit grid, stroked in the text's colour, and hidden
   from screen readers: every one sits beside words that say the same. */
const PATHS = Object.freeze({
  overview: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>',
  machines: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M7 10l3 2.5L7 15M12.5 15H17"/>',
  members: '<circle cx="9" cy="8.5" r="3.5"/><path d="M2.5 19.5c.8-3.2 3.4-5 6.5-5s5.7 1.8 6.5 5"/><path d="M15.5 5.3a3.5 3.5 0 0 1 0 6.4M17.8 14.9c1.9.7 3.2 2.3 3.7 4.6"/>',
  billing: '<rect x="2.5" y="5" width="19" height="14" rx="2"/><path d="M2.5 9.5h19M6.5 15h4"/>',
  security: '<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6L12 3z"/><path d="M9 12.2l2.2 2.2 4.3-4.4"/>',
  activity: '<path d="M3 12h4l2.5-6.5 5 13 2.5-6.5h4"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  mail: '<rect x="3" y="5.5" width="18" height="13" rx="2"/><path d="M3.5 7l8.5 6 8.5-6"/>',
  password: '<rect x="2.5" y="6.5" width="19" height="11" rx="2"/><path d="M7 12h.01M12 12h.01M17 12h.01" stroke-width="2.6"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L19.5 3.5M16 7l2.5 2.5M13.5 9.5l2 2"/>',
  exit: '<path d="M14 4.5h3.5a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H14M10 16l-4-4 4-4M6 12h9.5"/>',
  alert: '<path d="M12 4l9 16H3l9-16z"/><path d="M12 10v4.5M12 17.2h.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8h.01"/>',
  team: '<path d="M4 20.5V7l8-3.5L20 7v13.5M2.5 20.5h19M9.5 20.5v-4h5v4M8.5 9.5h1M14.5 9.5h1M8.5 13h1M14.5 13h1"/>',
  spark: '<path d="M12 3.5l1.9 5.4 5.6 1.6-5.6 1.6L12 17.5l-1.9-5.4-5.6-1.6 5.6-1.6L12 3.5zM18.5 16l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7.7-1.8z"/>',
  back: '<path d="M19 12H5M11 6l-6 6 6 6"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  ci: '<circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="9" r="2.5"/><path d="M6 8.5v7M18 11.5c0 3-2.5 4-6 4.5-2 .3-3.5 1-4.2 1.6"/>',
  user: '<circle cx="12" cy="8.5" r="3.8"/><path d="M4.5 20c1-3.6 3.9-5.6 7.5-5.6s6.5 2 7.5 5.6"/>',
  edit: '<path d="M14.5 5.5l4 4M4 20l1-4.5L15.8 4.7a1.8 1.8 0 0 1 2.5 0l1 1a1.8 1.8 0 0 1 0 2.5L8.5 19 4 20z"/>',
  code: '<path d="M8.5 7.5L4 12l4.5 4.5M15.5 7.5L20 12l-4.5 4.5"/>',
  swap: '<path d="M16.5 3.5l3 3-3 3M19.5 6.5h-13M7.5 14.5l-3 3 3 3M4.5 17.5h13"/>',
});

export const icon = (name) => (Object.hasOwn(PATHS, name)
  ? `<svg class="i" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" ` +
    `stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${PATHS[name]}</svg>`
  : "");

/* ---------- components ---------- */

const TONES = new Set(["brand", "ok", "warn", "crit", "info"]);

/* A short state, in words: text is escaped here. tone: one of TONES, or
   neutral. */
export const pill = (text, tone = "", attributes = "") =>
  `<span class="pill${TONES.has(tone) ? ` ${tone}` : ""}"${attributes ? ` ${attributes}` : ""}>${escape(text)}</span>`;

/* The badge beside something a plan unlocks. */
export const lockBadge = () => `<span class="lock">${icon("lock")}</span>`;

/* A button that takes something away, marked as such by more than its
   colour (in the dark theme the site's crit is its brand colour). text is
   markup already escaped by the caller; cls: more classes, such as
   compact or wide. */
export const dangerButton = (text, cls = "") =>
  `<button type="submit" class="danger${cls ? ` ${cls}` : ""}">${icon("alert")}${text}</button>`;

/* A command to type, selected whole on one click. text is escaped here. */
export const command = (text) => `<div class="cmd"><code>${escape(text)}</code></div>`;

/* A titled card. title is escaped here; mark (in place of the icon),
   aside, body and attributes are markup already escaped by the caller. */
export const card = ({ title, icon: name = "", mark = "", aside = "", body, cls = "", attributes = "", tag = "section", level = 2 }) =>
  `<${tag} class="card${cls ? ` ${cls}` : ""}"${attributes ? ` ${attributes}` : ""}>
    <header class="card-head"><h${level}>${mark || icon(name)}${escape(title)}</h${level}>${aside}</header>
    ${body}</${tag}>`;

/* A number with its caption, linking to where it comes from. label, value
   and sub are escaped here. */
export const stat = ({ label, value, sub = "", href, icon: name = "", id = "" }) =>
  `<a class="stat" href="${escape(href)}"><span class="label">${icon(name)}${escape(label)}</span>` +
  `<span class="stat-v"${id ? ` id="${escape(id)}"` : ""}>${escape(value)}</span>` +
  `<span class="stat-s">${escape(sub)}</span></a>`;

/* A notice across the page. tone: info, ok or warn. title is escaped here;
   text and act are markup. */
export const callout = ({ tone = "info", icon: name = "info", title = "", text, act = "", attributes = "" }) =>
  `<div class="callout ${TONES.has(tone) ? tone : "info"}"${attributes ? ` ${attributes}` : ""}>${icon(name)}` +
  `<div class="callout-text">${title ? `<strong>${escape(title)}</strong>` : ""}${text}</div>${act}</div>`;

/* An empty list, said so. text is markup. */
export const empty = (text) => `<div class="empty">${text}</div>`;

/* A table that stacks into one block per row on a phone, each cell under
   its column's name (cell()'s data-label). head: [name, class] pairs,
   names escaped here (an "act" column's, for its forms, is read out but
   not shown); rows: <tr> markup already escaped by the caller.
   cols: optional <col> classes, for widths. */
export const table = (head, rows, { label = "", cols = [] } = {}) =>
  `<div class="flush"><table class="table"${label ? ` aria-label="${escape(label)}"` : ""}>` +
  (cols.length ? `<colgroup>${cols.map((c) => `<col${c ? ` class="${c}"` : ""}>`).join("")}</colgroup>` : "") +
  `<thead><tr>${head.map(([name, cls = ""]) => `<th scope="col"${cls ? ` class="${cls}"` : ""}>` +
    `${cls === "act" ? `<span class="vh">${escape(name)}</span>` : escape(name)}</th>`).join("")}</tr></thead>
      <tbody>
        ${rows.join("\n        ")}
      </tbody></table></div>`;

/* One cell: label (escaped here) is what a phone shows beside it; html is
   markup already escaped by the caller. cls "opt": a column left out
   between a phone's width and a wide screen's, where the table is
   narrowest (its <th> takes "opt" too). */
export const cell = (label, html, cls = "") =>
  `<td${cls ? ` class="${cls}"` : ""}${label ? ` data-label="${escape(label)}"` : ""}>${html}</td>`;

/* A row's forms and buttons, kept on one line where they fit. */
export const actions = (items) => (items.length ? `<div class="act-row">${items.join("")}</div>` : "");

/* The step-up, once at the top of a page, for what on it needs an emailed
   code typed lately. what: a sentence, markup already escaped by the
   caller; email: where the code goes, escaped here; stepup: stepupForm(). */
export const confirmCallout = (what, email, stepup) => callout({
  tone: "warn", icon: "security", title: "Confirm it is you", attributes: 'id="confirm"',
  text: `<p>${what} We send the code to ${escape(email)}, and you come back here once it is typed.</p>`,
  act: stepup,
});

/* The form that asks for that code, back to `next` once it is typed:
   form(), with the token for "stepup" already made by the caller. */
export const stepupForm = (token, next, cls = "primary") => form("/stepup", token,
  `<input type="hidden" name="next" value="${escape(next)}"><button type="submit"${cls ? ` class="${cls}"` : ""}>Email me a code</button>`);

/* ---------- times ---------- */

const utc = (t) => `${new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;
const isoDay = (t) => new Date(t * 1000).toISOString().slice(0, 10);

/* How long ago `t` was, for a list read at a glance. */
export function ago(t, at = now()) {
  const s = Math.max(0, at - t);
  const n = (count, unit) => `${count} ${unit}${count === 1 ? "" : "s"} ago`;
  if (s < 60) return "just now";
  if (s < 3600) return n(Math.floor(s / 60), "minute");
  if (s < DAY) return n(Math.floor(s / 3600), "hour");
  if (s < 7 * DAY) return n(Math.floor(s / DAY), "day");
  return isoDay(t);
}

/* `t` as how long ago, or as its day: the time itself is in the title,
   and in the datetime for anything that reads it. */
export const stamp = (t) => `<time datetime="${new Date(t * 1000).toISOString()}" title="${utc(t)}">${escape(ago(t))}</time>`;
export const dayStamp = (t) => `<time datetime="${isoDay(t)}" title="${utc(t)}">${isoDay(t)}</time>`;

/* A link back to where someone came from. text is escaped here. */
export const back = (href, text) => `<p class="back-row"><a class="back" href="${escape(href)}">${icon("back")}${escape(text)}</a></p>`;

/* An address, escaped, that may wrap after its @ rather than anywhere. */
export const shownAddress = (email) => escape(email).replace("@", "@<wbr>");

/* ---------- pages ---------- */

const doc = (title, script, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><meta name="color-scheme" content="light dark">
<title>${escape(title)} | ranwhat account</title>
<style>${CSS}</style>${script}</head>
${body}</html>`;

const wordmark = `<span class="mark"><a class="wm" href="/">ran<i>what</i></a><span class="label">Account</span></span>`;

async function respond(html, { status, cookies, challenge = false, away = [], passkeys = false }) {
  const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(html, { status, headers: await secured(headers, { challenge, away, passkeys }) });
}

const FOOT = `<a href="https://ranwhat.com/">ranwhat.com</a> &middot; <a href="https://ranwhat.com/privacy">Privacy</a>`;

/* An HTML page in the narrow layout. body is markup already escaped by
   the caller. challenge: the page holds a widget() and may load
   Turnstile's script. passkeys: the page holds a passkey form and loads
   /passkeys.js. away: see csp(). icon and tone: the mark above the
   heading, one of icon()'s names in one of TONES (the brand's when
   none). */
export async function page(title, body, {
  status = 200, cookies = [], challenge = false, away = [], passkeys = false, icon: name = "", tone = "",
} = {}) {
  const script = challenge ? `\n<script src="${CHALLENGE_SCRIPT}" async defer></script>`
    : passkeys ? `\n<script src="/passkeys.js" defer></script>` : "";
  const mark = name ? `<span class="solo-mark${TONES.has(tone) ? ` ${tone}` : ""}">${icon(name)}</span>\n    ` : "";
  const html = doc(title, script, `<body class="solo"><a class="skip" href="#main">Skip to content</a>
<header class="solo-top">${wordmark}</header>
<main id="main" class="solo-card">${mark}${body}</main>
<footer class="solo-foot">${FOOT}</footer>
</body>`);
  return respond(html, { status, cookies, challenge, away, passkeys });
}

/* The signed-in pages, in the order the nav lists them. */
export const APP_PAGES = Object.freeze([
  ["overview", "/", "Overview"],
  ["machines", "/machines", "Machines"],
  ["members", "/members", "Members"],
  ["billing", "/billing", "Billing"],
  ["security", "/security", "Security"],
  ["activity", "/activity", "Activity"],
]);

/* A signed-in page: the sidebar, then the page's header and body. Never
   with a script: no account page has one.
     current  which of APP_PAGES this is
     side     { email, org, plan, planTone, role }, text escaped here, and
              { switcher, signout }, forms already made
     head     { title, sub, action }: title escaped here, sub and action
              markup
     body     markup already escaped by the caller */
export async function shell({ current, side, head, body, status = 200, cookies = [], away = [] }) {
  const nav = APP_PAGES.map(([key, path, name]) =>
    `<a href="${path}"${key === current ? ' aria-current="page"' : ""}>${icon(key)}${name}</a>`).join("\n      ");
  const html = doc(head.title, "", `<body><a class="skip" href="#main">Skip to content</a>
<div class="app">
  <aside class="side" aria-label="Your account"><div class="side-in">
    ${wordmark}
    <div class="org">
      <span class="label">Organisation</span>
      <span class="org-name" title="${escape(side.org)}">${escape(side.org)}</span>
      <span class="org-meta">${pill(side.plan, side.planTone)}<span>${escape(side.role)}</span></span>
      ${side.switcher}
    </div>
    <nav class="nav" aria-label="Account pages">
      ${nav}
    </nav>
    <div class="side-foot">
      <span class="label">Signed in as</span>
      <span class="who">${shownAddress(side.email)}</span>
      ${side.signout}
    </div>
  </div></aside>
  <main id="main" class="main" data-page="${escape(current)}"><div class="page">
    <header class="head"><div><h1>${escape(head.title)}</h1>${head.sub ? `<p>${head.sub}</p>` : ""}</div>${head.action
      ? `<div class="head-act">${head.action}</div>` : ""}</header>
    ${body}
    <footer class="foot">${FOOT}</footer>
  </div></main>
</div>
</body>`);
  return respond(html, { status, cookies, away });
}

/* JSON for /passkeys.js, with the same headers as a page. */
export async function data(value, status = 200) {
  const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
  return new Response(JSON.stringify(value), { status, headers: await secured(headers) });
}

/* /passkeys.js itself. */
export async function script(text) {
  const headers = new Headers({ "content-type": "text/javascript; charset=utf-8" });
  return new Response(text, { headers: await secured(headers) });
}

/* Turnstile's box, inside a form: once solved, it adds the token to the
   form as cf-turnstile-response, which the server checks for `action`
   (challenge.js). Only on a page made with { challenge: true }. */
export const widget = (action) =>
  `<div class="cf-turnstile" data-sitekey="${SITEKEY}" data-action="${escape(action)}"></div>`;

/* A form's fields, or none when the body is not a form. */
export async function fields(request) {
  try {
    return await request.formData();
  } catch {
    return new FormData();
  }
}

/* 303, so the browser follows a POST with a GET. Always a path on this
   host: nothing here redirects anywhere a request named. */
export async function redirect(path, cookies = []) {
  const headers = new Headers({ location: path });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status: 303, headers: await secured(headers) });
}

/* 303 to a provider's authorization endpoint, for Google or GitHub sign-in
   (a URL oauth.js builds from its own constants), or to a Stripe Checkout
   or billing-portal session (a URL Stripe gave back, which billing.js
   checks is on checkout.stripe.com or billing.stripe.com): never one a
   request named. */
export async function away(url, cookies = []) {
  const headers = new Headers({ location: url });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status: 303, headers: await secured(headers) });
}

/* A form that posts to this host, with its token first. attributes:
   markup already escaped by the caller, such as a passkey form's data-. */
export const form = (action, token, inner, cls = "", attributes = "") =>
  `<form method="post" action="${escape(action)}"${cls ? ` class="${cls}"` : ""}${attributes ? ` ${attributes}` : ""}>` +
  `<input type="hidden" name="form" value="${escape(token)}">${inner}</form>`;

export const notFound = () => page("Not found", `<h1>Nothing here</h1>
  <p class="lead">There is no page at this address.</p>
  ${back("/", "Your account")}`, { status: 404, icon: "info", tone: "info" });

export async function wrongMethod(methods) {
  const res = await page("Not allowed", `<h1>Not allowed</h1>
  ${back("/", "Your account")}`, { status: 405, icon: "alert", tone: "warn" });
  res.headers.set("allow", methods.join(", "));
  return res;
}

/* A form that failed the origin or token check. Nothing in it says which. */
export const refused = () => page("Not accepted", `<h1>That form was not accepted</h1>
  <p class="lead">It may have been open too long, or come from another site. Go back,
     reload the page and try again.</p>
  ${back("/", "Your account")}`, { status: 403, icon: "alert", tone: "warn" });

/* A form drawn for another of the person's organisations than the one the
   session looks at now (session.js's orgFormOk()): nothing was done. */
export const elsewhere = () => page("Another organisation", `<h1>Nothing was done</h1>
  <p class="bad">That form was for another of your organisations than the one this page is looking at now,
     so nothing was done. Reload your account page and try again.</p>
  ${back("/", "Your account")}`, { status: 409, icon: "alert", tone: "warn" });
