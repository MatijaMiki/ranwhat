"""Terminal rendering."""
from __future__ import annotations

import functools

from . import term
from .catalog import AUTHORITY_RANK

def _c(code, s):
    # term decides, for every colour here and in watch and clean: asking
    # only isatty() ignored NO_COLOR and TERM=dumb everywhere but the
    # wordmark.
    return term.paint(code, s)

BOLD = lambda s: _c("1", s)
DIM = lambda s: _c("2", s)
RED = lambda s: _c("31", s)
YEL = lambda s: _c("33", s)
GRN = lambda s: _c("32", s)
CYA = lambda s: _c("36", s)

SEV_COLOR = {"critical": RED, "high": YEL, "medium": CYA, "low": DIM}


def _plain(s):
    return s


def painters():
    """BOLD, DIM, RED, YEL, GRN and CYA, as they paint stdout now. A report
    asks once: each line asking term again, a megabyte of findings asked
    86,000 times, a tenth of a second spent on the answer it had. A yes is
    kept as a no is: the painters handed out for one were BOLD and the rest,
    which ask term again, so on a terminal a thousand findings still asked
    six thousand times."""
    if term.colour():
        return tuple(functools.partial(term.sgr, code)
                     for code in ("1", "2", "31", "33", "32", "36"))
    return (_plain,) * 6


def _bar(n, width=24):
    filled = int(round(width * n / 100.0))
    colour = RED if n < 40 else (YEL if n < 70 else GRN)
    return colour("█" * filled) + DIM("░" * (width - filled))


def _tail(text, limit):
    """An identifier cut from the front, marked where it was cut. The end is
    what tells .../auth/calendar from .../auth/contacts, so it is the end
    that has to survive a narrow terminal."""
    if len(text) <= limit:
        return text
    return "…" + text[-max(1, limit - 1):]


def _danger(row):
    """Most dangerous first: by authority, then irreversible before not."""
    return (-AUTHORITY_RANK[row["authority"]], bool(row["reversible"]))


# Said instead of term.FOOTER when live or --pull-usage asked a provider's own
# API, where "Nothing was transmitted" would be false. Fits MIN_WIDTH.
ONLINE_FOOTER = "  Each token went only to its own provider."


def render(result, online=False):
    """`online` is for live and --pull-usage, which send each token to the
    provider that issued it, so the footer cannot say nothing was sent."""
    width = term.width()
    L = []
    L.append("")
    L.append(BOLD("  ") + term.brand(BOLD("ranwhat")) + BOLD("  ")
             + DIM("· agent authority & insurability"))
    L.append(DIM(term.rule()))
    L.append("  agent: " + BOLD(result["agent"]))
    L.append("")

    v = result["verdict"]
    badge = {"UNINSURABLE": RED, "IMPAIRED": YEL, "INSURABLE": GRN}[v["status"]]
    status = " %s " % v["status"]
    # A headline too long for the line hangs under itself, not under the badge.
    head = term.wrap(v["headline"], indent=" " * (len(status) + 4))
    L.append("  " + badge(BOLD(status)) + "  " + BOLD(head[0].lstrip()))
    L += [BOLD(h) for h in head[1:]]
    if v.get("composite") is not None:
        L.append("  composite %s/100  grade %s" % (v["composite"], v["grade"]))
    if v["detail"]:
        for wrapped in term.wrap(v["detail"]):
            L.append(DIM(wrapped))
    L.append("")

    # Label, score and grade take 25 columns; the bar gets what is left.
    bar = max(8, min(24, width - 25))
    for key, label in (("authority", "Authority    "),
                       ("observability", "Observability"),
                       ("reversibility", "Reversibility")):
        n = result["scores"][key]
        L.append("  %s  %s  %3d  %s" % (label, _bar(n, bar), n,
                                        result["grades"][key]))
    L.append("")

    c = result["counts"]
    L.append("  " + BOLD("Permissions"))
    L.append("    %d granted · %s used · %s never used"
             % (c["total"], c["used"], RED(str(c["unused"])) if c["unused"] else "0"))
    ba = result["blast_radius"]
    if ba["monetary"]:
        L.append("    financial authority: " + RED(ba["monetary"]))
    L += term.wrap(", ".join(ba["dimensions"]) or "none", indent=" " * 18,
                   first="    blast radius: ")
    L.append("    irreversible actions: %d" % len(ba["irreversible_actions"]))
    L.append("")

    L.append("  " + BOLD("Findings"))
    for f in result["findings"]:
        colour = SEV_COLOR.get(f["severity"], DIM)
        title = term.wrap(f["title"], indent="      ")
        L.append("    " + colour("● ") + BOLD(title[0][6:]))
        L += ["      " + BOLD(t[6:]) for t in title[1:]]
        L += [DIM(line) for line in term.wrap(f["body"], indent="      ")]
        for ev in f["evidence"][:6]:
            L.append(DIM("        · " + _tail(ev, width - 10)))
        if len(f["evidence"]) > 6:
            L.append(DIM("        · … and %d more" % (len(f["evidence"]) - 6)))
        L.append("")

    unused = [r for r in result["scopes"] if r["usage"] == "unused"]
    if unused:
        # Sorted on the authority string this put "write" above "financial"
        # and "destructive", and the cut below dropped exactly those.
        L.append("  " + BOLD("Granted but never exercised"))
        for r in sorted(unused, key=_danger)[:10]:
            L.append("    %-14s %s" % (r["provider"], _tail(r["scope"], width - 19)))
            L += [DIM(line) for line in term.wrap(r["label"], indent=" " * 19)]
        if len(unused) > 10:
            L.append(DIM("    … and %d more" % (len(unused) - 10)))
        L.append("")

    L.append(DIM(term.rule()))
    L.append(DIM(ONLINE_FOOTER if online else term.FOOTER))
    L.append("")
    return "\n".join(L)
